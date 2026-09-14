//! Fetches the custody columns a block still needs after it enters the data availability checker.
//!
//! A block becomes DA-pending from four independent sources: gossip, range sync, the RPC publish
//! path, and unknown-parent lookup. In every case the block stalls identically if its columns never
//! arrive, and gossip will not redeliver them for a block that is no longer near the head. This
//! module therefore keys off the `PendingAvailability` import notification rather than living
//! inside any one of those sources.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use anyhow::ensure;
use libp2p::PeerId;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::data_column_sidecar::DataColumnSidecar;
use ream_p2p::network::beacon::channel::{P2PCallbackResponse, P2PMessage, P2PRequest};
use ream_polynomial_commitments::handlers::verify_data_column_sidecar_kzg_proofs;
use ream_req_resp::beacon::messages::{
    BeaconResponseMessage, data_column_sidecars::DataColumnsByRootIdentifier,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};
use tree_hash::TreeHash;

use crate::{block_lookup::ensure_pending_item_is_importable_with_store, p2p_sender::P2PSender};

/// If no untried peer is available for 30 seconds, the fetch is parked. This matches Lighthouse's
/// stale no-peer timeout for custody requests; transiently failed peers may also be retried then.
pub const NO_COLUMN_PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// Lighthouse makes at most three custody-column requests to one peer. Applying the same bound
/// lets transient failures recover without retrying a persistently unavailable peer forever.
const MAX_TRANSIENT_PEER_ATTEMPTS: u8 = 3;

/// One full 128-column response is about 2.5 MiB at the current blob limit. Limiting fetches to 32
/// therefore keeps buffered column responses around 80 MiB while allowing parallel fork recovery.
pub const MAX_CONCURRENT_COLUMN_FETCHES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchActionState {
    Queued,
    InFlight { peer: PeerId },
    WaitingForPeers { since: Instant },
    Parked,
}

#[derive(Debug)]
struct FetchEntry {
    action_state: FetchActionState,
    tried_peers: HashSet<PeerId>,
    retryable_peers: HashSet<PeerId>,
    transient_failures: HashMap<PeerId, u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnFetchOutcome {
    Complete,
    Incomplete,
    Retryable,
}

/// Deduplicates pending roots, queues work beyond the concurrency cap, and retries incomplete
/// responses without running two fetches for the same root.
#[derive(Debug, Default)]
pub struct ColumnFetchTracker {
    entries: HashMap<B256, FetchEntry>,
    queued: VecDeque<B256>,
}

impl ColumnFetchTracker {
    pub fn enqueue(&mut self, block_root: B256) -> bool {
        if self.entries.contains_key(&block_root) {
            return false;
        }
        self.entries.insert(
            block_root,
            FetchEntry {
                action_state: FetchActionState::Queued,
                tried_peers: HashSet::new(),
                retryable_peers: HashSet::new(),
                transient_failures: HashMap::new(),
            },
        );
        self.queued.push_back(block_root);
        true
    }

    /// Returns one untried peer for the next queued root so a slow peer holds only one fetch slot.
    pub fn next_fetch(
        &mut self,
        connected_peers: &[PeerId],
        now: Instant,
    ) -> Option<(B256, PeerId)> {
        self.refresh_connected_peers(connected_peers, now);
        if self.in_flight_count() >= MAX_CONCURRENT_COLUMN_FETCHES {
            return None;
        }
        while let Some(block_root) = self.queued.pop_front() {
            let Some(entry) = self.entries.get_mut(&block_root) else {
                continue;
            };
            if entry.action_state != FetchActionState::Queued {
                continue;
            }

            let Some(peer) = connected_peers
                .iter()
                .copied()
                .find(|peer| !entry.tried_peers.contains(peer))
            else {
                entry.action_state = FetchActionState::WaitingForPeers { since: now };
                continue;
            };

            entry.tried_peers.insert(peer);
            entry.action_state = FetchActionState::InFlight { peer };
            return Some((block_root, peer));
        }
        None
    }

    pub fn finish(
        &mut self,
        block_root: B256,
        peer: PeerId,
        outcome: ColumnFetchOutcome,
        now: Instant,
    ) {
        let Some(entry) = self.entries.get_mut(&block_root) else {
            return;
        };
        if !matches!(
            entry.action_state,
            FetchActionState::InFlight {
                peer: in_flight_peer
            } if in_flight_peer == peer
        ) {
            return;
        }
        match outcome {
            ColumnFetchOutcome::Complete => {
                self.entries.remove(&block_root);
            }
            ColumnFetchOutcome::Incomplete => {
                entry.action_state = FetchActionState::WaitingForPeers { since: now };
            }
            ColumnFetchOutcome::Retryable => {
                let failures = entry.transient_failures.entry(peer).or_default();
                *failures = failures.saturating_add(1);
                if *failures < MAX_TRANSIENT_PEER_ATTEMPTS {
                    entry.retryable_peers.insert(peer);
                }
                entry.action_state = FetchActionState::WaitingForPeers { since: now };
            }
        }
    }

    /// Forgets disconnected peers and wakes parked roots only when an untried peer is available.
    fn refresh_connected_peers(&mut self, connected_peers: &[PeerId], now: Instant) {
        let connected = connected_peers.iter().copied().collect::<HashSet<_>>();
        for (block_root, entry) in &mut self.entries {
            entry.tried_peers.retain(|peer| connected.contains(peer));
            entry
                .retryable_peers
                .retain(|peer| connected.contains(peer));

            let can_try_peer = connected
                .iter()
                .any(|peer| !entry.tried_peers.contains(peer));
            match entry.action_state {
                FetchActionState::WaitingForPeers { .. } | FetchActionState::Parked
                    if can_try_peer =>
                {
                    entry.action_state = FetchActionState::Queued;
                    self.queued.push_back(*block_root);
                }
                FetchActionState::WaitingForPeers { since }
                    if now.saturating_duration_since(since) >= NO_COLUMN_PEER_TIMEOUT =>
                {
                    for peer in entry.retryable_peers.drain() {
                        entry.tried_peers.remove(&peer);
                    }
                    if connected
                        .iter()
                        .any(|peer| !entry.tried_peers.contains(peer))
                    {
                        entry.action_state = FetchActionState::Queued;
                        self.queued.push_back(*block_root);
                    } else {
                        entry.action_state = FetchActionState::Parked;
                    }
                }
                _ => {}
            }
        }
    }

    pub fn remove(&mut self, block_root: &B256) {
        self.entries.remove(block_root);
    }

    pub fn peer_disconnected(&mut self, peer_id: PeerId) {
        for entry in self.entries.values_mut() {
            entry.tried_peers.remove(&peer_id);
            entry.retryable_peers.remove(&peer_id);
        }
    }

    pub fn retain_pending(&mut self, pending_roots: &[B256]) {
        let pending = pending_roots.iter().copied().collect::<HashSet<_>>();
        self.entries
            .retain(|block_root, _| pending.contains(block_root));
        self.queued
            .retain(|block_root| self.entries.contains_key(block_root));
    }

    pub fn in_flight_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| matches!(entry.action_state, FetchActionState::InFlight { .. }))
            .count()
    }

    pub fn tracked_count(&self) -> usize {
        self.entries.len()
    }
}

/// Requests the columns `block_root` still needs, then validates and imports each one.
///
/// A response is accepted only when it carries the requested root and a column this node actually
/// custodies, so a peer cannot use the reply to push unrelated data.
pub async fn fetch_missing_columns(
    beacon_chain: &BeaconChain,
    p2p_sender: &P2PSender,
    block_root: B256,
    peer_id: PeerId,
) -> ColumnFetchOutcome {
    // Re-read on every attempt: gossip or an earlier peer may have completed part of the set.
    let Some((missing, expected_header)) = ({
        let store = beacon_chain.store.lock().await;
        store
            .data_availability_checker
            .pending_block(&block_root)
            .map(|pending| {
                (
                    store.data_availability_checker.missing_columns(&block_root),
                    pending.signed_block.signed_header(),
                )
            })
    }) else {
        return ColumnFetchOutcome::Complete;
    };
    if missing.is_empty() {
        return ColumnFetchOutcome::Complete;
    }

    let sidecars = match request_columns_by_root(p2p_sender, peer_id, block_root, &missing).await {
        Ok(sidecars) => sidecars,
        Err(err) => {
            debug!(?block_root, %peer_id, %err, "Data column request failed");
            return if err.is_retryable() {
                ColumnFetchOutcome::Retryable
            } else {
                ColumnFetchOutcome::Incomplete
            };
        }
    };

    for sidecar in sidecars {
        let still_pending = {
            let store = beacon_chain.store.lock().await;
            store
                .data_availability_checker
                .pending_block(&block_root)
                .is_some()
        };
        if !still_pending {
            return ColumnFetchOutcome::Complete;
        }
        if !missing.contains(&sidecar.index) {
            warn!(
                ?block_root,
                %peer_id,
                index = sidecar.index,
                "Peer returned a data column that was not requested"
            );
            continue;
        }
        if !is_valid_rpc_column(&sidecar, block_root, &expected_header) {
            warn!(
                ?block_root,
                %peer_id,
                index = sidecar.index,
                "Peer returned an invalid data column"
            );
            continue;
        }

        let sidecar_header = sidecar.signed_block_header.clone();
        let parent_root = sidecar_header.message.parent_root;
        let slot = sidecar_header.message.slot;
        match beacon_chain
            .import_data_column_sidecar_if(sidecar, move |store| {
                ensure_pending_item_is_importable_with_store(
                    store,
                    slot,
                    parent_root,
                    Some(block_root),
                )?;
                let pending = store
                    .data_availability_checker
                    .pending_block(&block_root)
                    .ok_or_else(|| anyhow::anyhow!("block is no longer pending availability"))?;
                ensure!(
                    pending.signed_block.signed_header() == sidecar_header,
                    "data column signed header does not match the pending block"
                );
                Ok(())
            })
            .await
        {
            Ok(()) => {}
            Err(err) => {
                let still_pending = {
                    let store = beacon_chain.store.lock().await;
                    store
                        .data_availability_checker
                        .pending_block(&block_root)
                        .is_some()
                };
                if !still_pending {
                    return ColumnFetchOutcome::Complete;
                }
                warn!(?block_root, ?err, "Failed to import fetched data column");
            }
        }
    }

    let store = beacon_chain.store.lock().await;
    if store
        .data_availability_checker
        .pending_block(&block_root)
        .is_none_or(|_| {
            store
                .data_availability_checker
                .missing_columns(&block_root)
                .is_empty()
        })
    {
        ColumnFetchOutcome::Complete
    } else {
        ColumnFetchOutcome::Incomplete
    }
}

/// Applies the checks that are meaningful for a column obtained over req/resp. Gossip-only
/// conditions such as subnet placement and arrival timing are deliberately not applied: the block
/// is already past the head, so they would reject every honest response.
fn is_valid_rpc_column(
    sidecar: &DataColumnSidecar,
    expected_root: B256,
    expected_header: &ream_consensus_misc::beacon_block_header::SignedBeaconBlockHeader,
) -> bool {
    if sidecar.signed_block_header.message.tree_hash_root() != expected_root {
        return false;
    }
    if &sidecar.signed_block_header != expected_header {
        return false;
    }
    if !sidecar.verify() || !sidecar.verify_inclusion_proof() {
        return false;
    }
    verify_data_column_sidecar_kzg_proofs(sidecar).unwrap_or(false)
}

#[derive(Debug)]
enum ColumnRequestError {
    Retryable(String),
    Fatal(String),
}

impl ColumnRequestError {
    fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

impl std::fmt::Display for ColumnRequestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Retryable(message) | Self::Fatal(message) => formatter.write_str(message),
        }
    }
}

async fn request_columns_by_root(
    p2p_sender: &P2PSender,
    peer_id: PeerId,
    block_root: B256,
    columns: &[u64],
) -> Result<Vec<DataColumnSidecar>, ColumnRequestError> {
    let identifier = DataColumnsByRootIdentifier::new(block_root, columns.to_vec())
        .map_err(|err| ColumnRequestError::Fatal(err.to_string()))?;
    let requested_indices = columns.iter().copied().collect::<HashSet<_>>();
    let (callback, mut response_receiver) = mpsc::channel(2);
    p2p_sender
        .0
        .send(P2PMessage::Request(P2PRequest::DataColumnIdentifiers {
            peer_id,
            column_identifiers: vec![identifier],
            callback,
        }))
        .map_err(|err| {
            ColumnRequestError::Retryable(format!("data column request channel closed: {err}"))
        })?;

    let mut sidecars = Vec::new();
    let mut received_indices = HashSet::new();
    while let Some(response) = response_receiver.recv().await {
        match response {
            Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                let BeaconResponseMessage::DataColumnSidecarsByRoot(sidecar) = message.as_ref()
                else {
                    return Err(ColumnRequestError::Fatal(
                        "unexpected response type for data columns by root".to_string(),
                    ));
                };
                if !requested_indices.contains(&sidecar.index) {
                    return Err(ColumnRequestError::Fatal(format!(
                        "peer returned unrequested data column index {}",
                        sidecar.index
                    )));
                }
                if !received_indices.insert(sidecar.index) {
                    return Err(ColumnRequestError::Fatal(format!(
                        "peer returned data column index {} more than once",
                        sidecar.index
                    )));
                }
                sidecars.push(sidecar.clone());
            }
            Ok(P2PCallbackResponse::EndOfStream) => return Ok(sidecars),
            Ok(P2PCallbackResponse::Disconnected) => {
                return Err(ColumnRequestError::Retryable(
                    "peer disconnected".to_string(),
                ));
            }
            Ok(P2PCallbackResponse::Timeout) => {
                return Err(ColumnRequestError::Retryable(
                    "request timed out".to_string(),
                ));
            }
            Err(err) => {
                return Err(ColumnRequestError::Retryable(format!(
                    "callback failed: {err}"
                )));
            }
        }
    }

    Err(ColumnRequestError::Retryable(
        "response channel closed before end-of-stream".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ream_consensus_misc::beacon_block_header::SignedBeaconBlockHeader;
    use ream_req_resp::beacon::messages::BeaconResponseMessage;

    use super::*;

    fn column(index: u64) -> DataColumnSidecar {
        DataColumnSidecar {
            index,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: SignedBeaconBlockHeader::default(),
            kzg_commitments_inclusion_proof: Default::default(),
        }
    }

    #[test]
    fn tracker_queues_beyond_concurrency_and_deduplicates_roots() {
        let mut tracker = ColumnFetchTracker::default();
        let root = B256::repeat_byte(1);

        assert!(tracker.enqueue(root));
        assert!(!tracker.enqueue(root), "a root must not be queued twice");

        for index in 0..MAX_CONCURRENT_COLUMN_FETCHES {
            tracker.enqueue(B256::repeat_byte(index as u8 + 2));
        }
        let peer = PeerId::random();
        for _ in 0..MAX_CONCURRENT_COLUMN_FETCHES {
            assert!(tracker.next_fetch(&[peer], Instant::now()).is_some());
        }
        assert_eq!(tracker.in_flight_count(), MAX_CONCURRENT_COLUMN_FETCHES);
        assert!(tracker.next_fetch(&[], Instant::now()).is_none());

        tracker.finish(root, peer, ColumnFetchOutcome::Complete, Instant::now());
        assert!(
            tracker
                .next_fetch(&[PeerId::random()], Instant::now())
                .is_some(),
            "the queued root must not be lost"
        );
    }

    #[test]
    fn tracker_tries_another_peer_before_retrying_a_transient_failure() {
        let mut tracker = ColumnFetchTracker::default();
        let root = B256::repeat_byte(1);
        let first_peer = PeerId::random();
        let second_peer = PeerId::random();
        let now = Instant::now();
        tracker.enqueue(root);

        assert_eq!(
            tracker.next_fetch(&[first_peer], now),
            Some((root, first_peer))
        );
        tracker.finish(root, first_peer, ColumnFetchOutcome::Retryable, now);
        assert!(tracker.next_fetch(&[first_peer], now).is_none());
        assert!(
            !tracker.enqueue(root),
            "a waiting root must not reset its tried peers"
        );

        assert_eq!(
            tracker.next_fetch(&[first_peer, second_peer], now),
            Some((root, second_peer))
        );
    }

    #[test]
    fn tracker_parks_after_no_peer_timeout_and_wakes_after_reconnect() {
        let mut tracker = ColumnFetchTracker::default();
        let root = B256::repeat_byte(1);
        let peer = PeerId::random();
        let now = Instant::now();
        tracker.enqueue(root);

        assert_eq!(tracker.next_fetch(&[peer], now), Some((root, peer)));
        tracker.finish(root, peer, ColumnFetchOutcome::Incomplete, now);
        assert!(
            tracker
                .next_fetch(&[peer], now + NO_COLUMN_PEER_TIMEOUT)
                .is_none()
        );
        assert_eq!(
            tracker.entries.get(&root).map(|entry| entry.action_state),
            Some(FetchActionState::Parked)
        );

        tracker.peer_disconnected(peer);
        assert_eq!(
            tracker.next_fetch(&[peer], now + NO_COLUMN_PEER_TIMEOUT),
            Some((root, peer))
        );

        tracker.retain_pending(&[]);
        assert!(
            tracker.enqueue(root),
            "a pruned root may start fresh if seen later"
        );
    }

    #[test]
    fn tracker_retries_transient_failures_with_a_bound() {
        let mut tracker = ColumnFetchTracker::default();
        let root = B256::repeat_byte(1);
        let peer = PeerId::random();
        let mut now = Instant::now();
        tracker.enqueue(root);

        for attempt in 1..=MAX_TRANSIENT_PEER_ATTEMPTS {
            assert_eq!(tracker.next_fetch(&[peer], now), Some((root, peer)));
            tracker.finish(root, peer, ColumnFetchOutcome::Retryable, now);
            assert!(tracker.next_fetch(&[peer], now).is_none());

            now += NO_COLUMN_PEER_TIMEOUT;
            if attempt == MAX_TRANSIENT_PEER_ATTEMPTS {
                assert!(tracker.next_fetch(&[peer], now).is_none());
                assert_eq!(
                    tracker.entries.get(&root).map(|entry| entry.action_state),
                    Some(FetchActionState::Parked)
                );
            }
        }
    }

    #[tokio::test]
    async fn timeout_is_retryable() {
        let (p2p_sender, mut p2p_receiver) = mpsc::unbounded_channel();
        let request = tokio::spawn(async move {
            request_columns_by_root(
                &P2PSender(p2p_sender),
                PeerId::random(),
                B256::repeat_byte(1),
                &[0],
            )
            .await
        });

        let P2PMessage::Request(P2PRequest::DataColumnIdentifiers { callback, .. }) =
            p2p_receiver.recv().await.expect("request should be sent")
        else {
            panic!("expected a data-columns-by-root request");
        };
        callback
            .send(Ok(P2PCallbackResponse::Timeout))
            .await
            .expect("timeout should be delivered");

        let error = request
            .await
            .expect("request task should join")
            .expect_err("timeout must fail the response");
        assert!(error.is_retryable());
    }

    #[tokio::test]
    async fn duplicate_response_index_is_rejected() {
        let (p2p_sender, mut p2p_receiver) = mpsc::unbounded_channel();
        let request = tokio::spawn(async move {
            request_columns_by_root(
                &P2PSender(p2p_sender),
                PeerId::random(),
                B256::repeat_byte(1),
                &[0],
            )
            .await
        });

        let P2PMessage::Request(P2PRequest::DataColumnIdentifiers { callback, .. }) =
            p2p_receiver.recv().await.expect("request should be sent")
        else {
            panic!("expected a data-columns-by-root request");
        };
        let response = Arc::new(BeaconResponseMessage::DataColumnSidecarsByRoot(column(0)));
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(response.clone())))
            .await
            .expect("first response should be delivered");
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(response)))
            .await
            .expect("duplicate response should be delivered");

        let error = request
            .await
            .expect("request task should join")
            .expect_err("duplicate index must fail the response");
        assert!(error.to_string().contains("more than once"));
        assert!(!error.is_retryable());
    }

    #[tokio::test]
    async fn unrequested_response_index_is_rejected() {
        let (p2p_sender, mut p2p_receiver) = mpsc::unbounded_channel();
        let request = tokio::spawn(async move {
            request_columns_by_root(
                &P2PSender(p2p_sender),
                PeerId::random(),
                B256::repeat_byte(1),
                &[0],
            )
            .await
        });

        let P2PMessage::Request(P2PRequest::DataColumnIdentifiers { callback, .. }) =
            p2p_receiver.recv().await.expect("request should be sent")
        else {
            panic!("expected a data-columns-by-root request");
        };
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                BeaconResponseMessage::DataColumnSidecarsByRoot(column(1)),
            ))))
            .await
            .expect("response should be delivered");

        assert!(
            request
                .await
                .expect("request task should join")
                .expect_err("unrequested index must fail the response")
                .to_string()
                .contains("unrequested")
        );
    }
}

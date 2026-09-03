use std::{collections::HashSet, time::Instant};

use alloy_primitives::B256;
use libp2p::PeerId;
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use ream_consensus_misc::{constants::beacon::SLOTS_PER_EPOCH, misc::compute_start_slot_at_epoch};
use ream_fork_choice_beacon::store::Store;
use ream_storage::tables::{field::REDBField, table::REDBTable};
use tokio::time::Duration;
use tracing::warn;
use tree_hash::TreeHash;

use super::{
    BanReason, FailedRecoveryCandidate, FrontierObservation, PeerManager, RemoteNoProgressReason,
    SyncPhase,
    block_cache::validate_range_chain,
    peer_range_downloader::{PeerRangeDownloader, PeerRootsDownloader, Range, StreamOutcome},
    target_bucket,
};
use crate::block_range::BlockRangeSyncer;

pub(super) const MAX_RECOVERY_PEERS_PER_ROUND: usize = 3;
pub(super) const MAX_PROBE_REQUESTS_PER_ROUND: usize = 10;
pub(super) const MAX_TOTAL_ANCESTOR_REQUESTS_PER_ROUND: u64 = 128;
pub(super) const MAX_RECOVERY_SEED_BLOCKS: usize = 48;
pub(super) const RECOVERY_ROUND_TIMEOUT: Duration = Duration::from_secs(60);

struct RecoveryBudget {
    deadline: Instant,
    requests_used: u64,
}

impl RecoveryBudget {
    fn new() -> Self {
        Self {
            deadline: Instant::now() + RECOVERY_ROUND_TIMEOUT,
            requests_used: 0,
        }
    }

    fn has_capacity(&self) -> bool {
        Instant::now() < self.deadline && self.requests_used < MAX_TOTAL_ANCESTOR_REQUESTS_PER_ROUND
    }

    fn consume(&mut self) {
        self.requests_used += 1;
    }
}

pub(super) struct CoverageAdvance {
    pub parent_root: B256,
    pub parent_slot: u64,
    pub covered_through_slot: u64,
    pub confirming_peers: HashSet<PeerId>,
    pub proven_empty: bool,
}

pub(super) struct RecoverySeed {
    pub(super) ancestor_root: B256,
    pub(super) ancestor_slot: u64,
    pub(super) forward_blocks: Vec<SignedBeaconBlock>,
    pub(super) target_slot: u64,
    pub(super) source_peer: PeerId,
}

pub(super) enum RecoveryOutcome {
    AdvancedCoverage(CoverageAdvance),
    Seeded(RecoverySeed),
    NoProgress {
        reason: RemoteNoProgressReason,
        implicated_peers: HashSet<PeerId>,
        failed_candidates: HashSet<FailedRecoveryCandidate>,
    },
}

fn no_progress(
    reason: RemoteNoProgressReason,
    implicated_peers: HashSet<PeerId>,
) -> anyhow::Result<RecoveryOutcome> {
    Ok(RecoveryOutcome::NoProgress {
        reason,
        implicated_peers,
        failed_candidates: HashSet::new(),
    })
}

fn budget_exhausted(implicated_peers: HashSet<PeerId>) -> anyhow::Result<RecoveryOutcome> {
    no_progress(
        RemoteNoProgressReason::RecoveryBudgetExhausted,
        implicated_peers,
    )
}

fn is_processable_connection_point(
    store: &Store,
    parent_root: B256,
    first_child_slot: u64,
) -> anyhow::Result<bool> {
    if store.db.block_provider().get(parent_root)?.is_none() {
        return Ok(false);
    }
    if store.db.state_provider().get(parent_root)?.is_none() {
        return Ok(false);
    }
    let finalized_checkpoint = store.db.finalized_checkpoint_provider().get()?;
    let finalized_slot = compute_start_slot_at_epoch(finalized_checkpoint.epoch);
    if first_child_slot <= finalized_slot {
        return Ok(false);
    }
    let checkpoint_block = store.get_checkpoint_block(parent_root, finalized_checkpoint.epoch)?;
    Ok(checkpoint_block == finalized_checkpoint.root)
}

enum ProbeStep {
    Empty,
    Found(Vec<SignedBeaconBlock>),
    Failed,
}

fn reserve_round_robin(
    peer_manager: &mut PeerManager,
    peers: &[PeerId],
    excluded: &HashSet<PeerId>,
    start_index: usize,
) -> Option<(PeerId, usize)> {
    if peers.is_empty() {
        return None;
    }
    for offset in 0..peers.len() {
        let candidate = peers[(start_index + offset) % peers.len()];
        if excluded.contains(&candidate) {
            continue;
        }
        if let Some(peer) =
            peer_manager.fetch_idle_peer_from_excluding(&[candidate], &HashSet::new())
        {
            return Some((peer.peer_id, offset + 1));
        }
    }
    None
}

impl BlockRangeSyncer {
    pub(super) async fn run_recovery(
        &mut self,
        observation: &FrontierObservation,
        candidate_peers: &[PeerId],
        excluded: &HashSet<PeerId>,
    ) -> anyhow::Result<RecoveryOutcome> {
        let mut budget = RecoveryBudget::new();
        let tier = self
            .frontier_for(observation.phase)
            .as_ref()
            .map(|frontier| frontier.tier())
            .unwrap_or(0);

        let baseline_end = self
            .frontier_for(observation.phase)
            .as_ref()
            .and_then(|frontier| frontier.confirmed_empty_through.as_ref())
            .map(|coverage| coverage.end_slot_exclusive)
            .unwrap_or(observation.anchor_slot + 1);

        let probe_peers: Vec<PeerId> = candidate_peers
            .iter()
            .filter(|peer_id| !excluded.contains(peer_id))
            .take(MAX_RECOVERY_PEERS_PER_ROUND)
            .copied()
            .collect();

        if probe_peers.is_empty() {
            return no_progress(RemoteNoProgressReason::ProbeNotFound, HashSet::new());
        }

        let mut implicated_peers: HashSet<PeerId> = HashSet::new();
        let mut cursor = baseline_end;
        let mut confirmed_end: Option<(u64, HashSet<PeerId>)> = None;
        let mut found: Option<(Vec<SignedBeaconBlock>, PeerId)> = None;
        let mut failed_this_round: HashSet<PeerId> = HashSet::new();
        let mut next_peer_index = 0usize;

        for _ in 0..MAX_PROBE_REQUESTS_PER_ROUND {
            if !budget.has_capacity() || cursor > observation.target_slot {
                break;
            }
            let Some((peer_id, advance_by)) = reserve_round_robin(
                &mut self.peer_manager,
                &probe_peers,
                &failed_this_round,
                next_peer_index,
            ) else {
                break;
            };
            next_peer_index = (next_peer_index + advance_by) % probe_peers.len();
            let window = SLOTS_PER_EPOCH.min(observation.target_slot.saturating_add(1) - cursor);
            let range = Range::new(cursor, window);
            budget.consume();

            match self
                .probe_range(peer_id, range, &mut implicated_peers)
                .await
            {
                ProbeStep::Empty => {
                    match &mut confirmed_end {
                        Some((end, peers)) => {
                            *end = cursor + window;
                            peers.insert(peer_id);
                        }
                        None => confirmed_end = Some((cursor + window, HashSet::from([peer_id]))),
                    }
                    cursor += window;
                }
                ProbeStep::Found(blocks) => {
                    found = Some((blocks, peer_id));
                    break;
                }
                ProbeStep::Failed => {
                    failed_this_round.insert(peer_id);
                }
            }
        }

        if let Some((blocks, peer_id)) = found {
            return self
                .resolve_candidate(
                    observation,
                    blocks,
                    HashSet::from([peer_id]),
                    &probe_peers,
                    &mut budget,
                    implicated_peers,
                )
                .await;
        }

        if let Some((end, peers)) = confirmed_end
            && end > baseline_end
        {
            return Ok(RecoveryOutcome::AdvancedCoverage(CoverageAdvance {
                parent_root: observation.anchor_root,
                parent_slot: observation.anchor_slot,
                covered_through_slot: end - 1,
                proven_empty: true,
                confirming_peers: peers,
            }));
        }

        if tier < 3 {
            return no_progress(RemoteNoProgressReason::ProbeNotFound, implicated_peers);
        }

        self.run_fallback(
            observation,
            candidate_peers,
            excluded,
            &mut budget,
            implicated_peers,
        )
        .await
    }

    async fn probe_range(
        &mut self,
        peer_id: PeerId,
        range: Range,
        implicated_peers: &mut HashSet<PeerId>,
    ) -> ProbeStep {
        let handle = PeerRangeDownloader::start(
            peer_id,
            self.p2p_sender.clone(),
            self.executor.clone(),
            range,
        );
        let result = handle.await;
        let idle = IdleOnDrop::new(&mut self.peer_manager, peer_id);
        let outcome = match result {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(err)) => {
                warn!("Recovery probe task failed: {err}");
                implicated_peers.insert(peer_id);
                return ProbeStep::Failed;
            }
            Err(err) => {
                warn!("Recovery probe task panicked: {err}");
                implicated_peers.insert(peer_id);
                return ProbeStep::Failed;
            }
        };
        drop(idle);

        match outcome {
            StreamOutcome::Complete(blocks) if blocks.is_empty() => {
                implicated_peers.insert(peer_id);
                ProbeStep::Empty
            }
            StreamOutcome::Complete(blocks) => {
                let range_end = range.start_slot + range.count;
                let out_of_range = blocks.iter().any(|block| {
                    block.message.slot < range.start_slot || block.message.slot >= range_end
                });
                if out_of_range || validate_range_chain(&blocks).is_err() {
                    self.peer_manager.ban_peer(
                        &peer_id,
                        BanReason::ProtocolError(
                            "block(s) outside the requested range or not a valid chain".to_string(),
                        ),
                    );
                    return ProbeStep::Failed;
                }
                ProbeStep::Found(blocks)
            }
            StreamOutcome::Failed(_) => {
                implicated_peers.insert(peer_id);
                ProbeStep::Failed
            }
        }
    }

    async fn run_fallback(
        &mut self,
        observation: &FrontierObservation,
        candidate_peers: &[PeerId],
        excluded: &HashSet<PeerId>,
        budget: &mut RecoveryBudget,
        implicated_peers: HashSet<PeerId>,
    ) -> anyhow::Result<RecoveryOutcome> {
        if !budget.has_capacity() {
            return budget_exhausted(implicated_peers);
        }
        match observation.phase {
            SyncPhase::Head => {
                let eligible: Vec<PeerId> = candidate_peers
                    .iter()
                    .filter(|peer_id| !excluded.contains(peer_id))
                    .copied()
                    .collect();
                let Some(peer) = self
                    .peer_manager
                    .fetch_idle_peer_from_excluding(&eligible, &HashSet::new())
                else {
                    return no_progress(RemoteNoProgressReason::AncestorNotFound, implicated_peers);
                };
                let peer_id = peer.peer_id;
                let end_exclusive = observation.target_slot.saturating_add(1);
                let window = SLOTS_PER_EPOCH.min(end_exclusive);
                let start = end_exclusive.saturating_sub(window);
                let range = Range::new(start, window.max(1));
                let mut implicated = implicated_peers;
                budget.consume();
                match self.probe_range(peer_id, range, &mut implicated).await {
                    ProbeStep::Found(blocks) => {
                        self.resolve_candidate(
                            observation,
                            blocks,
                            HashSet::from([peer_id]),
                            &eligible,
                            budget,
                            implicated,
                        )
                        .await
                    }
                    _ => no_progress(RemoteNoProgressReason::AncestorNotFound, implicated),
                }
            }
            SyncPhase::Finalized => {
                let epoch = observation.target_slot / SLOTS_PER_EPOCH;
                let bucket = target_bucket(observation.target_slot);
                let previously_failed = self
                    .frontier_for(observation.phase)
                    .as_ref()
                    .map(|frontier| frontier.failed_candidates.clone())
                    .unwrap_or_default();

                let exact_epoch_peers = self.peer_manager.exact_finalized_epoch_peers(epoch);
                let ordered_peers = self.group_by_finalized_root_agreement(&exact_epoch_peers);

                let mut implicated = implicated_peers;
                let mut failed_candidates = HashSet::new();

                for peer_id in &ordered_peers {
                    let peer_id = *peer_id;
                    if !budget.has_capacity() {
                        break;
                    }
                    if excluded.contains(&peer_id) {
                        continue;
                    }
                    let Some(status) = self.peer_manager.status_of(&peer_id) else {
                        continue;
                    };
                    let candidate = FailedRecoveryCandidate {
                        peer_id,
                        candidate_root: status.finalized_root,
                        target_bucket: bucket,
                    };
                    if previously_failed.contains(&candidate)
                        || failed_candidates.contains(&candidate)
                    {
                        continue;
                    }
                    let Some(reserved) = self
                        .peer_manager
                        .fetch_idle_peer_from_excluding(&[peer_id], &HashSet::new())
                    else {
                        continue;
                    };
                    debug_assert_eq!(reserved.peer_id, peer_id);

                    budget.consume();
                    let Some(block) = self
                        .fetch_single_root(peer_id, status.finalized_root, &mut implicated)
                        .await
                    else {
                        failed_candidates.insert(candidate);
                        continue;
                    };

                    let required_backtrack_floor = block
                        .message
                        .slot
                        .saturating_sub(MAX_TOTAL_ANCESTOR_REQUESTS_PER_ROUND);
                    if status.earliest_available_slot > required_backtrack_floor {
                        implicated.insert(peer_id);
                        failed_candidates.insert(candidate);
                        continue;
                    }

                    match self
                        .resolve_candidate(
                            observation,
                            vec![block],
                            HashSet::from([peer_id]),
                            &ordered_peers,
                            budget,
                            implicated,
                        )
                        .await?
                    {
                        RecoveryOutcome::NoProgress {
                            reason,
                            implicated_peers: inner_implicated,
                            failed_candidates: mut inner_failed,
                        } => {
                            inner_failed.insert(candidate);
                            inner_failed.extend(failed_candidates.iter().copied());
                            if reason == RemoteNoProgressReason::RecoveryBudgetExhausted {
                                return Ok(RecoveryOutcome::NoProgress {
                                    reason,
                                    implicated_peers: inner_implicated,
                                    failed_candidates: inner_failed,
                                });
                            }
                            implicated = inner_implicated;
                            failed_candidates = inner_failed;
                        }
                        other => return Ok(other),
                    }
                }

                let reason = if budget.has_capacity() {
                    RemoteNoProgressReason::AncestorNotFound
                } else {
                    RemoteNoProgressReason::RecoveryBudgetExhausted
                };
                Ok(RecoveryOutcome::NoProgress {
                    reason,
                    implicated_peers: implicated,
                    failed_candidates,
                })
            }
        }
    }

    fn group_by_finalized_root_agreement(&self, peers: &[PeerId]) -> Vec<PeerId> {
        let mut by_root: std::collections::BTreeMap<B256, Vec<PeerId>> =
            std::collections::BTreeMap::new();
        for &peer_id in peers {
            let Some(status) = self.peer_manager.status_of(&peer_id) else {
                continue;
            };
            by_root
                .entry(status.finalized_root)
                .or_default()
                .push(peer_id);
        }
        for group in by_root.values_mut() {
            group.sort();
        }
        let mut groups: Vec<(B256, Vec<PeerId>)> = by_root.into_iter().collect();
        groups.sort_by(|(root_a, group_a), (root_b, group_b)| {
            group_b.len().cmp(&group_a.len()).then(root_a.cmp(root_b))
        });
        groups.into_iter().flat_map(|(_, group)| group).collect()
    }

    async fn fetch_single_root(
        &mut self,
        peer_id: PeerId,
        root: B256,
        implicated_peers: &mut HashSet<PeerId>,
    ) -> Option<SignedBeaconBlock> {
        let handle = PeerRootsDownloader::start(
            peer_id,
            self.p2p_sender.clone(),
            self.executor.clone(),
            vec![root],
        );
        let result = handle.await;
        let idle = IdleOnDrop::new(&mut self.peer_manager, peer_id);
        let outcome = match result {
            Ok(Ok(outcome)) => outcome,
            _ => {
                drop(idle);
                implicated_peers.insert(peer_id);
                return None;
            }
        };
        drop(idle);

        match outcome {
            StreamOutcome::Complete(blocks) if blocks.len() == 1 => {
                let block = &blocks[0];
                if block.message.tree_hash_root() == root {
                    Some(blocks.into_iter().next().expect("checked len == 1 above"))
                } else {
                    self.peer_manager.ban_peer(
                        &peer_id,
                        BanReason::ProtocolError("returned an unrequested root".to_string()),
                    );
                    None
                }
            }
            StreamOutcome::Complete(_) => {
                implicated_peers.insert(peer_id);
                None
            }
            StreamOutcome::Failed(_) => {
                implicated_peers.insert(peer_id);
                None
            }
        }
    }

    async fn resolve_candidate(
        &mut self,
        observation: &FrontierObservation,
        blocks: Vec<SignedBeaconBlock>,
        confirming_peers: HashSet<PeerId>,
        fallback_peers: &[PeerId],
        budget: &mut RecoveryBudget,
        implicated_peers: HashSet<PeerId>,
    ) -> anyhow::Result<RecoveryOutcome> {
        let mut blocks = blocks;
        blocks.sort_by_key(|block| block.message.slot);

        let primary_peer = *confirming_peers
            .iter()
            .next()
            .expect("resolve_candidate is always called with a non-empty confirming_peers set");

        let leading_parent = blocks[0].message.parent_root;
        let leading_slot = blocks[0].message.slot;

        let connected_at = {
            let store = self.beacon_chain.store.lock().await;
            if is_processable_connection_point(&store, leading_parent, leading_slot)? {
                store
                    .db
                    .block_provider()
                    .get(leading_parent)?
                    .map(|block| block.message.slot)
            } else {
                None
            }
        };

        if let Some(leading_parent_slot) = connected_at {
            return self
                .trim_and_seed(
                    observation,
                    (leading_parent, leading_parent_slot),
                    blocks,
                    confirming_peers,
                    implicated_peers,
                    primary_peer,
                )
                .await;
        }

        if !budget.has_capacity() {
            return budget_exhausted(implicated_peers);
        }

        let finalized_epoch_start = {
            let store = self.beacon_chain.store.lock().await;
            compute_start_slot_at_epoch(store.db.finalized_checkpoint_provider().get()?.epoch)
        };

        let mut chain: Vec<SignedBeaconBlock> = blocks;
        let mut visited: HashSet<B256> = HashSet::from([leading_parent]);
        let mut cursor_root = leading_parent;
        let mut cursor_slot = leading_slot;
        let mut implicated_peers = implicated_peers;
        let ancestor_walk_peers: Vec<PeerId> = confirming_peers
            .iter()
            .copied()
            .chain(fallback_peers.iter().copied())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let mut next_peer_index = 0usize;
        let mut hop_failed: HashSet<PeerId> = HashSet::new();

        while budget.has_capacity() && cursor_slot > finalized_epoch_start {
            let Some((peer_id, advance_by)) = reserve_round_robin(
                &mut self.peer_manager,
                &ancestor_walk_peers,
                &hop_failed,
                next_peer_index,
            ) else {
                return no_progress(RemoteNoProgressReason::AncestorNotFound, implicated_peers);
            };
            next_peer_index = (next_peer_index + advance_by) % ancestor_walk_peers.len();
            budget.consume();
            let Some(cursor_block) = self
                .fetch_single_root(peer_id, cursor_root, &mut implicated_peers)
                .await
            else {
                hop_failed.insert(peer_id);
                continue;
            };
            hop_failed.clear();
            if cursor_block.message.slot >= cursor_slot {
                self.peer_manager.ban_peer(
                    &peer_id,
                    BanReason::ProtocolError(
                        "ancestor walk did not strictly decrease slot".to_string(),
                    ),
                );
                return no_progress(RemoteNoProgressReason::AncestorNotFound, implicated_peers);
            }
            let grandparent_root = cursor_block.message.parent_root;
            let first_child_slot = cursor_block.message.slot;
            let grandparent_slot = {
                let store = self.beacon_chain.store.lock().await;
                if is_processable_connection_point(&store, grandparent_root, first_child_slot)? {
                    store
                        .db
                        .block_provider()
                        .get(grandparent_root)?
                        .map(|block| block.message.slot)
                } else {
                    None
                }
            };
            chain.insert(0, cursor_block);
            if let Some(grandparent_slot) = grandparent_slot {
                return self
                    .trim_and_seed(
                        observation,
                        (grandparent_root, grandparent_slot),
                        chain,
                        confirming_peers,
                        implicated_peers,
                        peer_id,
                    )
                    .await;
            }
            if !visited.insert(grandparent_root) {
                return no_progress(RemoteNoProgressReason::AncestorNotFound, implicated_peers);
            }
            cursor_root = grandparent_root;
            cursor_slot = first_child_slot;
        }

        budget_exhausted(implicated_peers)
    }

    async fn trim_and_seed(
        &mut self,
        observation: &FrontierObservation,
        ancestor: (B256, u64),
        mut chain: Vec<SignedBeaconBlock>,
        confirming_peers: HashSet<PeerId>,
        implicated_peers: HashSet<PeerId>,
        primary_peer: PeerId,
    ) -> anyhow::Result<RecoveryOutcome> {
        let (ancestor_root, ancestor_slot) = ancestor;
        chain.retain(|block| {
            block.message.slot > ancestor_slot && block.message.slot <= observation.target_slot
        });

        let mut new_ancestor_root = ancestor_root;
        let mut new_ancestor_slot = ancestor_slot;
        {
            let store = self.beacon_chain.store.lock().await;
            while let Some(first) = chain.first() {
                let first_root = first.message.tree_hash_root();
                let first_slot = first.message.slot;
                let next_child_slot = chain.get(1).map_or(first_slot, |block| block.message.slot);
                if is_processable_connection_point(&store, first_root, next_child_slot)? {
                    new_ancestor_root = first_root;
                    new_ancestor_slot = first_slot;
                    chain.remove(0);
                } else {
                    break;
                }
            }
        }

        if chain.is_empty() {
            if new_ancestor_slot < observation.anchor_slot {
                return no_progress(RemoteNoProgressReason::NoNewDescendants, implicated_peers);
            }
            return Ok(RecoveryOutcome::AdvancedCoverage(CoverageAdvance {
                parent_root: new_ancestor_root,
                parent_slot: new_ancestor_slot,
                covered_through_slot: new_ancestor_slot,
                proven_empty: false,
                confirming_peers,
            }));
        }

        if chain.len() > MAX_RECOVERY_SEED_BLOCKS {
            chain.truncate(MAX_RECOVERY_SEED_BLOCKS);
        }

        Ok(RecoveryOutcome::Seeded(RecoverySeed {
            ancestor_root: new_ancestor_root,
            ancestor_slot: new_ancestor_slot,
            forward_blocks: chain,
            target_slot: observation.target_slot,
            source_peer: primary_peer,
        }))
    }
}

struct IdleOnDrop<'a> {
    peer_manager: &'a mut super::PeerManager,
    peer_id: PeerId,
}

impl<'a> IdleOnDrop<'a> {
    fn new(peer_manager: &'a mut super::PeerManager, peer_id: PeerId) -> Self {
        Self {
            peer_manager,
            peer_id,
        }
    }
}

impl Drop for IdleOnDrop<'_> {
    fn drop(&mut self) {
        self.peer_manager.mark_peer_as_idle(&self.peer_id);
    }
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use discv5::{Enr, enr::CombinedKey};
    use libp2p::PeerId;
    use parking_lot::RwLock;
    use ream_p2p::network::beacon::{network_state::NetworkState, peer::CachedPeer};
    use ream_peer::{ConnectionState, Direction};
    use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};

    use super::*;

    fn test_network_state() -> Arc<NetworkState> {
        let enr_key = CombinedKey::generate_secp256k1();
        Arc::new(NetworkState {
            local_enr: RwLock::new(Enr::builder().build(&enr_key).expect("valid enr")),
            peer_table: RwLock::new(std::collections::HashMap::new()),
            meta_data: RwLock::new(GetMetaDataV3::default()),
            status: RwLock::new(Status::default()),
            data_dir: PathBuf::new(),
        })
    }

    fn idle_peer_manager_with(peer_ids: &[PeerId]) -> PeerManager {
        let network_state = test_network_state();
        for &peer_id in peer_ids {
            let mut peer = CachedPeer::new(
                peer_id,
                None,
                ConnectionState::Connected,
                Direction::Outbound,
                None,
            );
            peer.status = Some(Status::default());
            network_state.peer_table.write().insert(peer_id, peer);
        }
        let mut peer_manager = PeerManager::new(network_state);
        peer_manager.update_peer_set();
        peer_manager
    }

    #[test]
    fn recovery_budget_stops_capacity_at_the_request_cap_regardless_of_time_remaining() {
        let mut budget = RecoveryBudget::new();
        assert!(budget.has_capacity());
        for _ in 0..MAX_TOTAL_ANCESTOR_REQUESTS_PER_ROUND {
            assert!(
                budget.has_capacity(),
                "must still have capacity before the cap is reached"
            );
            budget.consume();
        }
        assert!(
            !budget.has_capacity(),
            "the shared budget must run out at exactly MAX_TOTAL_ANCESTOR_REQUESTS_PER_ROUND, \
             regardless of which phase (probe, fallback, or ancestor-walk hops) consumed it"
        );
    }

    #[test]
    fn recovery_budget_expires_on_deadline_even_with_requests_remaining() {
        let mut budget = RecoveryBudget::new();
        budget.deadline = Instant::now();
        std::thread::sleep(Duration::from_millis(1));
        assert!(
            !budget.has_capacity(),
            "a round past its soft deadline must refuse further dispatch even if the request \
             count is nowhere near the cap -- fallback and ancestor-walk hops must respect this \
             the same way the forward probe already does"
        );
    }

    #[test]
    fn reserve_round_robin_skips_excluded_and_wraps_around() {
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let mut peer_manager = idle_peer_manager_with(&[peer_a, peer_b]);

        let peers = [peer_a, peer_b];
        let excluded = HashSet::from([peer_a]);
        let (selected, advance_by) = reserve_round_robin(&mut peer_manager, &peers, &excluded, 0)
            .expect("peer_b should still be selectable");
        assert_eq!(selected, peer_b);
        assert_eq!(advance_by, 2);
    }
}

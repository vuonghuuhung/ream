mod block_cache;
mod peer_manager;
mod peer_range_downloader;

use std::{
    collections::HashSet,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use anyhow::{anyhow, bail, ensure};
use block_cache::{BlockAndBlobBundle, BlockCache, DataToFetch, RequestKey};
use futures::task::noop_waker;
use libp2p::PeerId;
use peer_manager::{BanReason, MIN_SYNC_PEERS, PeerManager, TargetQualification, TargetSelection};
use peer_range_downloader::{
    DownloadFailure, PeerBlobIdentifierDownloader, PeerDataColumnIdentifierDownloader,
    PeerDataColumnRangeDownloader, PeerRootsDownloader, StreamOutcome,
};
use ream_chain_beacon::beacon_chain::{
    BeaconChain, BlockProcessingOutcome, is_data_availability_check_required,
};
use ream_consensus_beacon::{
    blob_sidecar::{BlobIdentifier, BlobSidecar},
    data_column_sidecar::{
        ColumnIdentifier, DataColumnSidecar, get_data_column_sidecars_from_block,
    },
    electra::beacon_block::SignedBeaconBlock,
    matrix_entry::{compute_cells_and_kzg_proofs, das_context},
};
use ream_consensus_misc::{constants::beacon::SLOTS_PER_EPOCH, misc::compute_epoch_at_slot};
use ream_executor::ReamExecutor;
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::network::beacon::{channel::P2PMessage, network_state::NetworkState};
use ream_polynomial_commitments::handlers::verify_blob_kzg_proof_batch;
use ream_req_resp::{
    MAX_CONCURRENT_REQUESTS, beacon::messages::data_column_sidecars::DataColumnsByRootIdentifier,
    inbound_protocol::ResponseCode,
};
use ream_storage::tables::{
    field::REDBField,
    table::{CustomTable, REDBTable},
};
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle, time::sleep};
use tracing::{info, warn};
use tree_hash::TreeHash;

use crate::block_range::peer_range_downloader::{PeerRangeDownloader, Range};

const MAX_BLOBS_PER_REQUEST: usize = 6;
const MAX_BLOCKS_PER_REQUEST: u64 = 10;
const SLEEP_DURATION: Duration = Duration::from_secs(5);

/// Max slots behind wall-clock to still count as synced (like Lighthouse's
/// `SLOT_IMPORT_TOLERANCE`). A thin/early peer sample can be fooled; the clock can't.
const SLOT_IMPORT_TOLERANCE: u64 = 32;

const ZERO_PROGRESS_BACKOFF: Duration = Duration::from_secs(30);

const CANDIDATE_EXHAUSTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Validates downloaded blob sidecars and derives the columns needed for data availability.
/// An empty `blob_sidecars` map defers to the block-lookup coordinator instead of erroring,
/// since range sync never fetches legacy blob sidecars for post-Fulu blocks.
fn build_data_columns_from_blob_sidecars(
    block: &SignedBeaconBlock,
    blob_sidecars: &std::collections::HashMap<BlobIdentifier, BlobSidecar>,
    verify_data_availability: bool,
) -> anyhow::Result<Vec<DataColumnSidecar>> {
    if !verify_data_availability || blob_sidecars.is_empty() {
        return Ok(Vec::new());
    }

    let block_root = block.message.tree_hash_root();
    let expected_header = block.signed_header();
    let commitments = &block.message.body.blob_kzg_commitments;

    ensure!(
        blob_sidecars.len() == commitments.len(),
        "Expected {} blob sidecars for block {block_root}, got {}",
        commitments.len(),
        blob_sidecars.len()
    );

    let mut blobs = Vec::with_capacity(commitments.len());
    let mut proofs = Vec::with_capacity(commitments.len());
    for (index, expected_commitment) in commitments.iter().enumerate() {
        let identifier = BlobIdentifier::new(block_root, index as u64);
        let sidecar = blob_sidecars
            .get(&identifier)
            .ok_or_else(|| anyhow!("Missing blob sidecar {index} for block {block_root}"))?;
        ensure!(
            sidecar.signed_block_header == expected_header,
            "Blob sidecar {index} does not belong to block {block_root}"
        );
        ensure!(
            sidecar.kzg_commitment == *expected_commitment,
            "Blob sidecar {index} commitment does not match block {block_root}"
        );
        ensure!(
            sidecar.verify_blob_sidecar_inclusion_proof(),
            "Invalid inclusion proof for blob sidecar {index} of block {block_root}"
        );

        blobs.push(sidecar.blob.clone());
        proofs.push(sidecar.kzg_proof);
    }

    ensure!(
        verify_blob_kzg_proof_batch(&blobs, commitments, &proofs)?,
        "Invalid blob KZG proof for block {block_root}"
    );

    let cells_and_kzg_proofs = blobs
        .iter()
        .map(|blob| compute_cells_and_kzg_proofs(blob, das_context()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    get_data_column_sidecars_from_block(block, cells_and_kzg_proofs)
        .map_err(|err| anyhow!("Failed to build data columns for block {block_root}: {err}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncPhase {
    Finalized,
    Head,
}

#[derive(Debug, Clone)]
struct ActivePhaseTarget {
    slot: u64,
    qualification: TargetQualification,
}

pub struct BlockRangeSyncer {
    pub beacon_chain: Arc<BeaconChain>,
    pub peer_manager: PeerManager,
    pub p2p_sender: UnboundedSender<P2PMessage>,
    pub executor: ReamExecutor,
    next_segment_not_before: Option<Instant>,
}

impl BlockRangeSyncer {
    pub fn new(
        beacon_chain: Arc<BeaconChain>,
        p2p_sender: UnboundedSender<P2PMessage>,
        network_state: Arc<NetworkState>,
        executor: ReamExecutor,
    ) -> Self {
        Self {
            beacon_chain,
            p2p_sender,
            peer_manager: PeerManager::new(network_state),
            executor,
            next_segment_not_before: None,
        }
    }

    pub async fn is_synced_to_head_slot(&mut self) -> bool {
        self.peer_manager.update_peer_set();

        let store = self.beacon_chain.store.lock().await;
        let latest_synced_slot = store
            .db
            .slot_index_provider()
            .get_highest_slot()
            .unwrap_or_default()
            .unwrap_or(0);
        let Ok(finalized_epoch) = store.db.finalized_checkpoint_provider().get() else {
            return false;
        };
        let finalized_epoch = finalized_epoch.epoch;
        let Ok(current_slot) = store.get_current_slot() else {
            return false;
        };
        drop(store);

        let finalized_selection = self.peer_manager.best_finalized(finalized_epoch);
        let still_behind_finalized = matches!(
            &finalized_selection,
            TargetSelection::Ready { target_slot, .. } if latest_synced_slot < *target_slot
        );
        if still_behind_finalized {
            return false;
        }

        let our_head_epoch = latest_synced_slot / SLOTS_PER_EPOCH;
        let head_selection = self
            .peer_manager
            .best_non_finalized(MIN_SYNC_PEERS, our_head_epoch);
        // The clock is ground truth peers can't fake.
        let clock_confirms_caught_up =
            current_slot.saturating_sub(latest_synced_slot) <= SLOT_IMPORT_TOLERANCE;

        let TargetSelection::Ready { target_slot, .. } = head_selection else {
            return clock_confirms_caught_up;
        };

        let peers_report_caught_up = target_slot <= latest_synced_slot;

        peers_report_caught_up && clock_confirms_caught_up
    }

    pub fn start(mut self) -> JoinHandle<anyhow::Result<(BlockRangeSyncer, anyhow::Result<()>)>> {
        let executor = self.executor.clone();
        executor.spawn(async move {
            let result = self.run_segment().await;
            (self, result)
        })
    }

    async fn run_segment(&mut self) -> anyhow::Result<()> {
        if let Some(not_before) = self.next_segment_not_before.take()
            && let Some(remaining) = not_before.checked_duration_since(Instant::now())
        {
            info!("Backing off {remaining:?} after the previous segment made no progress...");
            sleep(remaining).await;
        }

        let store = self.beacon_chain.store.lock().await;
        let head_root = store
            .get_head()
            .map_err(|err| anyhow!("Failed to get canonical head: {err}"))?;
        let head_slot = store
            .db
            .block_provider()
            .get(head_root)
            .map_err(|err| anyhow!("Failed to load head block: {err}"))?
            .ok_or_else(|| anyhow!("Head block {head_root} not found"))?
            .message
            .slot;
        let finalized_epoch = store
            .db
            .finalized_checkpoint_provider()
            .get()
            .map_err(|err| anyhow!("Failed to get finalized checkpoint: {err}"))?
            .epoch;
        drop(store);
        let our_head_epoch = head_slot / SLOTS_PER_EPOCH;

        // phase 1: download majority of blocks from ranges
        let mut block_cache = BlockCache::new(head_root, head_slot);
        let mut task_handles = vec![];

        let mut phase = SyncPhase::Finalized;
        let mut active_target: Option<ActivePhaseTarget> = None;
        let mut saw_empty_range = false;
        let mut finalized_phase_settled = false;
        let mut finalized_target_was_ahead = false;
        let mut candidate_exhausted_since: Option<Instant> = None;
        let mut ended_due_to_candidate_exhaustion = false;

        loop {
            self.peer_manager.update_peer_set();

            let required_columns = self
                .beacon_chain
                .store
                .lock()
                .await
                .data_availability_checker
                .required_columns()
                .clone();

            let selection = match phase {
                SyncPhase::Finalized => self.peer_manager.best_finalized(finalized_epoch),
                SyncPhase::Head => self
                    .peer_manager
                    .best_non_finalized(MIN_SYNC_PEERS, our_head_epoch),
            };

            if active_target.is_none() {
                if phase == SyncPhase::Finalized {
                    match &selection {
                        TargetSelection::Ready {
                            target_slot,
                            eligible_peers,
                        } => {
                            if block_cache.next_start_slot() >= *target_slot {
                                phase = SyncPhase::Head;
                                continue;
                            }
                            if eligible_peers.len() < MIN_SYNC_PEERS {
                                info!(
                                    "Finalized target not yet confirmed by enough peers ({} < {MIN_SYNC_PEERS}), waiting...",
                                    eligible_peers.len()
                                );
                                sleep(SLEEP_DURATION).await;
                                continue;
                            }
                        }
                        TargetSelection::NoQuorum => {
                            phase = SyncPhase::Head;
                            continue;
                        }
                    }
                } else if let TargetSelection::NoQuorum = &selection {
                    if finalized_phase_settled || block_cache.block_count() > 0 {
                        info!(
                            "No head-phase sync target after the finalized phase settled; ending this segment."
                        );
                        break;
                    }
                    info!("No sync target yet, waiting for peers...");
                    sleep(SLEEP_DURATION).await;
                    continue;
                }
            }

            if let TargetSelection::Ready {
                target_slot,
                eligible_peers,
            } = &selection
            {
                let sufficient = match phase {
                    SyncPhase::Finalized => eligible_peers.len() >= MIN_SYNC_PEERS,
                    SyncPhase::Head => true,
                };
                if sufficient {
                    let qualification = match phase {
                        SyncPhase::Finalized => {
                            TargetQualification::FinalizedEpoch(target_slot / SLOTS_PER_EPOCH)
                        }
                        SyncPhase::Head => {
                            TargetQualification::HeadEpoch(target_slot / SLOTS_PER_EPOCH)
                        }
                    };
                    active_target = Some(match active_target {
                        Some(existing) if existing.slot > *target_slot => existing,
                        _ => ActivePhaseTarget {
                            slot: *target_slot,
                            qualification,
                        },
                    });
                }
            }

            let Some(target) = active_target.clone() else {
                sleep(SLEEP_DURATION).await;
                continue;
            };

            let candidate_peers = self.peer_manager.peers_satisfying(target.qualification);

            if candidate_peers.is_empty() {
                let exhausted_since = *candidate_exhausted_since.get_or_insert_with(Instant::now);
                if exhausted_since.elapsed() >= CANDIDATE_EXHAUSTION_TIMEOUT {
                    info!(
                        "No peer has qualified for the active sync target for over {CANDIDATE_EXHAUSTION_TIMEOUT:?}; ending this segment."
                    );
                    ended_due_to_candidate_exhaustion = true;
                    break;
                }
            } else {
                candidate_exhausted_since = None;
            }

            let now = Instant::now();
            poll_ready_tasks(
                &mut task_handles,
                &mut block_cache,
                &mut self.peer_manager,
                &required_columns,
                &mut saw_empty_range,
                &candidate_peers,
                now,
            )?;

            let current_epoch = self
                .beacon_chain
                .store
                .lock()
                .await
                .get_current_store_epoch()?;
            let data_to_fetch = block_cache.data_to_fetch(
                target.slot,
                current_epoch,
                &required_columns,
                &candidate_peers,
                now,
            );
            info!(
                "Forward sync status: Downloaded Blocks {}, Downloaded Blobs {}/{}, Stage {data_to_fetch}",
                block_cache.block_count(),
                block_cache.downloaded_blob_count(),
                block_cache.blob_count(),
            );

            match data_to_fetch {
                DataToFetch::BlockRange(range) => {
                    let key = RequestKey::BlockRange(range);
                    let excluded = block_cache.attempted_peers_for(key);
                    let Some(peer) = self
                        .peer_manager
                        .fetch_idle_peer_from_excluding(&candidate_peers, &excluded)
                    else {
                        self.peer_manager.update_peer_set();
                        info!("No idle peers available for block range sync.");
                        block_cache.push_retry_range(range);
                        sleep(SLEEP_DURATION).await;
                        continue;
                    };

                    block_cache.mark_block_range_in_progress(range);
                    task_handles.push(DownloadTask::new_block_range(
                        PeerRangeDownloader::start(
                            peer.peer_id,
                            self.p2p_sender.clone(),
                            self.executor.clone(),
                            range,
                        ),
                        range,
                        peer.peer_id,
                    ));
                }
                DataToFetch::DataColumnRange(range) => {
                    let key = RequestKey::ColumnRange(range);
                    let excluded = block_cache.attempted_peers_for(key);
                    let Some(peer) = self
                        .peer_manager
                        .fetch_idle_peer_from_excluding(&candidate_peers, &excluded)
                    else {
                        self.peer_manager.update_peer_set();
                        info!("No idle peers available for data column range sync.");
                        block_cache.push_column_range(range);
                        sleep(SLEEP_DURATION).await;
                        continue;
                    };

                    let expected_known_identifiers =
                        block_cache.expected_column_identifiers_in_range(range, &required_columns);

                    block_cache.mark_column_range_in_progress(range);
                    task_handles.push(DownloadTask::new_data_column_range(
                        PeerDataColumnRangeDownloader::start(
                            peer.peer_id,
                            self.p2p_sender.clone(),
                            self.executor.clone(),
                            range,
                            required_columns.iter().copied().collect(),
                        ),
                        range,
                        peer.peer_id,
                        expected_known_identifiers,
                    ));
                }
                DataToFetch::MissingBlockRoots(mut block_roots) => {
                    let mut exhausted_this_tick = HashSet::new();
                    while !block_roots.is_empty() {
                        let Some(peer) = self
                            .peer_manager
                            .fetch_idle_peer_from_excluding(&candidate_peers, &exhausted_this_tick)
                        else {
                            self.peer_manager.update_peer_set();
                            info!("No idle peers available for block roots sync.");
                            sleep(SLEEP_DURATION).await;
                            break;
                        };

                        let (assigned, remaining): (Vec<B256>, Vec<B256>) =
                            block_roots.into_iter().partition(|root| {
                                !block_cache
                                    .attempted_peers_for(RequestKey::BlockRoot(*root))
                                    .contains(&peer.peer_id)
                            });
                        block_roots = remaining;
                        if assigned.is_empty() {
                            self.peer_manager.mark_peer_as_idle(&peer.peer_id);
                            exhausted_this_tick.insert(peer.peer_id);
                            continue;
                        }
                        let chunk: Vec<B256> =
                            assigned.into_iter().take(MAX_CONCURRENT_REQUESTS).collect();

                        block_cache.extend_block_roots_in_progress(&chunk);

                        task_handles.push(DownloadTask::new_block_roots(
                            PeerRootsDownloader::start(
                                peer.peer_id,
                                self.p2p_sender.clone(),
                                self.executor.clone(),
                                chunk.clone(),
                            ),
                            chunk,
                            peer.peer_id,
                        ));
                    }
                }
                DataToFetch::MissingBlobIdentifiers(mut blob_identifiers) => {
                    let mut exhausted_this_tick = HashSet::new();
                    while !blob_identifiers.is_empty() {
                        let Some(peer) = self
                            .peer_manager
                            .fetch_idle_peer_from_excluding(&candidate_peers, &exhausted_this_tick)
                        else {
                            self.peer_manager.update_peer_set();
                            info!(
                                "No idle peers available for blob sync. {}",
                                self.peer_manager.peer_counts()
                            );
                            sleep(SLEEP_DURATION).await;
                            break;
                        };

                        let (assigned, remaining): (Vec<BlobIdentifier>, Vec<BlobIdentifier>) =
                            blob_identifiers.into_iter().partition(|identifier| {
                                !block_cache
                                    .attempted_peers_for(RequestKey::Blob(*identifier))
                                    .contains(&peer.peer_id)
                            });
                        blob_identifiers = remaining;
                        if assigned.is_empty() {
                            self.peer_manager.mark_peer_as_idle(&peer.peer_id);
                            exhausted_this_tick.insert(peer.peer_id);
                            continue;
                        }
                        let chunk: Vec<BlobIdentifier> =
                            assigned.into_iter().take(MAX_BLOBS_PER_REQUEST).collect();

                        block_cache.extend_blob_identifiers_in_progress(&chunk);

                        task_handles.push(DownloadTask::new_blob_identifiers(
                            PeerBlobIdentifierDownloader::start(
                                peer.peer_id,
                                self.p2p_sender.clone(),
                                self.executor.clone(),
                                chunk.clone(),
                            ),
                            chunk,
                            peer.peer_id,
                        ));
                    }
                }
                DataToFetch::MissingDataColumnIdentifiers(mut identifiers) => {
                    let mut exhausted_this_tick = HashSet::new();
                    while !identifiers.is_empty() {
                        let Some(peer) = self
                            .peer_manager
                            .fetch_idle_peer_from_excluding(&candidate_peers, &exhausted_this_tick)
                        else {
                            self.peer_manager.update_peer_set();
                            info!("No idle peers available for data column sync.");
                            sleep(SLEEP_DURATION).await;
                            break;
                        };

                        let (assigned, remaining): (Vec<ColumnIdentifier>, Vec<ColumnIdentifier>) =
                            identifiers.into_iter().partition(|identifier| {
                                !block_cache
                                    .attempted_peers_for(RequestKey::Column(*identifier))
                                    .contains(&peer.peer_id)
                            });
                        identifiers = remaining;
                        if assigned.is_empty() {
                            self.peer_manager.mark_peer_as_idle(&peer.peer_id);
                            exhausted_this_tick.insert(peer.peer_id);
                            continue;
                        }
                        let chunk: Vec<ColumnIdentifier> =
                            assigned.into_iter().take(MAX_CONCURRENT_REQUESTS).collect();

                        block_cache.extend_data_column_identifiers_in_progress(&chunk);

                        task_handles.push(DownloadTask::new_data_column_identifiers(
                            PeerDataColumnIdentifierDownloader::start(
                                peer.peer_id,
                                self.p2p_sender.clone(),
                                self.executor.clone(),
                                group_by_block_root(&chunk),
                            ),
                            chunk,
                            peer.peer_id,
                        ));
                    }
                }
                DataToFetch::DownloadsInProgress => {
                    info!(
                        "Waiting for ongoing downloads to complete... {}",
                        self.peer_manager.peer_counts()
                    );
                    sleep(Duration::from_secs(10)).await;
                }
                DataToFetch::Finished => {
                    if phase == SyncPhase::Finalized && block_cache.next_start_slot() >= target.slot
                    {
                        finalized_target_was_ahead = target.slot > head_slot;
                        phase = SyncPhase::Head;
                        active_target = None;
                        finalized_phase_settled = true;
                        continue;
                    }
                    break;
                }
            }
        }

        info!(
            "Block range sync completed a segment successfully with {} blocks and {} blobs.",
            block_cache.block_count(),
            block_cache.downloaded_blob_count(),
        );

        let fulu_fork_epoch = beacon_network_spec().fulu_fork_epoch;
        let mut imported_count: u64 = 0;

        // execute all the blocks downloaded
        for BlockAndBlobBundle {
            block,
            blobs,
            columns,
        } in block_cache.get_blocks_and_blobs()?
        {
            info!("Processing block with slot {}", block.message.slot,);

            let (block, columns) = if block.message.body.blob_kzg_commitments.is_empty() {
                ensure!(
                    blobs.is_empty(),
                    "Range-sync block without blob commitments had downloaded blob sidecars"
                );
                ensure!(
                    columns.is_empty(),
                    "Range-sync block without blob commitments had downloaded data columns"
                );
                (block, Vec::new())
            } else if compute_epoch_at_slot(block.message.slot) >= fulu_fork_epoch {
                let required_columns = self
                    .beacon_chain
                    .store
                    .lock()
                    .await
                    .data_availability_checker
                    .required_columns()
                    .clone();
                let columns = columns
                    .into_values()
                    .filter(|column| required_columns.contains(&column.index))
                    .collect::<Vec<_>>();
                (block, columns)
            } else {
                let (blobs_provider, required_columns, verify_data_availability) = {
                    let store = self.beacon_chain.store.lock().await;
                    let network_spec = beacon_network_spec();
                    (
                        store.db.blobs_and_proofs_provider(),
                        store.data_availability_checker.required_columns().clone(),
                        is_data_availability_check_required(
                            compute_epoch_at_slot(block.message.slot),
                            store.get_current_store_epoch()?,
                            network_spec.fulu_fork_epoch,
                            network_spec.min_epochs_for_data_column_sidecars_requests,
                        ),
                    )
                };
                tokio::task::spawn_blocking(move || {
                    let columns = build_data_columns_from_blob_sidecars(
                        &block,
                        &blobs,
                        verify_data_availability,
                    )?
                    .into_iter()
                    .filter(|column| required_columns.contains(&column.index))
                    .collect::<Vec<_>>();
                    for (identifier, sidecar) in blobs {
                        blobs_provider.insert(identifier, sidecar.into())?;
                    }
                    Ok::<_, anyhow::Error>((block, columns))
                })
                .await
                .map_err(|err| anyhow!("Range-sync data-column task failed: {err}"))??
            };

            match self.beacon_chain.process_block(block).await? {
                BlockProcessingOutcome::Imported { .. } => {}
                BlockProcessingOutcome::PendingAvailability { block_root } => {
                    for column in columns {
                        self.beacon_chain
                            .import_data_column_sidecar_if(column, |_| Ok(()))
                            .await?;
                    }
                    ensure!(
                        self.beacon_chain
                            .store
                            .lock()
                            .await
                            .db
                            .block_provider()
                            .get(block_root)?
                            .is_some(),
                        "Range-sync block {block_root} remained pending after processing its downloaded data"
                    );
                }
            }
            imported_count += 1;
        }

        info!("All blocks processed successfully.");

        let target_was_ahead = finalized_target_was_ahead
            || active_target
                .as_ref()
                .is_some_and(|target| target.slot > head_slot);
        if target_was_ahead
            && (saw_empty_range || ended_due_to_candidate_exhaustion)
            && imported_count == 0
        {
            self.next_segment_not_before = Some(Instant::now() + ZERO_PROGRESS_BACKOFF);
        }

        Ok(())
    }
}

fn group_by_block_root(identifiers: &[ColumnIdentifier]) -> Vec<DataColumnsByRootIdentifier> {
    let mut by_root: std::collections::HashMap<B256, Vec<u64>> = std::collections::HashMap::new();
    for identifier in identifiers {
        by_root
            .entry(identifier.block_root)
            .or_default()
            .push(identifier.index);
    }
    by_root
        .into_iter()
        .filter_map(
            |(block_root, columns)| match DataColumnsByRootIdentifier::new(block_root, columns) {
                Ok(identifier) => Some(identifier),
                Err(err) => {
                    warn!("Failed to build data column identifier for {block_root}: {err}");
                    None
                }
            },
        )
        .collect()
}

pub enum DownloadTask {
    BlockRange {
        handle: JoinHandle<anyhow::Result<StreamOutcome<SignedBeaconBlock>>>,
        range: Range,
        peer_id: PeerId,
    },
    DataColumnRange {
        handle: JoinHandle<anyhow::Result<StreamOutcome<DataColumnSidecar>>>,
        range: Range,
        peer_id: PeerId,
        expected_known_identifiers: Vec<ColumnIdentifier>,
    },
    BlockRoots {
        handle: JoinHandle<anyhow::Result<StreamOutcome<SignedBeaconBlock>>>,
        roots: Vec<B256>,
        peer_id: PeerId,
    },
    BlobIdentifiers {
        handle: JoinHandle<anyhow::Result<StreamOutcome<BlobSidecar>>>,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: PeerId,
    },
    DataColumnIdentifiers {
        handle: JoinHandle<anyhow::Result<StreamOutcome<DataColumnSidecar>>>,
        identifiers: Vec<ColumnIdentifier>,
        peer_id: PeerId,
    },
}

impl DownloadTask {
    pub fn new_block_range(
        handle: JoinHandle<anyhow::Result<StreamOutcome<SignedBeaconBlock>>>,
        range: Range,
        peer_id: PeerId,
    ) -> Self {
        DownloadTask::BlockRange {
            handle,
            range,
            peer_id,
        }
    }

    pub fn new_data_column_range(
        handle: JoinHandle<anyhow::Result<StreamOutcome<DataColumnSidecar>>>,
        range: Range,
        peer_id: PeerId,
        expected_known_identifiers: Vec<ColumnIdentifier>,
    ) -> Self {
        DownloadTask::DataColumnRange {
            handle,
            range,
            peer_id,
            expected_known_identifiers,
        }
    }

    pub fn new_block_roots(
        handle: JoinHandle<anyhow::Result<StreamOutcome<SignedBeaconBlock>>>,
        roots: Vec<B256>,
        peer_id: PeerId,
    ) -> Self {
        DownloadTask::BlockRoots {
            handle,
            roots,
            peer_id,
        }
    }

    pub fn new_blob_identifiers(
        handle: JoinHandle<anyhow::Result<StreamOutcome<BlobSidecar>>>,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: PeerId,
    ) -> Self {
        DownloadTask::BlobIdentifiers {
            handle,
            blob_identifiers,
            peer_id,
        }
    }

    pub fn new_data_column_identifiers(
        handle: JoinHandle<anyhow::Result<StreamOutcome<DataColumnSidecar>>>,
        identifiers: Vec<ColumnIdentifier>,
        peer_id: PeerId,
    ) -> Self {
        DownloadTask::DataColumnIdentifiers {
            handle,
            identifiers,
            peer_id,
        }
    }
}

fn handle_stream_outcome<T>(
    peer_manager: &mut PeerManager,
    peer_id: &PeerId,
    result: Result<anyhow::Result<StreamOutcome<T>>, tokio::task::JoinError>,
) -> Option<Vec<T>> {
    let outcome = match result {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(err)) => {
            warn!("Forward fill task failed: {err}");
            return None;
        }
        Err(err) => {
            warn!("Forward fill task panicked: {err}");
            return None;
        }
    };

    match outcome {
        StreamOutcome::Complete(items) => Some(items),
        StreamOutcome::Failed(DownloadFailure::Transport(detail)) => {
            info!("Transport failure from peer {peer_id}, will retry with someone else: {detail}");
            None
        }
        StreamOutcome::Failed(DownloadFailure::InvalidData(detail)) => {
            warn!("Invalid data from peer {peer_id}: {detail}");
            peer_manager.ban_peer(peer_id, BanReason::ProtocolError(detail));
            None
        }
        StreamOutcome::Failed(DownloadFailure::RemoteError { code, message }) => {
            if code == ResponseCode::InvalidRequest {
                warn!("Peer {peer_id} reported InvalidRequest (possible local bug): {message}");
            } else {
                info!("Peer {peer_id} declined the request ({code:?}): {message}");
            }
            None
        }
    }
}

fn poll_ready_tasks(
    tasks: &mut Vec<DownloadTask>,
    block_cache: &mut BlockCache,
    peer_manager: &mut PeerManager,
    required_columns: &HashSet<u64>,
    saw_empty_range: &mut bool,
    candidate_peers: &[PeerId],
    now: Instant,
) -> anyhow::Result<()> {
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut indexes_to_remove = vec![];
    let fulu_fork_epoch = beacon_network_spec().fulu_fork_epoch;

    for index in (0..tasks.len()).rev() {
        let Some(task) = tasks.get_mut(index) else {
            bail!("Task handle not found at index {index}");
        };

        match task {
            DownloadTask::BlockRange {
                handle,
                range,
                peer_id,
            } => {
                let pinned = Pin::new(handle);

                match pinned.poll(&mut context) {
                    Poll::Ready(result) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_block_range_in_progress(range);
                        peer_manager.mark_peer_as_idle(peer_id);
                        let key = RequestKey::BlockRange(*range);

                        let Some(blocks) = handle_stream_outcome(peer_manager, peer_id, result)
                        else {
                            block_cache.mark_attempted(key, *peer_id, candidate_peers, now);
                            block_cache.push_retry_range(*range);
                            continue;
                        };

                        if blocks.is_empty() {
                            info!("Received empty block range from peer: {peer_id}");
                            block_cache.clear_attempted(key);
                            *saw_empty_range = true;
                            continue;
                        }

                        let range_end = range.start_slot + range.count;
                        let out_of_range = blocks.iter().any(|block| {
                            block.message.slot < range.start_slot || block.message.slot >= range_end
                        });
                        if out_of_range {
                            warn!(
                                "Peer {peer_id} returned block(s) outside the requested range {range:?}"
                            );
                            block_cache.mark_attempted(key, *peer_id, candidate_peers, now);
                            block_cache.push_retry_range(*range);
                            peer_manager.ban_peer(
                                peer_id,
                                BanReason::ProtocolError(
                                    "block(s) outside the requested range".to_string(),
                                ),
                            );
                            continue;
                        }

                        let needs_columns = !required_columns.is_empty()
                            && blocks.iter().any(|block| {
                                !block.message.body.blob_kzg_commitments.is_empty()
                                    && compute_epoch_at_slot(block.message.slot) >= fulu_fork_epoch
                            });

                        if let Err(err) = block_cache.add_blocks(blocks, true) {
                            warn!("Failed to add downloaded blocks to cache: {err:?}");
                            block_cache.mark_attempted(key, *peer_id, candidate_peers, now);
                            block_cache.push_retry_range(*range);
                            peer_manager.ban_peer(
                                peer_id,
                                BanReason::ProtocolError(format!("invalid block range: {err:?}")),
                            );
                        } else {
                            block_cache.clear_attempted(key);
                            if needs_columns {
                                block_cache.push_column_range(*range);
                            }
                        }
                    }
                    Poll::Pending => {}
                }
            }
            DownloadTask::DataColumnRange {
                handle,
                range,
                peer_id,
                expected_known_identifiers,
            } => {
                let pinned = Pin::new(handle);

                match pinned.poll(&mut context) {
                    Poll::Ready(result) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_column_range_in_progress(range);
                        peer_manager.mark_peer_as_idle(peer_id);
                        let key = RequestKey::ColumnRange(*range);

                        let Some(columns) = handle_stream_outcome(peer_manager, peer_id, result)
                        else {
                            block_cache.mark_attempted(key, *peer_id, candidate_peers, now);
                            for identifier in expected_known_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            continue;
                        };

                        if columns.is_empty() {
                            info!("Received empty data column range from peer: {peer_id}");
                            block_cache.clear_attempted(key);
                            for identifier in expected_known_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            *saw_empty_range = true;
                            continue;
                        }

                        let range_end = range.start_slot + range.count;
                        let mut seen_identifiers = HashSet::new();
                        let out_of_shape = columns.iter().any(|column| {
                            let slot = column.signed_block_header.message.slot;
                            let identifier = ColumnIdentifier::new(
                                column.signed_block_header.message.tree_hash_root(),
                                column.index,
                            );
                            slot < range.start_slot
                                || slot >= range_end
                                || !required_columns.contains(&column.index)
                                || !seen_identifiers.insert(identifier)
                        });
                        if out_of_shape {
                            warn!(
                                "Peer {peer_id} returned data column(s) outside the requested range/columns, or a duplicate, for range {range:?}"
                            );
                            block_cache.clear_attempted(key);
                            for identifier in expected_known_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            peer_manager.ban_peer(
                                peer_id,
                                BanReason::ProtocolError(
                                    "data column(s) outside the requested range/columns, or a duplicate"
                                        .to_string(),
                                ),
                            );
                            continue;
                        }

                        let returned: HashSet<ColumnIdentifier> = columns
                            .iter()
                            .map(|column| {
                                ColumnIdentifier::new(
                                    column.signed_block_header.message.tree_hash_root(),
                                    column.index,
                                )
                            })
                            .collect();

                        if let Err(err) = block_cache.add_data_columns(columns, required_columns) {
                            warn!("Failed to add downloaded data columns to cache: {err:?}");
                            block_cache.clear_attempted(key);
                            for identifier in expected_known_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            peer_manager
                                .ban_peer(peer_id, BanReason::InvalidProof(format!("{err:?}")));
                        } else {
                            block_cache.clear_attempted(key);
                            for identifier in expected_known_identifiers.iter() {
                                if returned.contains(identifier) {
                                    block_cache.clear_attempted(RequestKey::Column(*identifier));
                                } else {
                                    block_cache.mark_attempted(
                                        RequestKey::Column(*identifier),
                                        *peer_id,
                                        candidate_peers,
                                        now,
                                    );
                                }
                            }
                        }
                    }
                    Poll::Pending => {}
                }
            }
            DownloadTask::BlockRoots {
                handle,
                roots,
                peer_id,
            } => {
                let pinned = Pin::new(handle);

                match pinned.poll(&mut context) {
                    Poll::Ready(result) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_block_roots_in_progress(roots);
                        peer_manager.mark_peer_as_idle(peer_id);

                        let Some(blocks) = handle_stream_outcome(peer_manager, peer_id, result)
                        else {
                            for root in roots.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::BlockRoot(*root),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            continue;
                        };

                        let requested: HashSet<B256> = roots.iter().copied().collect();
                        let has_unexpected = blocks
                            .iter()
                            .any(|block| !requested.contains(&block.message.tree_hash_root()));
                        if has_unexpected {
                            warn!(
                                "Peer {peer_id} returned block(s) with an unrequested root for a BlockRoots request"
                            );
                            for root in roots.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::BlockRoot(*root),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            peer_manager.ban_peer(
                                peer_id,
                                BanReason::ProtocolError(
                                    "returned block(s) with an unrequested root".to_string(),
                                ),
                            );
                            continue;
                        }

                        let returned: HashSet<B256> = blocks
                            .iter()
                            .map(|block| block.message.tree_hash_root())
                            .collect();
                        for root in roots.iter() {
                            if returned.contains(root) {
                                block_cache.clear_attempted(RequestKey::BlockRoot(*root));
                            } else {
                                block_cache.mark_attempted(
                                    RequestKey::BlockRoot(*root),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                        }

                        if blocks.is_empty() {
                            warn!("Received empty block roots from peer: {peer_id}");
                            continue;
                        }

                        if let Err(err) = block_cache.add_blocks(blocks, false) {
                            warn!("Failed to add downloaded blocks to cache: {err:?}");
                        }
                    }
                    Poll::Pending => {}
                }
            }
            DownloadTask::BlobIdentifiers {
                handle,
                blob_identifiers,
                peer_id,
            } => {
                let pinned = Pin::new(handle);

                match pinned.poll(&mut context) {
                    Poll::Ready(result) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_blob_identifiers_in_progress(blob_identifiers);
                        peer_manager.mark_peer_as_idle(peer_id);

                        let Some(blob_sidecars) =
                            handle_stream_outcome(peer_manager, peer_id, result)
                        else {
                            for identifier in blob_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Blob(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            continue;
                        };

                        if blob_sidecars.is_empty() {
                            warn!("Received empty blob identifiers from peer: {peer_id}");
                            for identifier in blob_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Blob(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            continue;
                        }

                        let requested: HashSet<BlobIdentifier> =
                            blob_identifiers.iter().copied().collect();
                        let has_unexpected = blob_sidecars.iter().any(|sidecar| {
                            !requested.contains(&BlobIdentifier {
                                block_root: sidecar.signed_block_header.message.tree_hash_root(),
                                index: sidecar.index,
                            })
                        });
                        if has_unexpected {
                            warn!("Peer {peer_id} returned unrequested blob sidecar(s)");
                            for identifier in blob_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Blob(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            peer_manager.ban_peer(
                                peer_id,
                                BanReason::ProtocolError(
                                    "returned unrequested blob sidecar(s)".to_string(),
                                ),
                            );
                            continue;
                        }

                        let returned: HashSet<BlobIdentifier> = blob_sidecars
                            .iter()
                            .map(|sidecar| BlobIdentifier {
                                block_root: sidecar.signed_block_header.message.tree_hash_root(),
                                index: sidecar.index,
                            })
                            .collect();

                        if let Err(err) = block_cache.add_blobs(blob_sidecars) {
                            warn!("Failed to add downloaded blobs to cache: {err:?}");
                            for identifier in blob_identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Blob(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            peer_manager
                                .ban_peer(peer_id, BanReason::InvalidProof(format!("{err:?}")));
                        } else {
                            for identifier in blob_identifiers.iter() {
                                if returned.contains(identifier) {
                                    block_cache.clear_attempted(RequestKey::Blob(*identifier));
                                } else {
                                    block_cache.mark_attempted(
                                        RequestKey::Blob(*identifier),
                                        *peer_id,
                                        candidate_peers,
                                        now,
                                    );
                                }
                            }
                        }
                    }
                    Poll::Pending => {}
                }
            }
            DownloadTask::DataColumnIdentifiers {
                handle,
                identifiers,
                peer_id,
            } => {
                let pinned = Pin::new(handle);

                match pinned.poll(&mut context) {
                    Poll::Ready(result) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_data_column_identifiers_in_progress(identifiers);
                        peer_manager.mark_peer_as_idle(peer_id);

                        let Some(columns) = handle_stream_outcome(peer_manager, peer_id, result)
                        else {
                            for identifier in identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            continue;
                        };

                        if columns.is_empty() {
                            warn!("Received empty data column identifiers from peer: {peer_id}");
                            for identifier in identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            continue;
                        }

                        let requested: HashSet<ColumnIdentifier> =
                            identifiers.iter().copied().collect();
                        let has_unexpected = columns.iter().any(|column| {
                            !requested.contains(&ColumnIdentifier::new(
                                column.signed_block_header.message.tree_hash_root(),
                                column.index,
                            ))
                        });
                        if has_unexpected {
                            warn!("Peer {peer_id} returned unrequested data column(s)");
                            for identifier in identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            peer_manager.ban_peer(
                                peer_id,
                                BanReason::ProtocolError(
                                    "returned unrequested data column(s)".to_string(),
                                ),
                            );
                            continue;
                        }

                        let returned: HashSet<ColumnIdentifier> = columns
                            .iter()
                            .map(|column| {
                                ColumnIdentifier::new(
                                    column.signed_block_header.message.tree_hash_root(),
                                    column.index,
                                )
                            })
                            .collect();

                        if let Err(err) = block_cache.add_data_columns(columns, required_columns) {
                            warn!("Failed to add downloaded data columns to cache: {err:?}");
                            for identifier in identifiers.iter() {
                                block_cache.mark_attempted(
                                    RequestKey::Column(*identifier),
                                    *peer_id,
                                    candidate_peers,
                                    now,
                                );
                            }
                            peer_manager
                                .ban_peer(peer_id, BanReason::InvalidProof(format!("{err:?}")));
                        } else {
                            for identifier in identifiers.iter() {
                                if returned.contains(identifier) {
                                    block_cache.clear_attempted(RequestKey::Column(*identifier));
                                } else {
                                    block_cache.mark_attempted(
                                        RequestKey::Column(*identifier),
                                        *peer_id,
                                        candidate_peers,
                                        now,
                                    );
                                }
                            }
                        }
                    }
                    Poll::Pending => {}
                }
            }
        }
    }

    for index in indexes_to_remove {
        tasks.remove(index);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, path::PathBuf};

    use discv5::{Enr, enr::CombinedKey};
    use kzg::{G1, eip_4844::compute_blob_kzg_proof_raw};
    use parking_lot::RwLock;
    use ream_consensus_beacon::{
        data_column_sidecar::NUMBER_OF_COLUMNS, electra::beacon_block::BeaconBlock,
    };
    use ream_consensus_misc::{
        checkpoint::Checkpoint,
        polynomial_commitments::{kzg_commitment::KZGCommitment, kzg_proof::KZGProof},
    };
    use ream_execution_rpc_types::get_blobs::{Blob, BlobAndProofV1};
    use ream_network_spec::networks::beacon::initialize_test_network_spec;
    use ream_operation_pool::OperationPool;
    use ream_p2p::network::beacon::peer::CachedPeer;
    use ream_peer::{ConnectionState, Direction};
    use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};
    use ream_storage::{db::ReamDB, tables::field::REDBField};
    use ream_sync_committee_pool::SyncCommitteePool;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn range_blob_sidecars_build_valid_columns_and_reject_bad_proofs() {
        let blob = Blob::default();
        let blob_bytes = blob.to_fixed_bytes();
        let raw_commitment = das_context()
            .blob_to_kzg_commitment(&blob_bytes)
            .expect("test blob should produce a commitment");
        let commitment = KZGCommitment(raw_commitment);
        let proof = KZGProof::from(
            compute_blob_kzg_proof_raw(
                blob_bytes,
                raw_commitment,
                ream_polynomial_commitments::trusted_setup::blst_settings(),
            )
            .expect("test blob should produce a proof")
            .to_bytes(),
        );
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        block
            .message
            .body
            .blob_kzg_commitments
            .push(commitment)
            .expect("one commitment should fit");
        let block_root = block.message.tree_hash_root();
        let identifier = BlobIdentifier::new(block_root, 0);
        let sidecar = block
            .blob_sidecar(BlobAndProofV1 { blob, proof }, 0)
            .expect("test sidecar should be constructed");
        let mut sidecars = HashMap::from([(identifier, sidecar)]);

        assert!(
            build_data_columns_from_blob_sidecars(&block, &HashMap::new(), false)
                .expect("expired blocks should not require blob sidecars")
                .is_empty()
        );
        assert!(
            build_data_columns_from_blob_sidecars(&block, &HashMap::new(), true)
                .expect("blocks awaiting column fetch should not error")
                .is_empty()
        );

        let columns = build_data_columns_from_blob_sidecars(&block, &sidecars, true)
            .expect("valid blobs should produce data columns");
        assert_eq!(columns.len() as u64, NUMBER_OF_COLUMNS);

        sidecars
            .get_mut(&identifier)
            .expect("test sidecar should exist")
            .kzg_proof[0] ^= 1;
        assert!(build_data_columns_from_blob_sidecars(&block, &sidecars, true).is_err());

        let wrong_identifier = BlobIdentifier::new(B256::repeat_byte(0xAB), 0);
        let mismatched = HashMap::from([(
            wrong_identifier,
            sidecars.remove(&identifier).expect("sidecar should exist"),
        )]);
        assert!(build_data_columns_from_blob_sidecars(&block, &mismatched, true).is_err());
    }

    /// Kept alongside the chain so the dir isn't dropped (and cleaned up) until the test ends.
    fn test_beacon_chain() -> (TempDir, BeaconChain) {
        let data_dir = tempfile::tempdir().expect("tempdir should be created");
        let beacon_db = ReamDB::new(data_dir.path().to_path_buf())
            .expect("ReamDB should init")
            .init_beacon_db()
            .expect("beacon DB tables should init");
        let beacon_chain = BeaconChain::new(
            beacon_db,
            Arc::new(OperationPool::default()),
            Arc::new(SyncCommitteePool::default()),
            None,
            None,
        );
        (data_dir, beacon_chain)
    }

    fn test_network_state() -> Arc<NetworkState> {
        let enr_key = CombinedKey::generate_secp256k1();
        Arc::new(NetworkState {
            local_enr: RwLock::new(Enr::builder().build(&enr_key).expect("valid enr")),
            peer_table: RwLock::new(HashMap::new()),
            meta_data: RwLock::new(GetMetaDataV3::default()),
            status: RwLock::new(Status::default()),
            data_dir: PathBuf::new(),
        })
    }

    fn test_peer_manager_with_one_peer() -> (PeerManager, PeerId) {
        let network_state = test_network_state();
        let peer_id = PeerId::random();
        let mut peer = CachedPeer::new(
            peer_id,
            None,
            ConnectionState::Connected,
            Direction::Outbound,
            None,
        );
        peer.status = Some(Status::default());
        network_state.peer_table.write().insert(peer_id, peer);

        let mut peer_manager = PeerManager::new(network_state);
        peer_manager.update_peer_set();
        (peer_manager, peer_id)
    }

    fn poll_until_done(
        tasks: &mut Vec<DownloadTask>,
        block_cache: &mut BlockCache,
        peer_manager: &mut PeerManager,
        required_columns: &HashSet<u64>,
        saw_empty_range: &mut bool,
        candidate_peers: &[PeerId],
    ) {
        for _ in 0..500 {
            poll_ready_tasks(
                tasks,
                block_cache,
                peer_manager,
                required_columns,
                saw_empty_range,
                candidate_peers,
                Instant::now(),
            )
            .expect("poll_ready_tasks should not error");
            if tasks.is_empty() {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        panic!("task did not complete within the test timeout");
    }

    /// `start()` must hand `self` back out even on an ordinary segment error, not just success,
    /// or the caller loses the syncer (and its warmed-up peer table) and can never retry.
    #[test]
    fn start_returns_self_after_a_failed_segment() {
        initialize_test_network_spec();
        // Empty DB has no highest synced slot, so run_segment fails immediately.
        let (_data_dir, beacon_chain) = test_beacon_chain();
        let executor = ReamExecutor::new().expect("executor should start");
        let (p2p_sender, _p2p_receiver) = tokio::sync::mpsc::unbounded_channel();

        let syncer = BlockRangeSyncer::new(
            Arc::new(beacon_chain),
            p2p_sender,
            test_network_state(),
            executor,
        );

        // ReamExecutor owns its own runtime; #[tokio::test] would make dropping it panic.
        let (_syncer, sync_result) = futures::executor::block_on(syncer.start())
            .expect("task should not panic")
            .expect("task should not be cancelled by shutdown");

        assert!(
            sync_result.is_err(),
            "expected the empty-DB segment to fail"
        );
    }

    /// A lone/early peer must not be enough to call the node synced. The wall clock has to
    /// agree too, or one thin sample could "vote" the node caught up while it's still far behind.
    #[test]
    fn is_synced_to_head_slot_requires_wall_clock_agreement() {
        // ReamExecutor owns its own runtime; #[tokio::test] would make dropping it panic.
        futures::executor::block_on(is_synced_to_head_slot_requires_wall_clock_agreement_inner());
    }

    async fn is_synced_to_head_slot_requires_wall_clock_agreement_inner() {
        initialize_test_network_spec();
        let (_data_dir, beacon_chain) = test_beacon_chain();
        let seconds_per_slot = beacon_network_spec().seconds_per_slot();
        let highest_slot = 100u64;
        let highest_root = B256::repeat_byte(0x42);

        {
            let store = beacon_chain.store.lock().await;
            store
                .db
                .genesis_time_provider()
                .insert(0)
                .expect("insert genesis time");
            store
                .db
                .slot_index_provider()
                .insert(highest_slot, highest_root)
                .expect("insert highest synced slot");
            store
                .db
                .finalized_checkpoint_provider()
                .insert(Checkpoint {
                    epoch: 0,
                    root: B256::ZERO,
                })
                .expect("insert finalized checkpoint");
        }

        let network_state = test_network_state();
        for _ in 0..MIN_SYNC_PEERS {
            let peer_id = PeerId::random();
            let mut peer = CachedPeer::new(
                peer_id,
                None,
                ConnectionState::Connected,
                Direction::Outbound,
                None,
            );
            peer.status = Some(Status {
                head_slot: highest_slot,
                head_root: highest_root,
                ..Default::default()
            });
            network_state.peer_table.write().insert(peer_id, peer);
        }

        let (p2p_sender, _p2p_receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut syncer = BlockRangeSyncer::new(
            Arc::new(beacon_chain),
            p2p_sender,
            network_state,
            ReamExecutor::new().expect("executor should start"),
        );
        syncer.peer_manager.update_peer_set();

        // Clock agrees with the peer: genuinely caught up.
        syncer
            .beacon_chain
            .store
            .lock()
            .await
            .db
            .time_provider()
            .insert(highest_slot * seconds_per_slot)
            .expect("insert time");
        assert!(syncer.is_synced_to_head_slot().await);

        // Clock disagrees: must not report synced, even though the peer still does.
        syncer
            .beacon_chain
            .store
            .lock()
            .await
            .db
            .time_provider()
            .insert((highest_slot + 10_000) * seconds_per_slot)
            .expect("insert time");
        assert!(!syncer.is_synced_to_head_slot().await);
    }

    #[test]
    fn poll_ready_tasks_partial_block_roots_marks_only_the_omitted_root_attempted() {
        initialize_test_network_spec();
        let executor = ReamExecutor::new().expect("executor should start");
        let (mut peer_manager, peer_id) = test_peer_manager_with_one_peer();

        let delivered_block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: 1,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let delivered_root = delivered_block.message.tree_hash_root();
        let omitted_root = B256::repeat_byte(9);

        let mut block_cache = BlockCache::new(B256::ZERO, 0);
        let handle = executor.spawn(async move { StreamOutcome::Complete(vec![delivered_block]) });
        let mut tasks = vec![DownloadTask::new_block_roots(
            handle,
            vec![delivered_root, omitted_root],
            peer_id,
        )];

        poll_until_done(
            &mut tasks,
            &mut block_cache,
            &mut peer_manager,
            &HashSet::new(),
            &mut false,
            &[peer_id],
        );

        assert!(
            block_cache
                .attempted_peers_for(RequestKey::BlockRoot(delivered_root))
                .is_empty(),
            "a delivered root must not be marked as a failed attempt"
        );
        assert!(
            block_cache
                .attempted_peers_for(RequestKey::BlockRoot(omitted_root))
                .contains(&peer_id),
            "the omitted root must be attributed to this peer, so a retry excludes it"
        );
    }

    #[test]
    fn poll_ready_tasks_unrequested_block_root_bans_peer_and_discards_whole_batch() {
        initialize_test_network_spec();
        let executor = ReamExecutor::new().expect("executor should start");
        let (mut peer_manager, peer_id) = test_peer_manager_with_one_peer();

        let requested_block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: 1,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let requested_root = requested_block.message.tree_hash_root();
        let unrequested_block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: 2,
                ..Default::default()
            },
            signature: Default::default(),
        };

        let mut block_cache = BlockCache::new(B256::ZERO, 0);
        let handle = executor.spawn(async move {
            StreamOutcome::Complete(vec![requested_block, unrequested_block])
        });
        let mut tasks = vec![DownloadTask::new_block_roots(
            handle,
            vec![requested_root],
            peer_id,
        )];

        poll_until_done(
            &mut tasks,
            &mut block_cache,
            &mut peer_manager,
            &HashSet::new(),
            &mut false,
            &[peer_id],
        );

        assert_eq!(
            block_cache.block_count(),
            0,
            "a response with any unrequested item is atomically discarded -- even the \
             requested, otherwise-valid item in the same batch must not be committed"
        );
        assert!(
            block_cache
                .attempted_peers_for(RequestKey::BlockRoot(requested_root))
                .contains(&peer_id),
            "the requested root must still be attributed to this peer's failed attempt"
        );
        assert!(
            peer_manager.fetch_idle_peer_from(&[peer_id]).is_none(),
            "a peer that smuggled in an unrequested item must be banned, not just marked idle"
        );
    }

    #[test]
    fn poll_ready_tasks_empty_data_column_range_falls_through_to_by_root_and_excludes_peer() {
        initialize_test_network_spec();
        let executor = ReamExecutor::new().expect("executor should start");
        let (mut peer_manager, peer_id) = test_peer_manager_with_one_peer();

        let range = Range::new(1, 10);
        let identifier = ColumnIdentifier::new(B256::repeat_byte(3), 0);
        let mut block_cache = BlockCache::new(B256::ZERO, 0);
        let handle =
            executor.spawn(async move { StreamOutcome::Complete(Vec::<DataColumnSidecar>::new()) });
        let mut tasks = vec![DownloadTask::new_data_column_range(
            handle,
            range,
            peer_id,
            vec![identifier],
        )];

        let mut saw_empty_range = false;
        poll_until_done(
            &mut tasks,
            &mut block_cache,
            &mut peer_manager,
            &HashSet::new(),
            &mut saw_empty_range,
            &[peer_id],
        );

        assert!(saw_empty_range);
        assert!(
            block_cache
                .attempted_peers_for(RequestKey::Column(identifier))
                .contains(&peer_id),
            "the expected identifier must fall through to the by-root fallback, excluding this peer"
        );
        assert!(
            block_cache
                .attempted_peers_for(RequestKey::ColumnRange(range))
                .is_empty(),
            "an empty range response is accepted (settled), not held as a pending attempt"
        );
    }

    #[test]
    fn poll_ready_tasks_invalid_blob_proof_bans_peer_and_marks_it_attempted() {
        initialize_test_network_spec();
        let executor = ReamExecutor::new().expect("executor should start");
        let (mut peer_manager, peer_id) = test_peer_manager_with_one_peer();

        let blob = Blob::default();
        let blob_bytes = blob.to_fixed_bytes();
        let raw_commitment = das_context()
            .blob_to_kzg_commitment(&blob_bytes)
            .expect("test blob should produce a commitment");
        let commitment = KZGCommitment(raw_commitment);
        let proof = KZGProof::from(
            compute_blob_kzg_proof_raw(
                blob_bytes,
                raw_commitment,
                ream_polynomial_commitments::trusted_setup::blst_settings(),
            )
            .expect("test blob should produce a proof")
            .to_bytes(),
        );
        let mut block = SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        };
        block
            .message
            .body
            .blob_kzg_commitments
            .push(commitment)
            .expect("one commitment should fit");
        let block_root = block.message.tree_hash_root();
        let identifier = BlobIdentifier::new(block_root, 0);
        let mut sidecar = block
            .blob_sidecar(BlobAndProofV1 { blob, proof }, 0)
            .expect("test sidecar should be constructed");
        sidecar.kzg_proof[0] ^= 1;

        let mut block_cache = BlockCache::new(B256::ZERO, 0);
        block_cache
            .add_blocks(vec![block], false)
            .expect("block should enter cache");

        let handle = executor.spawn(async move { StreamOutcome::Complete(vec![sidecar]) });
        let mut tasks = vec![DownloadTask::new_blob_identifiers(
            handle,
            vec![identifier],
            peer_id,
        )];

        poll_until_done(
            &mut tasks,
            &mut block_cache,
            &mut peer_manager,
            &HashSet::new(),
            &mut false,
            &[peer_id],
        );

        assert!(
            block_cache
                .attempted_peers_for(RequestKey::Blob(identifier))
                .contains(&peer_id),
            "the dependency must be attributed to this peer so a retry picks someone else"
        );
        assert!(
            peer_manager.fetch_idle_peer_from(&[peer_id]).is_none(),
            "a peer that served an invalid blob proof must be banned, not just marked idle"
        );
    }
}

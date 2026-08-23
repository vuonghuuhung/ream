mod block_cache;
mod peer_manager;
mod peer_range_downloader;

use std::{
    collections::HashSet,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use alloy_primitives::B256;
use anyhow::{anyhow, bail, ensure};
use block_cache::{BlockAndBlobBundle, BlockCache, DataToFetch};
use futures::task::noop_waker;
use libp2p::PeerId;
use peer_manager::{BanReason, PeerManager};
use peer_range_downloader::{
    PeerBlobIdentifierDownloader, PeerDataColumnIdentifierDownloader,
    PeerDataColumnRangeDownloader, PeerRootsDownloader,
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
use ream_consensus_misc::misc::compute_epoch_at_slot;
use ream_executor::ReamExecutor;
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::network::beacon::{channel::P2PMessage, network_state::NetworkState};
use ream_polynomial_commitments::handlers::verify_blob_kzg_proof_batch;
use ream_req_resp::{
    MAX_CONCURRENT_REQUESTS, beacon::messages::data_column_sidecars::DataColumnsByRootIdentifier,
};
use ream_storage::tables::table::{CustomTable, REDBTable};
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

pub struct BlockRangeSyncer {
    pub beacon_chain: Arc<BeaconChain>,
    pub peer_manager: PeerManager,
    pub p2p_sender: UnboundedSender<P2PMessage>,
    pub executor: ReamExecutor,
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
        }
    }

    pub async fn is_synced_to_head_slot(&self) -> bool {
        let Some(sync_target) = self.peer_manager.sync_target() else {
            return false;
        };

        let store = self.beacon_chain.store.lock().await;
        let latest_synced_slot = store
            .db
            .slot_index_provider()
            .get_highest_slot()
            .unwrap_or_default()
            .unwrap_or(0);
        let Ok(current_slot) = store.get_current_slot() else {
            return false;
        };
        drop(store);

        let peers_report_caught_up = sync_target.slot <= latest_synced_slot;
        // The clock is ground truth peers can't fake.
        let clock_confirms_caught_up =
            current_slot.saturating_sub(latest_synced_slot) <= SLOT_IMPORT_TOLERANCE;

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
        let Some(latest_synced_root) = self
            .beacon_chain
            .store
            .lock()
            .await
            .db
            .slot_index_provider()
            .get_highest_root()
            .map_err(|err| anyhow!("Failed to get highest root: {err}"))?
        else {
            bail!("No synced root found in the database");
        };

        let Some(latest_synced_slot) = self
            .beacon_chain
            .store
            .lock()
            .await
            .db
            .slot_index_provider()
            .get_highest_slot()
            .map_err(|err| anyhow!("Failed to get highest slot: {err}"))?
        else {
            bail!("No synced slot found in the database");
        };

        // phase 1: download majority of blocks from ranges
        let mut block_cache = BlockCache::new(latest_synced_root, latest_synced_slot);
        let mut task_handles = vec![];
        loop {
            let required_columns = self
                .beacon_chain
                .store
                .lock()
                .await
                .data_availability_checker
                .required_columns()
                .clone();

            poll_ready_tasks(
                &mut task_handles,
                &mut block_cache,
                &mut self.peer_manager,
                &required_columns,
            )?;

            let Some(sync_target) = self.peer_manager.sync_target() else {
                warn!("No peers available to determine sync target, retrying...");
                sleep(SLEEP_DURATION).await;
                self.peer_manager.update_peer_set();
                continue;
            };

            let current_epoch = self
                .beacon_chain
                .store
                .lock()
                .await
                .get_current_store_epoch()?;
            let data_to_fetch =
                block_cache.data_to_fetch(sync_target.slot, current_epoch, &required_columns);
            info!(
                "Forward sync status: Downloaded Blocks {}, Downloaded Blobs {}/{}, Stage {data_to_fetch}",
                block_cache.block_count(),
                block_cache.downloaded_blob_count(),
                block_cache.blob_count(),
            );

            match data_to_fetch {
                DataToFetch::BlockRange(range) => {
                    let Some(peer) = self
                        .peer_manager
                        .fetch_idle_peer_preferring(Some(sync_target.root))
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
                    let Some(peer) = self
                        .peer_manager
                        .fetch_idle_peer_preferring(Some(sync_target.root))
                    else {
                        self.peer_manager.update_peer_set();
                        info!("No idle peers available for data column range sync.");
                        block_cache.push_column_range(range);
                        sleep(SLEEP_DURATION).await;
                        continue;
                    };

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
                    ));
                }
                DataToFetch::MissingBlockRoots(block_roots) => {
                    for block_roots_chunk in block_roots.chunks(MAX_CONCURRENT_REQUESTS) {
                        let Some(peer) = self
                            .peer_manager
                            .fetch_idle_peer_preferring(Some(sync_target.root))
                        else {
                            self.peer_manager.update_peer_set();
                            info!("No idle peers available for block roots sync.");
                            sleep(SLEEP_DURATION).await;
                            break;
                        };
                        block_cache.extend_block_roots_in_progress(block_roots_chunk);

                        task_handles.push(DownloadTask::new_block_roots(
                            PeerRootsDownloader::start(
                                peer.peer_id,
                                self.p2p_sender.clone(),
                                self.executor.clone(),
                                block_roots_chunk.to_vec(),
                            ),
                            block_roots_chunk.to_vec(),
                            peer.peer_id,
                        ));
                    }
                }
                DataToFetch::MissingBlobIdentifiers(blob_identifiers) => {
                    for blob_identifiers_chunk in blob_identifiers.chunks(MAX_BLOBS_PER_REQUEST) {
                        let Some(peer) = self
                            .peer_manager
                            .fetch_idle_peer_preferring(Some(sync_target.root))
                        else {
                            self.peer_manager.update_peer_set();
                            info!(
                                "No idle peers available for blob sync. {}",
                                self.peer_manager.peer_counts()
                            );
                            sleep(SLEEP_DURATION).await;
                            break;
                        };

                        block_cache.extend_blob_identifiers_in_progress(blob_identifiers_chunk);

                        task_handles.push(DownloadTask::new_blob_identifiers(
                            PeerBlobIdentifierDownloader::start(
                                peer.peer_id,
                                self.p2p_sender.clone(),
                                self.executor.clone(),
                                blob_identifiers_chunk.to_vec(),
                            ),
                            blob_identifiers_chunk.to_vec(),
                            peer.peer_id,
                        ));
                    }
                }
                DataToFetch::MissingDataColumnIdentifiers(identifiers) => {
                    for identifiers_chunk in identifiers.chunks(MAX_CONCURRENT_REQUESTS) {
                        let Some(peer) = self
                            .peer_manager
                            .fetch_idle_peer_preferring(Some(sync_target.root))
                        else {
                            self.peer_manager.update_peer_set();
                            info!("No idle peers available for data column sync.");
                            sleep(SLEEP_DURATION).await;
                            break;
                        };

                        block_cache.extend_data_column_identifiers_in_progress(identifiers_chunk);

                        task_handles.push(DownloadTask::new_data_column_identifiers(
                            PeerDataColumnIdentifierDownloader::start(
                                peer.peer_id,
                                self.p2p_sender.clone(),
                                self.executor.clone(),
                                group_by_block_root(identifiers_chunk),
                            ),
                            identifiers_chunk.to_vec(),
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
                DataToFetch::Finished => break,
            }
        }

        info!(
            "Block range sync completed a segment successfully with {} blocks and {} blobs.",
            block_cache.block_count(),
            block_cache.downloaded_blob_count(),
        );

        let fulu_fork_epoch = beacon_network_spec().fulu_fork_epoch;

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
        }

        info!("All blocks processed successfully.");

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
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<SignedBeaconBlock>>>>,
        range: Range,
        peer_id: PeerId,
    },
    DataColumnRange {
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<DataColumnSidecar>>>>,
        range: Range,
        peer_id: PeerId,
    },
    BlockRoots {
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<SignedBeaconBlock>>>>,
        roots: Vec<B256>,
        peer_id: PeerId,
    },
    BlobIdentifiers {
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<BlobSidecar>>>>,
        blob_identifiers: Vec<BlobIdentifier>,
        peer_id: PeerId,
    },
    DataColumnIdentifiers {
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<DataColumnSidecar>>>>,
        identifiers: Vec<ColumnIdentifier>,
        peer_id: PeerId,
    },
}

impl DownloadTask {
    pub fn new_block_range(
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<SignedBeaconBlock>>>>,
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
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<DataColumnSidecar>>>>,
        range: Range,
        peer_id: PeerId,
    ) -> Self {
        DownloadTask::DataColumnRange {
            handle,
            range,
            peer_id,
        }
    }

    pub fn new_block_roots(
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<SignedBeaconBlock>>>>,
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
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<BlobSidecar>>>>,
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
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<DataColumnSidecar>>>>,
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

fn poll_ready_tasks(
    tasks: &mut Vec<DownloadTask>,
    block_cache: &mut BlockCache,
    peer_manager: &mut PeerManager,
    required_columns: &HashSet<u64>,
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
                    Poll::Ready(Ok(blocks_result)) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_block_range_in_progress(range);
                        peer_manager.mark_peer_as_idle(peer_id);
                        let blocks = match blocks_result {
                            Ok(blocks) => blocks,
                            Err(err) => {
                                warn!("Failed to fetch blocks from peer: {err:?}");
                                block_cache.push_retry_range(*range);
                                continue;
                            }
                        };

                        let blocks = match blocks {
                            Ok(blocks) => blocks,
                            Err(err) => {
                                block_cache.push_retry_range(*range);
                                peer_manager.ban_peer(
                                    peer_id,
                                    BanReason::ProtocolError(format!("{err:?}")),
                                );
                                continue;
                            }
                        };

                        if blocks.is_empty() {
                            warn!("Received empty block range from peer: {peer_id}");
                            block_cache.push_retry_range(*range);
                            peer_manager.ban_peer(peer_id, BanReason::EmptyResponse);
                            continue;
                        }

                        let needs_columns = !required_columns.is_empty()
                            && blocks.iter().any(|block| {
                                !block.message.body.blob_kzg_commitments.is_empty()
                                    && compute_epoch_at_slot(block.message.slot) >= fulu_fork_epoch
                            });

                        if let Err(err) = block_cache.add_blocks(blocks, true) {
                            warn!("Failed to add downloaded blocks to cache: {err:?}");
                            block_cache.push_retry_range(*range);
                        } else if needs_columns {
                            block_cache.push_column_range(*range);
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
                        peer_manager.mark_peer_as_idle(peer_id);
                        block_cache.remove_block_range_in_progress(range);
                        block_cache.push_retry_range(*range);
                        indexes_to_remove.push(index);
                    }
                    Poll::Pending => {}
                }
            }
            DownloadTask::DataColumnRange {
                handle,
                range,
                peer_id,
            } => {
                let pinned = Pin::new(handle);

                match pinned.poll(&mut context) {
                    Poll::Ready(Ok(columns_result)) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_column_range_in_progress(range);
                        peer_manager.mark_peer_as_idle(peer_id);
                        let columns = match columns_result {
                            Ok(columns) => columns,
                            Err(err) => {
                                warn!("Failed to fetch data columns from peer: {err:?}");
                                block_cache.push_column_range(*range);
                                continue;
                            }
                        };

                        let columns = match columns {
                            Ok(columns) => columns,
                            Err(err) => {
                                block_cache.push_column_range(*range);
                                peer_manager.ban_peer(
                                    peer_id,
                                    BanReason::ProtocolError(format!("{err:?}")),
                                );
                                continue;
                            }
                        };

                        if columns.is_empty() {
                            warn!("Received empty data column range from peer: {peer_id}");
                            block_cache.push_column_range(*range);
                            peer_manager.ban_peer(peer_id, BanReason::EmptyResponse);
                            continue;
                        }

                        if let Err(err) = block_cache.add_data_columns(columns, required_columns) {
                            warn!("Failed to add downloaded data columns to cache: {err:?}");
                            block_cache.push_column_range(*range);
                            peer_manager
                                .ban_peer(peer_id, BanReason::InvalidProof(format!("{err:?}")));
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
                        peer_manager.mark_peer_as_idle(peer_id);
                        block_cache.remove_column_range_in_progress(range);
                        block_cache.push_column_range(*range);
                        indexes_to_remove.push(index);
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
                    Poll::Ready(Ok(blocks_result)) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_block_roots_in_progress(roots);
                        peer_manager.mark_peer_as_idle(peer_id);
                        let blocks = match blocks_result {
                            Ok(blocks) => blocks,
                            Err(err) => {
                                warn!("Failed to fetch blocks from peer: {err:?}");
                                continue;
                            }
                        };

                        let blocks = match blocks {
                            Ok(blocks) => blocks,
                            Err(err) => {
                                warn!("Failed to fetch blocks from roots: {err:?}");
                                peer_manager.ban_peer(
                                    peer_id,
                                    BanReason::ProtocolError(format!("{err:?}")),
                                );
                                continue;
                            }
                        };

                        if blocks.is_empty() {
                            warn!("Received empty block roots from peer: {peer_id}");
                            peer_manager.ban_peer(peer_id, BanReason::EmptyResponse);
                            continue;
                        }

                        if let Err(err) = block_cache.add_blocks(blocks, false) {
                            warn!("Failed to add downloaded blocks to cache: {err:?}");
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
                        peer_manager.mark_peer_as_idle(peer_id);
                        block_cache.remove_block_roots_in_progress(roots);
                        indexes_to_remove.push(index);
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
                    Poll::Ready(Ok(blob_sidecars_result)) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_blob_identifiers_in_progress(blob_identifiers);
                        peer_manager.mark_peer_as_idle(peer_id);
                        let blob_sidecars = match blob_sidecars_result {
                            Ok(blob_sidecars) => blob_sidecars,
                            Err(err) => {
                                warn!("Failed to fetch blobs from peer: {err:?}");
                                continue;
                            }
                        };

                        let blob_sidecars = match blob_sidecars {
                            Ok(blob_sidecars) => blob_sidecars,
                            Err(err) => {
                                warn!("Failed to fetch blobs from identifiers: {err:?}");
                                peer_manager.ban_peer(
                                    peer_id,
                                    BanReason::ProtocolError(format!("{err:?}")),
                                );
                                continue;
                            }
                        };

                        if blob_sidecars.is_empty() {
                            warn!("Received empty blob identifiers from peer: {peer_id}");
                            peer_manager.ban_peer(peer_id, BanReason::EmptyResponse);
                            continue;
                        }

                        if let Err(err) = block_cache.add_blobs(blob_sidecars) {
                            warn!("Failed to add downloaded blobs to cache: {err:?}");
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
                        peer_manager.mark_peer_as_idle(peer_id);
                        block_cache.remove_blob_identifiers_in_progress(blob_identifiers);
                        indexes_to_remove.push(index);
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
                    Poll::Ready(Ok(columns_result)) => {
                        indexes_to_remove.push(index);
                        block_cache.remove_data_column_identifiers_in_progress(identifiers);
                        peer_manager.mark_peer_as_idle(peer_id);
                        let columns = match columns_result {
                            Ok(columns) => columns,
                            Err(err) => {
                                warn!("Failed to fetch data columns from peer: {err:?}");
                                continue;
                            }
                        };

                        let columns = match columns {
                            Ok(columns) => columns,
                            Err(err) => {
                                warn!("Failed to fetch data columns from identifiers: {err:?}");
                                peer_manager.ban_peer(
                                    peer_id,
                                    BanReason::ProtocolError(format!("{err:?}")),
                                );
                                continue;
                            }
                        };

                        if columns.is_empty() {
                            warn!("Received empty data column identifiers from peer: {peer_id}");
                            peer_manager.ban_peer(peer_id, BanReason::EmptyResponse);
                            continue;
                        }

                        if let Err(err) = block_cache.add_data_columns(columns, required_columns) {
                            warn!("Failed to add downloaded data columns to cache: {err:?}");
                            peer_manager
                                .ban_peer(peer_id, BanReason::InvalidProof(format!("{err:?}")));
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
                        peer_manager.mark_peer_as_idle(peer_id);
                        block_cache.remove_data_column_identifiers_in_progress(identifiers);
                        indexes_to_remove.push(index);
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
    use ream_consensus_beacon::data_column_sidecar::NUMBER_OF_COLUMNS;
    use ream_consensus_misc::polynomial_commitments::{
        kzg_commitment::KZGCommitment, kzg_proof::KZGProof,
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
        }

        let network_state = test_network_state();
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
}

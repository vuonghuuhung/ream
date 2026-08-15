mod block_cache;
mod peer_manager;
mod peer_range_downloader;

use std::{
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
use peer_manager::PeerManager;
use peer_range_downloader::{PeerBlobIdentifierDownloader, PeerRootsDownloader};
use ream_chain_beacon::beacon_chain::{
    BeaconChain, BlockProcessingOutcome, is_data_availability_check_required,
};
use ream_consensus_beacon::{
    blob_sidecar::{BlobIdentifier, BlobSidecar},
    data_column_sidecar::{DataColumnSidecar, get_data_column_sidecars_from_block},
    electra::beacon_block::SignedBeaconBlock,
    matrix_entry::{compute_cells_and_kzg_proofs, das_context},
};
use ream_consensus_misc::misc::compute_epoch_at_slot;
use ream_executor::ReamExecutor;
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::network::beacon::{channel::P2PMessage, network_state::NetworkState};
use ream_polynomial_commitments::handlers::verify_blob_kzg_proof_batch;
use ream_req_resp::MAX_CONCURRENT_REQUESTS;
use ream_storage::tables::table::{CustomTable, REDBTable};
use tokio::{sync::mpsc::UnboundedSender, task::JoinHandle, time::sleep};
use tracing::{info, warn};
use tree_hash::TreeHash;

use crate::block_range::peer_range_downloader::{PeerRangeDownloader, Range};

const MAX_BLOBS_PER_REQUEST: usize = 6;
const MAX_BLOCKS_PER_REQUEST: u64 = 10;
const SLEEP_DURATION: Duration = Duration::from_secs(5);

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
        let target_slot = self
            .peer_manager
            .head_slot()
            .or_else(|| self.peer_manager.finalized_slot());
        let latest_synced_slot = self
            .beacon_chain
            .store
            .lock()
            .await
            .db
            .slot_index_provider()
            .get_highest_slot()
            .unwrap_or_default()
            .unwrap_or(0);

        target_slot <= Some(latest_synced_slot)
    }

    pub fn start(mut self) -> JoinHandle<anyhow::Result<anyhow::Result<BlockRangeSyncer>>> {
        let executor = self.executor.clone();
        executor.spawn(async move {
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
            let mut block_cache =
                BlockCache::new(latest_synced_root, latest_synced_slot);
            let mut task_handles = vec![];
            loop {
                poll_ready_tasks(&mut task_handles, &mut block_cache, &mut self.peer_manager)?;

                let target_slot = match self
                    .peer_manager
                    .head_slot()
                    .or_else(|| self.peer_manager.finalized_slot())
                {
                    Some(target_slot) => target_slot,
                    None => {
                        warn!("No peers available to determine sync target, retrying...");
                        sleep(SLEEP_DURATION).await;
                        self.peer_manager.update_peer_set();
                        continue;
                    }
                };

                let current_epoch = self
                    .beacon_chain
                    .store
                    .lock()
                    .await
                    .get_current_store_epoch()?;
                let data_to_fetch = block_cache.data_to_fetch(target_slot, current_epoch);
                info!(
                    "Forward sync status: Downloaded Blocks {}, Downloaded Blobs {}/{}, Stage {data_to_fetch}",
                    block_cache.block_count(),
                    block_cache.downloaded_blob_count(),
                    block_cache.blob_count(),
                );

                match data_to_fetch {
                    DataToFetch::BlockRange(range) => {
                        let Some(peer) = self.peer_manager.fetch_idle_peer() else {
                            self.peer_manager.update_peer_set();
                            info!("No idle peers available for block range sync.");
                            sleep(SLEEP_DURATION).await;
                            continue;
                        };

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
                    DataToFetch::MissingBlockRoots(block_roots) => {
                        for block_roots_chunk in block_roots.chunks(MAX_CONCURRENT_REQUESTS) {
                            let Some(peer) = self.peer_manager.fetch_idle_peer() else {
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
                            let Some(peer) = self.peer_manager.fetch_idle_peer() else {
                                self.peer_manager.update_peer_set();
                                info!("No idle peers available for blob sync. {}", self.peer_manager.peer_counts());
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
                    DataToFetch::DownloadsInProgress => {
                        info!("Waiting for ongoing downloads to complete... {}", self.peer_manager.peer_counts());
                        sleep(Duration::from_secs(10)).await;
                    }
                    DataToFetch::Finished => break,
                }
            }

            info!("Block range sync completed a segment successfully with {} blocks and {} blobs.",
                block_cache.block_count(),
                block_cache.downloaded_blob_count(),
            );

            // execute all the blocks downloaded
            for BlockAndBlobBundle { block, blobs } in block_cache.get_blocks_and_blobs()?  {
                info!("Processing block with slot {}",
                    block.message.slot,
                );

                let (block, columns) = if block.message.body.blob_kzg_commitments.is_empty() {
                    ensure!(
                        blobs.is_empty(),
                        "Range-sync block without blob commitments had downloaded blob sidecars"
                    );
                    (block, Vec::new())
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

            Ok(self)
        })
    }
}

pub enum DownloadTask {
    BlockRange {
        handle: JoinHandle<anyhow::Result<anyhow::Result<Vec<SignedBeaconBlock>>>>,
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
}

fn poll_ready_tasks(
    tasks: &mut Vec<DownloadTask>,
    block_cache: &mut BlockCache,
    peer_manager: &mut PeerManager,
) -> anyhow::Result<()> {
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    let mut indexes_to_remove = vec![];

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
                                peer_manager
                                    .ban_peer(peer_id, format!("Failed to fetch blocks: {err:?}"));
                                continue;
                            }
                        };

                        if blocks.is_empty() {
                            warn!("Received empty block range from peer: {peer_id}");
                            block_cache.push_retry_range(*range);
                            peer_manager
                                .ban_peer(peer_id, "Received empty block range".to_string());
                            continue;
                        }

                        if let Err(err) = block_cache.add_blocks(blocks, true) {
                            warn!("Failed to add downloaded blocks to cache: {err:?}");
                            block_cache.push_retry_range(*range);
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
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
                                    format!("Failed to fetch blocks from receipts: {err:?}"),
                                );
                                continue;
                            }
                        };

                        if blocks.is_empty() {
                            warn!("Received empty block roots from peer: {peer_id}");
                            peer_manager
                                .ban_peer(peer_id, "Received empty block roots".to_string());
                            continue;
                        }

                        if let Err(err) = block_cache.add_blocks(blocks, false) {
                            warn!("Failed to add downloaded blocks to cache: {err:?}");
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
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
                                    format!("Failed to fetch blobs from identifiers: {err:?}"),
                                );
                                continue;
                            }
                        };

                        if blob_sidecars.is_empty() {
                            warn!("Received empty blob identifiers from peer: {peer_id}");
                            peer_manager
                                .ban_peer(peer_id, "Received empty blob identifiers".to_string());
                            continue;
                        }

                        if let Err(err) = block_cache.add_blobs(blob_sidecars) {
                            warn!("Failed to add downloaded blobs to cache: {err:?}");
                        }
                    }
                    Poll::Ready(Err(err)) => {
                        warn!("Forward fill task failed: {err}");
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
    use std::collections::HashMap;

    use kzg::{G1, eip_4844::compute_blob_kzg_proof_raw};
    use ream_consensus_beacon::data_column_sidecar::NUMBER_OF_COLUMNS;
    use ream_consensus_misc::polynomial_commitments::{
        kzg_commitment::KZGCommitment, kzg_proof::KZGProof,
    };
    use ream_execution_rpc_types::get_blobs::{Blob, BlobAndProofV1};

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
}

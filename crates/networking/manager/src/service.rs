use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;
use libp2p::PeerId;
use rand::seq::SliceRandom;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    data_column_sidecar::NUMBER_OF_COLUMNS, electra::beacon_block::SignedBeaconBlock,
};
use ream_consensus_misc::{constants::beacon::SLOTS_PER_EPOCH, misc::compute_start_slot_at_epoch};
use ream_discv5::{
    config::DiscoveryConfig,
    subnet::{AttestationSubnets, CustodyGroupCount, SyncCommitteeSubnets},
};
use ream_executor::ReamExecutor;
use ream_fork_choice_beacon::data_availability::AvailabilityEntryStatus;
use ream_metrics::{
    BEACON_BLOCK_LOOKUP_ENTRIES, BEACON_BLOCK_LOOKUP_EVENTS_TOTAL, BEACON_CUSTODY_GROUPS,
    BEACON_DATA_COLUMN_FETCH_ATTEMPTS_TOTAL, BEACON_DATA_COLUMN_FETCH_DURATION_SECONDS,
    BEACON_DATA_COLUMN_FETCH_ENTRIES, BEACON_EXECUTION_COLUMN_FETCHES_TOTAL,
    BEACON_UNSEEN_BLOCK_LOOKUPS_TOTAL, inc_int_counter_vec, inc_int_counter_vec_by,
    observe_histogram, set_int_gauge_vec,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::{
    config::NetworkConfig,
    network::beacon::{
        Network, ReamNetworkEvent, identity::local_node_id, network_state::NetworkState,
    },
};
use ream_storage::{
    cache::BeaconCacheDB,
    db::{beacon::BeaconDB, beacon_backfill::CustodyAlignment},
    tables::{field::REDBField, table::REDBTable},
};
use ream_sync_committee_pool::SyncCommitteePool;
use ream_syncer::{
    backfill::BackfillSyncer,
    block_range::BlockRangeSyncer,
    unknown_parent_lookups::{MAX_LOOKUPS, UnknownBlockMeta, UnknownParentLookupCoordinator},
};
use tokio::{
    sync::mpsc,
    time::{Instant, MissedTickBehavior, interval, interval_at, sleep},
};
use tracing::{debug, error, info, warn};
use tree_hash::TreeHash;

use crate::{
    block_lookup::{
        BlockLookupConfig, BlockLookupCoordinator, PendingGossipItem, apply_block_import_event,
        apply_coordinator_update, insert_pending_item, log_insert_outcome,
        spawn_block_lookup_worker,
    },
    config::ManagerConfig,
    custody::{
        ValidatorCustody, attached_validators_custody_requirement, local_custody_assignment,
    },
    data_availability_fetch::{
        ColumnFetchOutcome, ColumnFetchTracker, fetch_missing_columns, pending_anchor_for_recovery,
    },
    gossip_hint::{ExecutionFetchReservations, GossipHint, UnknownParentColumns, UnseenBlock},
    gossipsub::{
        cross_seed::publish_reconstructed_columns,
        handle::{
            UnknownParentGossipBlock, handle_gossipsub_message, init_gossipsub_config_with_topics,
        },
        workers::{
            GossipWorkerBudget, GossipWorkers, HINT_QUEUE_CAPACITY, OnValidBlock,
            PENDING_ITEM_QUEUE_CAPACITY, is_data_column, is_gossip_block, is_handled_concurrently,
        },
    },
    p2p_sender::P2PSender,
    req_resp::handle_req_resp_message,
    timing::{ColumnSource, log_columns_received, log_unseen_block_lookup},
    unknown_parent_lookup::{
        BlocksByRootRefusals, UnknownParentLookupUpdate, apply_unknown_parent_update,
        fallback_lookup_peer, spawn_unknown_parent_action,
    },
};

const PENDING_AVAILABILITY_LOOKUP: &str = "pending_availability";
const UNKNOWN_PARENT_LOOKUP: &str = "unknown_parent";

fn record_removed_lookup_entries(kind: &str, event: &str, before: usize, after: usize) {
    let removed = before.saturating_sub(after);
    if removed > 0 {
        inc_int_counter_vec_by(
            &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
            removed as u64,
            &[kind, event],
        );
    }
}

fn update_lookup_gauges<BlockPayload>(
    block_lookup_coordinator: &BlockLookupCoordinator,
    unknown_parent_lookups: &UnknownParentLookupCoordinator<BlockPayload, PeerId>,
    column_fetch_tracker: &ColumnFetchTracker,
) {
    set_int_gauge_vec(
        &BEACON_BLOCK_LOOKUP_ENTRIES,
        block_lookup_coordinator.pending_entry_count() as i64,
        &[PENDING_AVAILABILITY_LOOKUP],
    );
    set_int_gauge_vec(
        &BEACON_BLOCK_LOOKUP_ENTRIES,
        unknown_parent_lookups.len() as i64,
        &[UNKNOWN_PARENT_LOOKUP],
    );
    set_int_gauge_vec(
        &BEACON_DATA_COLUMN_FETCH_ENTRIES,
        column_fetch_tracker.tracked_count() as i64,
        &["tracked"],
    );
    set_int_gauge_vec(
        &BEACON_DATA_COLUMN_FETCH_ENTRIES,
        column_fetch_tracker.in_flight_count() as i64,
        &["in_flight"],
    );
}

pub struct NetworkManagerService {
    pub beacon_chain: Arc<BeaconChain>,
    manager_receiver: mpsc::UnboundedReceiver<ReamNetworkEvent>,
    pub p2p_sender: P2PSender,
    pub network_state: Arc<NetworkState>,
    pub block_range_syncer: BlockRangeSyncer,
    pub ream_db: BeaconDB,
    pub cached_db: Arc<BeaconCacheDB>,
    pub sync_committee_pool: Arc<SyncCommitteePool>,
    pub executor: ReamExecutor,
    /// Whether gossip blocks fetch their blobs from the execution client.
    pub fetch_execution_blobs: bool,
    pub backfill_config: ream_syncer::backfill::scheduler::BackfillConfig,
    pub disable_backfill_rate_limiting: bool,
    pub blob_retention_epochs: u64,
    /// Column backfill covers what live import samples, so history matches the live range.
    pub backfill_custody: ream_syncer::backfill::ColumnCustody,
    pub validator_custody: ValidatorCustody,
}

fn maintain_historical_sidecars(
    db: &BeaconDB,
    current_slot: u64,
    finalized_slot: u64,
    blob_retention_epochs: u64,
) -> anyhow::Result<()> {
    let spec = beacon_network_spec();
    let da_start = spec.data_column_retention_start_slot(current_slot / SLOTS_PER_EPOCH);
    let removed = db.prune_columns(da_start, finalized_slot, 256)?;
    ream_metrics::BEACON_COLUMNS_PRUNED_TOTAL.inc_by(removed as u64);
    if removed > 0 {
        info!(removed, "Pruned historical data columns");
    }
    if let ream_storage::tables::beacon::backfill::BackfillMode::Checkpoint(meta) =
        db.cached_backfill_mode()?
        && meta
            .sidecars
            .frontier
            .is_some_and(|slot| slot < da_start.min(meta.origin.slot))
    {
        match db.advance_sidecar_retention(meta.revision, da_start) {
            Ok(_) | Err(ream_storage::db::beacon_backfill::CommitError::Conflict { .. }) => {}
            Err(err) => return Err(err.into()),
        }
    }
    db.prune_old_blobs(current_slot, blob_retention_epochs)?;
    Ok(())
}

struct ReconciledBlockLookupState {
    imported_roots: Vec<alloy_primitives::B256>,
    pending_availability_roots: Vec<alloy_primitives::B256>,
}

/// Hands a block or column waiting on its parent's availability to the pending lookups.
async fn insert_pending_gossip_item<BlockPayload>(
    beacon_chain: &BeaconChain,
    block_lookup_coordinator: &mut BlockLookupCoordinator,
    unknown_parent_lookups: &mut UnknownParentLookupCoordinator<BlockPayload, PeerId>,
    item: PendingGossipItem,
) {
    let is_block = matches!(&item, PendingGossipItem::Block { .. });
    let block_root = match &item {
        PendingGossipItem::Block { block, .. } => block.block().message.tree_hash_root(),
        PendingGossipItem::Column { column, .. } => column
            .sidecar()
            .signed_block_header
            .message
            .tree_hash_root(),
    };
    let current_slot = {
        let store = beacon_chain.store.lock().await;
        store.get_current_slot()
    };
    match current_slot {
        Ok(current_slot) => {
            let entry_existed = block_lookup_coordinator.contains_entry(&block_root);
            let entries_before = block_lookup_coordinator.pending_entry_count();
            let outcome = insert_pending_item(block_lookup_coordinator, item, current_slot);
            let retained = matches!(
                outcome,
                ream_syncer::block_lookups::InsertOutcome::Inserted
                    | ream_syncer::block_lookups::InsertOutcome::Duplicate
            );
            match outcome {
                ream_syncer::block_lookups::InsertOutcome::Inserted if !entry_existed => {
                    inc_int_counter_vec(
                        &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                        &[PENDING_AVAILABILITY_LOOKUP, "created"],
                    );
                    let evicted = entries_before
                        .saturating_add(1)
                        .saturating_sub(block_lookup_coordinator.pending_entry_count());
                    if evicted > 0 {
                        inc_int_counter_vec_by(
                            &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                            evicted as u64,
                            &[PENDING_AVAILABILITY_LOOKUP, "pruned"],
                        );
                    }
                }
                ream_syncer::block_lookups::InsertOutcome::Rejected(_) => {
                    inc_int_counter_vec(
                        &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                        &[PENDING_AVAILABILITY_LOOKUP, "rejected"],
                    );
                }
                _ => {}
            }
            log_insert_outcome(block_root, outcome);
            if is_block && retained {
                unknown_parent_lookups.block_deferred_elsewhere(block_root);
            }
            if !is_block && retained {
                // The block event may have been handled while this column was still validating.
                // Reconcile after insertion so an earlier event cannot leave it waiting forever.
                let reconciliation =
                    reconcile_block_lookup_state(beacon_chain, vec![block_root]).await;
                if reconciliation.imported_roots.contains(&block_root) {
                    block_lookup_coordinator.parent_imported(block_root);
                    unknown_parent_lookups.block_imported(block_root);
                } else if reconciliation
                    .pending_availability_roots
                    .contains(&block_root)
                {
                    block_lookup_coordinator.mark_block_pending_availability(block_root);
                    unknown_parent_lookups.block_pending_availability(block_root);
                }
            }
        }
        Err(err) => {
            error!("Failed to read current slot for pending gossip: {err}")
        }
    }
}

fn spawn_queued_column_fetches(
    tracker: &mut ColumnFetchTracker,
    beacon_chain: &Arc<BeaconChain>,
    p2p_sender: &P2PSender,
    network_state: &NetworkState,
    done_sender: &mpsc::UnboundedSender<(B256, PeerId, ColumnFetchOutcome)>,
) {
    // Only peers with a valid custody advertisement are expected to serve any column.
    let custody_peers = network_state
        .connected_peers()
        .into_iter()
        .filter_map(|peer| {
            let custody = peer.custody().groups()?.clone();
            Some((peer.peer_id, custody))
        })
        .collect::<HashMap<_, _>>();
    let connected_peers = custody_peers.keys().copied().collect::<Vec<_>>();
    while let Some((block_root, peer)) =
        tracker.next_fetch(&connected_peers, std::time::Instant::now())
    {
        // `next_fetch` only returns peers from `connected_peers`, the keys of `custody_peers`.
        let peer_custody = custody_peers[&peer].clone();
        let beacon_chain = beacon_chain.clone();
        let p2p_sender = p2p_sender.clone();
        let done_sender = done_sender.clone();
        tokio::spawn(async move {
            let started_at = std::time::Instant::now();
            let outcome =
                fetch_missing_columns(&beacon_chain, &p2p_sender, block_root, peer, &peer_custody)
                    .await;
            observe_histogram(
                &BEACON_DATA_COLUMN_FETCH_DURATION_SECONDS,
                started_at.elapsed().as_secs_f64(),
            );
            let _ = done_sender.send((block_root, peer, outcome));
        });
    }
}

/// Attempts per announced reconstruction. The block stays pending until its columns are rebuilt,
/// and no further column may arrive to announce it again, so a transient failure is retried.
const COLUMN_RECONSTRUCTION_ATTEMPTS: u32 = 3;
const COLUMN_RECONSTRUCTION_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Wait before rebuilding, so columns a few milliseconds away arrive by gossip instead (das-core
/// allows a delay). The block's import waits for the rebuild, so the delay is kept as short as
/// Lighthouse v8.2.0's `QUEUED_RECONSTRUCTION_DELAY`.
const COLUMN_RECONSTRUCTION_DELAY: Duration = Duration::from_millis(150);

/// Rebuilds a block's missing columns on its own task, since reading the stored columns and
/// recovering the rest takes too long for the event loop, then cross-seeds the rebuilt ones.
fn spawn_column_reconstruction(
    beacon_chain: &Arc<BeaconChain>,
    cached_db: &Arc<BeaconCacheDB>,
    p2p_sender: &P2PSender,
    block_root: B256,
) {
    let beacon_chain = beacon_chain.clone();
    let cached_db = cached_db.clone();
    let p2p_sender = p2p_sender.clone();
    tokio::spawn(async move {
        sleep(COLUMN_RECONSTRUCTION_DELAY).await;
        for attempt in 1..=COLUMN_RECONSTRUCTION_ATTEMPTS {
            // A block that left the pending set, or no longer needs columns, returns no columns.
            match beacon_chain.reconstruct_data_columns(block_root).await {
                Ok(rebuilt) => {
                    if rebuilt.is_empty() {
                        return;
                    }
                    if let (Ok(genesis_time), Some(first)) = (
                        beacon_chain.db().genesis_time_provider().get(),
                        rebuilt.first(),
                    ) {
                        log_columns_received(
                            genesis_time,
                            first.signed_block_header.message.slot,
                            rebuilt.iter().map(|column| column.index),
                            ColumnSource::Reconstructed,
                            None,
                        );
                    }
                    let finalized_slot =
                        match beacon_chain.db().finalized_checkpoint_provider().get() {
                            Ok(checkpoint) => compute_start_slot_at_epoch(checkpoint.epoch),
                            Err(err) => {
                                error!(%block_root, "Cannot cross-seed rebuilt columns: {err}");
                                return;
                            }
                        };
                    let published = publish_reconstructed_columns(
                        rebuilt,
                        finalized_slot,
                        &cached_db,
                        &p2p_sender,
                    )
                    .await;
                    debug!(%block_root, published, "Cross-seeded reconstructed data columns");
                    return;
                }
                Err(err) if attempt == COLUMN_RECONSTRUCTION_ATTEMPTS => {
                    error!(%block_root, attempt, "Column reconstruction failed: {err:#}");
                    return;
                }
                Err(err) => {
                    warn!(%block_root, attempt, "Column reconstruction failed, retrying: {err:#}");
                    sleep(COLUMN_RECONSTRUCTION_RETRY_DELAY).await;
                }
            }
        }
    });
}

/// Raises the custody for the validators that prepared to propose through this node, and makes
/// blocks wait for the raised sampled set once it takes effect.
async fn update_validator_custody(
    validator_custody: &mut ValidatorCustody,
    beacon_chain: &BeaconChain,
    p2p_sender: &P2PSender,
    current_slot: u64,
) {
    let validator_indices = beacon_chain
        .operation_pool()
        .get_all_proposer_preparations()
        .into_keys()
        .collect::<Vec<_>>();
    if validator_indices.is_empty() && !validator_custody.has_pending_sampling() {
        return;
    }
    let head = match beacon_chain.head() {
        Ok(head) => head,
        Err(err) => {
            debug!("Validator custody waits for the head: {err}");
            return;
        }
    };
    let requirement = attached_validators_custody_requirement(&head.state, &validator_indices);
    match requirement.and_then(|requirement| validator_custody.on_slot(current_slot, requirement)) {
        Ok(change) => {
            if let Some(custody) = change.raised {
                info!(
                    custody_group_count = custody.custody_group_count,
                    validators = validator_indices.len(),
                    "Raising data column custody for attached validators"
                );
                BEACON_CUSTODY_GROUPS.set(custody.custody_group_count as i64);
                p2p_sender.raise_custody(custody);
            }
            if let Some(sampling_columns) = change.sampling_columns {
                beacon_chain.set_sampling_columns(sampling_columns).await;
            }
        }
        Err(err) => warn!("Failed to update validator custody: {err:#}"),
    }
}

/// Columns built from execution blobs are published in batches of this size, a quarter of them.
const EXECUTION_COLUMN_PUBLICATION_BATCH_SIZE: usize = (NUMBER_OF_COLUMNS / 4) as usize;
/// Wait between two batches of columns built from execution blobs.
const EXECUTION_COLUMN_PUBLICATION_INTERVAL: Duration = Duration::from_millis(300);

/// Imports the columns of a gossip block from the execution client's blobs on its own task, so
/// it runs alongside the block's import, then publishes them like reconstructed columns (Fulu p2p
/// "Distributed Blob Publishing using blobs retrieved from local execution-layer client").
fn spawn_execution_column_fetch(
    beacon_chain: &Arc<BeaconChain>,
    cached_db: &Arc<BeaconCacheDB>,
    p2p_sender: &P2PSender,
    signed_block: &SignedBeaconBlock,
) {
    if signed_block.message.body.blob_kzg_commitments.is_empty() {
        return;
    }
    let beacon_chain = beacon_chain.clone();
    let cached_db = cached_db.clone();
    let p2p_sender = p2p_sender.clone();
    let signed_block = signed_block.clone();
    tokio::spawn(async move {
        let block_root = signed_block.message.tree_hash_root();
        let columns = match beacon_chain
            .fetch_columns_from_execution(&signed_block)
            .await
        {
            Ok(columns) if columns.is_empty() => return,
            Ok(columns) => columns,
            Err(err) => {
                warn!(%block_root, "Failed to import data columns from execution blobs: {err:#}");
                return;
            }
        };
        if let Ok(genesis_time) = beacon_chain.db().genesis_time_provider().get() {
            log_columns_received(
                genesis_time,
                signed_block.message.slot,
                columns.iter().map(|column| column.index),
                ColumnSource::ExecutionLayer,
                None,
            );
        }
        let finalized_slot = match beacon_chain.db().finalized_checkpoint_provider().get() {
            Ok(checkpoint) => compute_start_slot_at_epoch(checkpoint.epoch),
            Err(err) => {
                error!(%block_root, "Cannot publish data columns from execution blobs: {err}");
                return;
            }
        };
        // Publish in random batches, so columns that arrive over gossip meanwhile are skipped;
        // sending every column at once delayed the columns of other blocks (Lighthouse v8.2.0's
        // `publish_data_columns_gradually`, with its defaults).
        let mut columns = columns;
        columns.shuffle(&mut rand::rng());
        let mut published = 0;
        for (batch_index, batch) in columns
            .chunks(EXECUTION_COLUMN_PUBLICATION_BATCH_SIZE)
            .enumerate()
        {
            if batch_index > 0 {
                sleep(EXECUTION_COLUMN_PUBLICATION_INTERVAL).await;
            }
            published += publish_reconstructed_columns(
                batch.to_vec(),
                finalized_slot,
                &cached_db,
                &p2p_sender,
            )
            .await;
        }
        debug!(%block_root, published, "Published data columns from execution blobs");
    });
}

/// Fetches the columns of `block_root` from the execution client's blobs once it is pending
/// availability. Blocks that came by gossip are fetched on validation; this covers those imported
/// through a lookup, whose columns gossip may have dropped before their parent came.
fn spawn_pending_execution_column_fetch(
    beacon_chain: &Arc<BeaconChain>,
    cached_db: &Arc<BeaconCacheDB>,
    p2p_sender: &P2PSender,
    reservations: &ExecutionFetchReservations,
    block_root: B256,
) {
    if !reservations.reserve(block_root) {
        return;
    }
    let beacon_chain = beacon_chain.clone();
    let cached_db = cached_db.clone();
    let p2p_sender = p2p_sender.clone();
    tokio::spawn(async move {
        let block = {
            let store = beacon_chain.store.lock().await;
            store
                .data_availability_checker
                .pending_block(&block_root)
                .map(|pending| pending.signed_block.clone())
        };
        let Some(block) = block else {
            return;
        };
        // The execution client only keeps the blobs of recent blocks.
        let current_slot = beacon_chain.head().map_or(0, |head| head.current_slot);
        if block.message.slot + SLOTS_PER_EPOCH < current_slot {
            return;
        }
        inc_int_counter_vec(&BEACON_EXECUTION_COLUMN_FETCHES_TOTAL, &["pending"]);
        spawn_execution_column_fetch(&beacon_chain, &cached_db, &p2p_sender, &block);
    });
}

/// Wait before looking up a block that gossip referred to, so a block that is still coming or
/// being imported is not downloaded again.
const UNSEEN_BLOCK_LOOKUP_DELAY: Duration = Duration::from_secs(1);
/// Blocks referred to longer ago than this many slots are left to range sync.
const UNSEEN_BLOCK_LOOKUP_SLOTS: u64 = 4;

fn schedule_unseen_block_lookup(unseen: UnseenBlock, due: &mpsc::UnboundedSender<UnseenBlock>) {
    let due = due.clone();
    tokio::spawn(async move {
        sleep(UNSEEN_BLOCK_LOOKUP_DELAY).await;
        let _ = due.send(unseen);
    });
}

/// Looks up `unseen` by root unless it came or is already being looked up meanwhile.
async fn start_unseen_block_lookup(
    unseen: UnseenBlock,
    beacon_chain: &BeaconChain,
    network_state: &NetworkState,
    lookup_refusals: &BlocksByRootRefusals,
    unknown_parent_lookups: &mut UnknownParentLookupCoordinator<SignedBeaconBlock, PeerId>,
    block_lookup_coordinator: &BlockLookupCoordinator,
) {
    let UnseenBlock {
        block_root,
        slot,
        source,
        peer,
    } = unseen;
    let count = |outcome: &str| {
        inc_int_counter_vec(
            &BEACON_UNSEEN_BLOCK_LOOKUPS_TOTAL,
            &[source.as_str(), outcome],
        );
    };
    let Ok(head) = beacon_chain.head() else {
        return;
    };
    // While syncing, recent gossip names blocks that range sync is about to download.
    if slot + UNSEEN_BLOCK_LOOKUP_SLOTS < head.current_slot
        || head.head_slot + SLOTS_PER_EPOCH < head.current_slot
    {
        return count("stale");
    }
    let known = unknown_parent_lookups.contains(&block_root)
        || block_lookup_coordinator.contains_entry(&block_root)
        || beacon_chain
            .db()
            .block_provider()
            .contains_key(block_root)
            .unwrap_or(true)
        || beacon_chain
            .store
            .lock()
            .await
            .data_availability_checker
            .pending_block(&block_root)
            .is_some();
    if known {
        return count("known");
    }
    let lookup_peer = if lookup_refusals.contains(&peer) {
        fallback_lookup_peer(network_state, lookup_refusals, &[peer], block_root).unwrap_or(peer)
    } else {
        peer
    };
    match unknown_parent_lookups.insert_block_root(block_root, lookup_peer) {
        ream_syncer::unknown_parent_lookups::InsertOutcome::Inserted => {
            count("started");
            if let Ok(genesis_time) = beacon_chain.db().genesis_time_provider().get() {
                log_unseen_block_lookup(genesis_time, slot, block_root, source.as_str());
            }
        }
        ream_syncer::unknown_parent_lookups::InsertOutcome::Duplicate => count("known"),
        ream_syncer::unknown_parent_lookups::InsertOutcome::Rejected(_) => count("rejected"),
    }
}

/// Hands the columns that waited for `parent_root` back to the column workers.
fn replay_unknown_parent_columns(
    unknown_parent_columns: &mut UnknownParentColumns,
    column_workers: &GossipWorkers,
    parent_root: B256,
) {
    for (column, peer) in unknown_parent_columns.take(parent_root) {
        column_workers.replay_column(column, peer);
    }
}

/// Margin after a slot start before the slot tick runs. The tick reads the wall clock in whole
/// seconds, so it must not run before the slot's first second has begun.
const SLOT_TICK_DELAY: Duration = Duration::from_millis(20);

/// Time from `now` (since the Unix epoch) until the next slot tick: `SLOT_TICK_DELAY` after the
/// next slot start, or after genesis before it.
fn until_next_slot_tick(genesis_time: u64, seconds_per_slot: u64, now: Duration) -> Duration {
    let genesis = Duration::from_secs(genesis_time);
    if now < genesis {
        return genesis - now + SLOT_TICK_DELAY;
    }
    let slot_nanos = u128::from(seconds_per_slot) * 1_000_000_000;
    let into_slot = Duration::from_nanos(((now - genesis).as_nanos() % slot_nanos) as u64);
    let until_slot_start = if into_slot.is_zero() {
        Duration::ZERO
    } else {
        Duration::from_secs(seconds_per_slot) - into_slot
    };
    until_slot_start + SLOT_TICK_DELAY
}

/// Starts a lookup for the parent of `unknown`, a gossip block whose parent is not known, from
/// `propagation_source` or, if that peer refused blocks by root, another peer.
fn start_unknown_parent_lookup(
    unknown: UnknownParentGossipBlock,
    propagation_source: PeerId,
    network_state: &NetworkState,
    lookup_refusals: &BlocksByRootRefusals,
    unknown_parent_lookups: &mut UnknownParentLookupCoordinator<SignedBeaconBlock, PeerId>,
) {
    let meta = UnknownBlockMeta {
        block_root: unknown.block.message.tree_hash_root(),
        parent_root: unknown.parent_root,
        slot: unknown.block.message.slot,
    };
    let before = unknown_parent_lookups.len();
    // A source that refused blocks by root cannot serve the parent.
    let lookup_peer = if lookup_refusals.contains(&propagation_source) {
        fallback_lookup_peer(
            network_state,
            lookup_refusals,
            &[propagation_source],
            meta.parent_root,
        )
        .unwrap_or(propagation_source)
    } else {
        propagation_source
    };
    let outcome = unknown_parent_lookups.insert_gossip_block(meta, unknown.block, lookup_peer);
    match outcome {
        ream_syncer::unknown_parent_lookups::InsertOutcome::Inserted => {
            let created = unknown_parent_lookups.len().saturating_sub(before);
            if created > 0 {
                inc_int_counter_vec_by(
                    &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                    created as u64,
                    &[UNKNOWN_PARENT_LOOKUP, "created"],
                );
            }
        }
        ream_syncer::unknown_parent_lookups::InsertOutcome::Duplicate => {}
        ream_syncer::unknown_parent_lookups::InsertOutcome::Rejected(error) => {
            inc_int_counter_vec(
                &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                &[UNKNOWN_PARENT_LOOKUP, "rejected"],
            );
            warn!(block_root = ?meta.block_root, ?error, "Rejected unknown-parent lookup");
        }
    }
}

/// How far into a slot, in basis points of the slot, the head state is advanced through a coming
/// epoch boundary. Lighthouse's state advance runs at three quarters of each slot: the slot's
/// block has usually come by then, and the next block is still seconds away.
const STATE_ADVANCE_SLOT_BPS: u64 = 7_500;

/// The epoch the head state is advanced into during `slot`: the next one, when `slot` is the last
/// slot of its epoch.
fn epoch_to_advance_into(slot: u64) -> Option<u64> {
    (slot + 1)
        .is_multiple_of(SLOTS_PER_EPOCH)
        .then(|| (slot + 1) / SLOTS_PER_EPOCH)
}

/// Advances the head state into the next epoch in the background when `slot` is the last slot
/// of an epoch; see `BeaconChain::advance_head_to_next_epoch`.
fn spawn_state_advance(beacon_chain: &Arc<BeaconChain>, slot: u64) {
    let Some(next_epoch) = epoch_to_advance_into(slot) else {
        return;
    };
    let beacon_chain = beacon_chain.clone();
    tokio::spawn(async move { beacon_chain.advance_head_to_next_epoch(next_epoch).await });
}

/// Validators active in the head state's epoch, which gossipsub peer scoring derives its expected
/// message rates from. `None`, leaving scoring off, before there is a head.
fn active_validator_count(beacon_chain: &BeaconChain) -> Option<usize> {
    match beacon_chain.head() {
        Ok(head) => Some(
            head.state
                .get_active_validator_indices(head.state.get_current_epoch())
                .len(),
        ),
        Err(err) => {
            warn!("Gossipsub peer scoring is off: no head state yet: {err:#}");
            None
        }
    }
}

async fn reconcile_block_lookup_state(
    beacon_chain: &BeaconChain,
    roots: Vec<alloy_primitives::B256>,
) -> ReconciledBlockLookupState {
    let store = beacon_chain.store.lock().await;
    let mut imported_roots = roots.clone();
    imported_roots.retain(|block_root| {
        let has_block = store
            .db
            .block_provider()
            .contains_key(*block_root)
            .unwrap_or(false);
        let has_state = store
            .db
            .state_provider()
            .contains_key(*block_root)
            .unwrap_or(false);
        has_block && has_state
    });
    let pending_availability_roots = roots
        .into_iter()
        .filter(|block_root| {
            matches!(
                store.data_availability_checker.status(block_root),
                AvailabilityEntryStatus::PendingBlock | AvailabilityEntryStatus::Complete
            )
        })
        .collect();
    ReconciledBlockLookupState {
        imported_roots,
        pending_availability_roots,
    }
}

/// The `NetworkManagerService` acts as the manager for all networking activities in Ream.
/// Its core responsibilities include:
/// - Managing interactions between discovery, gossipsub, and sync protocols
/// - Routing messages from network protocols to the beacon chain logic
/// - Handling peer lifecycle management and connection state
impl NetworkManagerService {
    /// Creates a new `NetworkManagerService` instance.
    ///
    /// This function initializes the manager service by configuring:
    /// - discv5 configurations such as bootnodes, socket address, port, attestation subnets, sync
    ///   committee subnets, etc.
    /// - The gossipsub topics to subscribe to
    ///
    /// Upon successful configuration, it starts the network worker.
    pub async fn new(
        executor: ReamExecutor,
        config: ManagerConfig,
        ream_db: BeaconDB,
        ream_directory: PathBuf,
        beacon_chain: Arc<BeaconChain>,
        sync_committee_pool: Arc<SyncCommitteePool>,
        cached_db: Arc<BeaconCacheDB>,
    ) -> anyhow::Result<Self> {
        config.backfill_config.validate()?;
        // Initialize the KZG trusted setup before validating data column sidecars to avoid delaying
        // the first gossipsub validation decision.
        executor
            .spawn_blocking(|| {
                ream_polynomial_commitments::trusted_setup::blst_settings();
            })
            .await?;

        let discv5_config = discv5::ConfigBuilder::new(discv5::ListenConfig::from_ip(
            config.socket_address,
            config.discovery_port,
        ))
        .build();

        let custody = local_custody_assignment(&ream_directory, config.supernode)?;
        let validator_custody = ValidatorCustody::new(local_node_id(&ream_directory)?, &custody)?;
        let custody_group_count = CustodyGroupCount(custody.custody_group_count);
        BEACON_CUSTODY_GROUPS.set(custody_group_count.0 as i64);
        info!(
            custody_group_count = custody.custody_group_count,
            sampling_columns = custody.sampling_columns.len(),
            "Data column custody"
        );
        match ream_db.align_sidecar_custody(
            &custody.sampling_columns,
            ream_fork_choice_beacon::store::get_current_slot_from_db(&ream_db)? + 1,
            custody.custody_group_count <= beacon_network_spec().custody_requirement,
        )? {
            CustodyAlignment::Restarted(meta) => info!(
                frontier_slot = ?meta.sidecars.frontier,
                "Custody columns grew, backfilling them for the retention window"
            ),
            CustodyAlignment::Missing => anyhow::bail!(
                "Custody grew beyond the columns this genesis-synced history holds. Keep the \
                 previous custody, or resync from a checkpoint with --purge-db"
            ),
            CustodyAlignment::Unchanged | CustodyAlignment::Recorded => {}
        }

        let bootnodes = config
            .bootnodes
            .to_enrs_beacon(beacon_network_spec().network.clone());
        let discv5_config = DiscoveryConfig {
            discv5_config,
            bootnodes,
            socket_address: config.socket_address,
            socket_port: config.socket_port,
            discovery_port: config.discovery_port,
            disable_discovery: config.disable_discovery,
            // Set from the gossip topics by `Network::init`.
            attestation_subnets: AttestationSubnets::new(),
            sync_committee_subnets: SyncCommitteeSubnets::new(),
            // Must match the count advertised in our MetaData: peers cross-check the ENR
            // `cgc` against it and treat a mismatch, or a value below CUSTODY_REQUIREMENT,
            // as a fault worth banning us for.
            custody_group_count,
        };

        let gossipsub_config = init_gossipsub_config_with_topics(
            config.gossipsub_history_length,
            &custody.data_column_subnet_ids,
        );

        let network_config = NetworkConfig {
            discv5_config,
            gossipsub_config,
            data_dir: ream_directory,
            genesis_time: ream_db.genesis_time_provider().get()?,
            target_peers: config.target_peers,
            active_validators: if config.disable_peer_scoring {
                None
            } else {
                active_validator_count(&beacon_chain)
            },
        };

        let (manager_sender, manager_receiver) = mpsc::unbounded_channel();
        let (p2p_sender, p2p_receiver) = mpsc::unbounded_channel();

        let status = beacon_chain.build_status_request().await?;

        let network = Network::init(executor.clone(), &network_config, status).await?;

        let network_state = network.network_state();

        executor.spawn(async move {
            network.start(manager_sender, p2p_receiver).await;
        });

        let block_range_syncer = BlockRangeSyncer::new(
            beacon_chain.clone(),
            p2p_sender.clone(),
            network_state.clone(),
            executor.clone(),
        );

        Ok(Self {
            beacon_chain,
            manager_receiver,
            p2p_sender: P2PSender(p2p_sender),
            network_state,
            block_range_syncer,
            ream_db,
            cached_db,
            sync_committee_pool,
            executor,
            fetch_execution_blobs: !config.disable_get_blobs,
            backfill_config: config.backfill_config,
            disable_backfill_rate_limiting: config.disable_backfill_rate_limiting,
            backfill_custody: ream_syncer::backfill::ColumnCustody {
                group_count: custody.custody_group_count,
                columns: custody.sampling_columns.clone(),
            },
            blob_retention_epochs: config
                .blob_retention_epochs
                .unwrap_or_default()
                .max(beacon_network_spec().min_epochs_for_blob_sidecars_requests),
            validator_custody,
        })
    }

    /// Starts the manager service, which receives either a Gossipsub message or Req/Resp message
    /// from the network worker, and dispatches them to the appropriate handlers.
    ///
    /// Panics if the manager receiver is not initialized.
    pub async fn start(self) {
        let NetworkManagerService {
            beacon_chain,
            mut manager_receiver,
            p2p_sender,
            ream_db,
            cached_db,
            network_state,
            block_range_syncer,
            executor,
            fetch_execution_blobs,
            backfill_config,
            disable_backfill_rate_limiting,
            blob_retention_epochs,
            backfill_custody,
            mut validator_custody,
            ..
        } = self;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("correct time")
            .as_secs();
        if let Err(err) = beacon_chain.process_tick(now).await {
            error!("Failed to process startup tick: {err}");
        }

        let mut resync_check_interval = interval(Duration::from_secs(
            SLOTS_PER_EPOCH * beacon_network_spec().seconds_per_slot(),
        ));
        // The slot tick advances the store's slot and resets the proposer boost, so it runs at
        // each slot start instead of at the offset the service happened to start at.
        let seconds_per_slot = beacon_network_spec().seconds_per_slot();
        let first_slot_tick = match ream_db.genesis_time_provider().get() {
            Ok(genesis_time) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("correct time");
                Instant::now() + until_next_slot_tick(genesis_time, seconds_per_slot, now)
            }
            Err(err) => {
                warn!("Slot tick is not aligned to slot starts, genesis time unavailable: {err}");
                Instant::now()
            }
        };
        let mut interval = interval_at(first_slot_tick, Duration::from_secs(seconds_per_slot));
        // A tick delayed by a busy loop is skipped rather than replayed, so later ticks stay at
        // slot starts.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut state_advance_interval = interval_at(
            first_slot_tick + Duration::from_millis(seconds_per_slot * STATE_ADVANCE_SLOT_BPS / 10),
            Duration::from_secs(seconds_per_slot),
        );
        state_advance_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // The slot whose state advance has run, so a head block that comes later in that slot is
        // advanced too.
        let mut state_advance_slot = None;
        let mut block_import_receiver = beacon_chain.subscribe_block_imports();
        let mut block_import_receiver_active = true;
        let mut block_lookup_coordinator =
            BlockLookupCoordinator::new(BlockLookupConfig::for_data_column_retention(
                beacon_network_spec().min_epochs_for_data_column_sidecars_requests,
            ));
        let (block_lookup_action_sender, mut block_lookup_update_receiver) =
            spawn_block_lookup_worker(beacon_chain.clone());
        let mut block_lookup_worker_active = true;
        let mut unknown_parent_lookups = UnknownParentLookupCoordinator::default();
        let mut lookup_refusals = BlocksByRootRefusals::default();
        let (unknown_parent_update_sender, mut unknown_parent_update_receiver) =
            mpsc::channel(MAX_LOOKUPS);
        let mut column_fetch_tracker = ColumnFetchTracker::default();
        let mut maintenance_epoch = None;
        let mut maintenance_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>> = None;
        let (column_fetch_done_sender, mut column_fetch_done_receiver) =
            mpsc::unbounded_channel::<(B256, PeerId, ColumnFetchOutcome)>();
        let (pending_item_sender, mut pending_item_receiver) =
            mpsc::channel(PENDING_ITEM_QUEUE_CAPACITY);
        let (hint_sender, mut hint_receiver) = mpsc::channel(HINT_QUEUE_CAPACITY);
        let (unseen_block_sender, mut unseen_block_receiver) = mpsc::unbounded_channel();
        let mut unknown_parent_columns = UnknownParentColumns::default();
        let execution_fetches = Arc::new(ExecutionFetchReservations::default());
        let gossip_worker_budget = GossipWorkerBudget::for_current_runtime();
        let mut gossip_workers = GossipWorkers::start(
            beacon_chain.clone(),
            cached_db.clone(),
            p2p_sender.clone(),
            pending_item_sender.clone(),
            hint_sender.clone(),
            &gossip_worker_budget,
        );
        let mut column_workers = GossipWorkers::start(
            beacon_chain.clone(),
            cached_db.clone(),
            p2p_sender.clone(),
            pending_item_sender.clone(),
            hint_sender.clone(),
            &gossip_worker_budget,
        );
        let (unknown_parent_sender, mut unknown_parent_receiver) = mpsc::channel(MAX_LOOKUPS);
        let on_valid_block: OnValidBlock = {
            let beacon_chain = beacon_chain.clone();
            let cached_db = cached_db.clone();
            let p2p_sender = p2p_sender.clone();
            let execution_fetches = execution_fetches.clone();
            Arc::new(move |block| {
                if fetch_execution_blobs
                    && !block.message.body.blob_kzg_commitments.is_empty()
                    && execution_fetches.reserve(block.message.tree_hash_root())
                {
                    inc_int_counter_vec(&BEACON_EXECUTION_COLUMN_FETCHES_TOTAL, &["gossip"]);
                    spawn_execution_column_fetch(&beacon_chain, &cached_db, &p2p_sender, block);
                }
            })
        };
        let mut block_workers = GossipWorkers::start_blocks(
            beacon_chain.clone(),
            cached_db.clone(),
            p2p_sender.clone(),
            pending_item_sender,
            unknown_parent_sender,
            on_valid_block,
        );
        let mut syncer_handle = block_range_syncer.start();
        // Avoid polling a completed JoinHandle after the syncer has caught up.
        let mut syncer_active = true;
        // Kept alive (not dropped) once synced, so the periodic re-check can restart it later.
        let mut idle_syncer: Option<BlockRangeSyncer> = None;
        // Historical blocks are only downloaded while forward sync has nothing to do.
        let backfill = BackfillSyncer::spawn_with_config(
            ream_db.clone(),
            p2p_sender.0.clone(),
            network_state.clone(),
            executor.clone(),
            backfill_config,
            !disable_backfill_rate_limiting,
            backfill_custody,
        )
        .unwrap_or_else(|err| {
            error!("Failed to start block backfill: {err}");
            None
        });
        let set_backfill_running = |running: bool| {
            if let Some(backfill) = &backfill {
                backfill.set_running(running);
            }
        };
        loop {
            tokio::select! {
                // Drive unknown-parent lookup actions and results.
                _ = std::future::ready(()), if unknown_parent_lookups.has_dispatchable_action() => {
                    if let Some(action) = unknown_parent_lookups.next_action() {
                        spawn_unknown_parent_action(
                            action,
                            beacon_chain.clone(),
                            cached_db.clone(),
                            p2p_sender.clone(),
                            unknown_parent_update_sender.clone(),
                        );
                    }
                }
                Some(update) = unknown_parent_update_receiver.recv() => {
                    let before = unknown_parent_lookups.len();
                    let completed = matches!(&update, UnknownParentLookupUpdate::BlockImported { .. });
                    let failed_download = match &update {
                        UnknownParentLookupUpdate::DownloadFailed { requested_root, .. } => Some(*requested_root),
                        _ => None,
                    };
                    apply_unknown_parent_update(
                        &mut unknown_parent_lookups,
                        &beacon_chain,
                        &network_state,
                        &mut lookup_refusals,
                        update,
                    ).await;
                    // A lookup that gave up may be hinted again by later gossip.
                    if let Some(block_root) = failed_download
                        && !unknown_parent_lookups.contains(&block_root)
                    {
                        cached_db.hinted_block_roots.write().await.pop(&block_root);
                    }
                    record_removed_lookup_entries(
                        UNKNOWN_PARENT_LOOKUP,
                        if completed { "completed" } else { "failed" },
                        before,
                        unknown_parent_lookups.len(),
                    );
                }
                // Drive pending-availability lookup actions and results.
                permit = block_lookup_action_sender.reserve(), if block_lookup_worker_active
                    && block_lookup_coordinator.pending_action_count() > 0
                    && block_lookup_coordinator.in_flight_action_count() == 0 => {
                    match permit {
                        Ok(permit) => {
                            if let Some(action) = block_lookup_coordinator.next_action() {
                                permit.send(action);
                            }
                        }
                        Err(err) => {
                            block_lookup_worker_active = false;
                            let before = block_lookup_coordinator.pending_entry_count();
                            block_lookup_coordinator.fail_in_flight_action();
                            record_removed_lookup_entries(
                                PENDING_AVAILABILITY_LOOKUP,
                                "failed",
                                before,
                                block_lookup_coordinator.pending_entry_count(),
                            );
                            error!("Block lookup worker action channel closed: {err}");
                        }
                    }
                }
                update = block_lookup_update_receiver.recv(), if block_lookup_worker_active => {
                    match update {
                        Some(update) => {
                            let pending_before = block_lookup_coordinator.pending_entry_count();
                            let unknown_before = unknown_parent_lookups.len();
                            let failed_block_root = match &update {
                                crate::block_lookup::CoordinatorUpdate::BlockFailed {
                                    block_root,
                                    ..
                                } => Some(*block_root),
                                _ => None,
                            };
                            if let Some(block_root) = failed_block_root {
                                unknown_parent_lookups.block_failed_elsewhere(block_root);
                            }
                            apply_coordinator_update(&mut block_lookup_coordinator, update);
                            record_removed_lookup_entries(
                                PENDING_AVAILABILITY_LOOKUP,
                                if failed_block_root.is_some() { "failed" } else { "completed" },
                                pending_before,
                                block_lookup_coordinator.pending_entry_count(),
                            );
                            record_removed_lookup_entries(
                                UNKNOWN_PARENT_LOOKUP,
                                "failed",
                                unknown_before,
                                unknown_parent_lookups.len(),
                            );
                        }
                        None => {
                            block_lookup_worker_active = false;
                            let before = block_lookup_coordinator.pending_entry_count();
                            block_lookup_coordinator.fail_in_flight_action();
                            record_removed_lookup_entries(
                                PENDING_AVAILABILITY_LOOKUP,
                                "failed",
                                before,
                                block_lookup_coordinator.pending_entry_count(),
                            );
                            error!("Block lookup worker result channel closed");
                        }
                    }
                }
                // Reconcile block imports with lookup and column-fetch state.
                import_event = block_import_receiver.recv(), if block_import_receiver_active => {
                    match import_event {
                        Ok(event) => {
                            let pending_before = block_lookup_coordinator.pending_entry_count();
                            let unknown_before = unknown_parent_lookups.len();
                            apply_block_import_event(&mut block_lookup_coordinator, event);
                            match event {
                                ream_chain_beacon::beacon_chain::BlockImportEvent::Imported { block_root } => {
                                    unknown_parent_lookups.block_imported(block_root);
                                    column_fetch_tracker.remove(&block_root);
                                    replay_unknown_parent_columns(&mut unknown_parent_columns, &column_workers, block_root);
                                    if let Some(slot) = state_advance_slot
                                        && beacon_chain.head().is_ok_and(|head| head.current_slot == slot)
                                    {
                                        spawn_state_advance(&beacon_chain, slot);
                                    }
                                }
                                ream_chain_beacon::beacon_chain::BlockImportEvent::PendingAvailability { block_root } => {
                                    unknown_parent_lookups.block_pending_availability(block_root);
                                    replay_unknown_parent_columns(&mut unknown_parent_columns, &column_workers, block_root);
                                    if fetch_execution_blobs {
                                        spawn_pending_execution_column_fetch(
                                            &beacon_chain,
                                            &cached_db,
                                            &p2p_sender,
                                            &execution_fetches,
                                            block_root,
                                        );
                                    }
                                    // Gossip will not redeliver columns for a block that is no
                                    // longer near the head, so fetch them regardless of which
                                    // ingress path left this block pending.
                                    column_fetch_tracker.enqueue(block_root);
                                    spawn_queued_column_fetches(
                                        &mut column_fetch_tracker,
                                        &beacon_chain,
                                        &p2p_sender,
                                        &network_state,
                                        &column_fetch_done_sender,
                                    );
                                }
                                ream_chain_beacon::beacon_chain::BlockImportEvent::ReconstructionReady { block_root } => {
                                    spawn_column_reconstruction(&beacon_chain, &cached_db, &p2p_sender, block_root);
                                }
                            }
                            record_removed_lookup_entries(
                                PENDING_AVAILABILITY_LOOKUP,
                                "completed",
                                pending_before,
                                block_lookup_coordinator.pending_entry_count(),
                            );
                            record_removed_lookup_entries(
                                UNKNOWN_PARENT_LOOKUP,
                                "completed",
                                unknown_before,
                                unknown_parent_lookups.len(),
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "Block import notifications lagged; reconciling pending parents");
                            let mut roots = block_lookup_coordinator.reconciliation_roots();
                            roots.extend(unknown_parent_lookups.reconciliation_roots());
                            roots.sort_unstable();
                            roots.dedup();
                            let reconciliation = reconcile_block_lookup_state(
                                &beacon_chain,
                                roots,
                            )
                            .await;
                            let pending_before = block_lookup_coordinator.pending_entry_count();
                            let unknown_before = unknown_parent_lookups.len();
                            for block_root in reconciliation.imported_roots {
                                block_lookup_coordinator.parent_imported(block_root);
                                unknown_parent_lookups.block_imported(block_root);
                                replay_unknown_parent_columns(&mut unknown_parent_columns, &column_workers, block_root);
                            }
                            for block_root in reconciliation.pending_availability_roots {
                                replay_unknown_parent_columns(&mut unknown_parent_columns, &column_workers, block_root);
                                block_lookup_coordinator
                                    .mark_block_pending_availability(block_root);
                                unknown_parent_lookups.block_pending_availability(block_root);
                                column_fetch_tracker.enqueue(block_root);
                            }
                            spawn_queued_column_fetches(
                                &mut column_fetch_tracker,
                                &beacon_chain,
                                &p2p_sender,
                                &network_state,
                                &column_fetch_done_sender,
                            );
                            // Skipped events may include a ReconstructionReady, which is sent
                            // once per block.
                            for block_root in beacon_chain.reconstructable_pending_blocks().await {
                                spawn_column_reconstruction(&beacon_chain, &cached_db, &p2p_sender, block_root);
                            }
                            record_removed_lookup_entries(
                                PENDING_AVAILABILITY_LOOKUP,
                                "completed",
                                pending_before,
                                block_lookup_coordinator.pending_entry_count(),
                            );
                            record_removed_lookup_entries(
                                UNKNOWN_PARENT_LOOKUP,
                                "completed",
                                unknown_before,
                                unknown_parent_lookups.len(),
                            );
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            block_import_receiver_active = false;
                            error!("Block import notification channel closed");
                        }
                    }
                }
                // Continue queued data-column fetches.
                Some((block_root, peer, outcome)) = column_fetch_done_receiver.recv() => {
                    let outcome_label = match outcome {
                        ColumnFetchOutcome::Complete => "complete",
                        ColumnFetchOutcome::Incomplete => "incomplete",
                        ColumnFetchOutcome::Retryable => "retryable",
                    };
                    inc_int_counter_vec(
                        &BEACON_DATA_COLUMN_FETCH_ATTEMPTS_TOTAL,
                        &[outcome_label],
                    );
                    column_fetch_tracker.finish(
                        block_root,
                        peer,
                        outcome,
                        std::time::Instant::now(),
                    );
                    spawn_queued_column_fetches(
                        &mut column_fetch_tracker,
                        &beacon_chain,
                        &p2p_sender,
                        &network_state,
                        &column_fetch_done_sender,
                    );
                }
                // Restart range sync until the finalized target is reached.
                result = &mut syncer_handle, if syncer_active => {
                    syncer_active = false;
                    match result {
                        Ok(Ok((mut block_range_syncer, sync_result))) => {
                            if let Err(err) = sync_result {
                                warn!("Block range sync failed: {err:?}");
                            }
                            if block_range_syncer.is_synced_to_head_slot().await {
                                idle_syncer = Some(block_range_syncer);
                                set_backfill_running(true);
                            } else {
                                syncer_handle = block_range_syncer.start();
                                syncer_active = true;
                            }
                        }
                        Ok(Err(err)) => {
                            // Executor shutdown cancelled the task; do not re-arm.
                            error!("Block range syncer task cancelled: {err}");
                        }
                        Err(err) => {
                            error!("Block range syncer task panicked, reconstructing: {err}");
                            sleep(Duration::from_secs(5)).await;
                            let block_range_syncer = BlockRangeSyncer::new(
                                beacon_chain.clone(),
                                p2p_sender.0.clone(),
                                network_state.clone(),
                                executor.clone(),
                            );
                            syncer_handle = block_range_syncer.start();
                            syncer_active = true;
                        }
                    }
                }
                _ = resync_check_interval.tick(), if !syncer_active && idle_syncer.is_some() => {
                    let mut block_range_syncer = idle_syncer
                        .take()
                        .expect("checked by the select guard above");
                    if block_range_syncer.is_synced_to_head_slot().await {
                        idle_syncer = Some(block_range_syncer);
                    } else {
                        set_backfill_running(false);
                        syncer_handle = block_range_syncer.start();
                        syncer_active = true;
                    }
                }
                _ = state_advance_interval.tick() => {
                    if let Ok(head) = beacon_chain.head() {
                        state_advance_slot = Some(head.current_slot);
                        spawn_state_advance(&beacon_chain, head.current_slot);
                    }
                }
                // Advance the chain clock and prune stale lookup state.
                _ = interval.tick() => {
                    let time = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("correct time")
                        .as_secs();

                    if let Err(err) =  beacon_chain.process_tick(time).await {
                        error!("Failed to process gossipsub tick: {err}");
                    }

                    // Head, finality, fork digest and historical coverage all move after
                    // startup; peers pick who to ask from what we advertise.
                    match beacon_chain.build_status_request().await {
                        Ok(status) => *network_state.status.write() = status,
                        Err(err) => warn!("Failed to refresh Status: {err}"),
                    }

                    // Started ahead of genesis: p2p, discovery and the HTTP API all stay up so
                    // the gossip mesh is formed by slot 0. `on_tick` is a no-op until then, but
                    // announce the wait so a node that looks idle is visibly just early.
                    // Everything below still runs: skipping it would freeze the store's slot
                    // clock and make blocks arriving right after genesis look future-dated.
                    if let Ok(genesis_time) = {
                        let store = beacon_chain.store.lock().await;
                        store.db.genesis_time_provider().get()
                    } && time < genesis_time
                    {
                        let remaining = genesis_time - time;
                        warn!(
                            "Waiting for genesis in {:02}:{:02}",
                            remaining / 60,
                            remaining % 60,
                        );
                    }

                    let slots = {
                        let store = beacon_chain.store.lock().await;
                        (
                            store.get_current_slot(),
                            store.db.finalized_checkpoint_provider().get(),
                            store.data_availability_checker.pending_block_roots(),
                        )
                    };
                    match slots {
                        (Ok(current_slot), Ok(finalized_checkpoint), mut pending_roots) => {
                            update_validator_custody(
                                &mut validator_custody,
                                &beacon_chain,
                                &p2p_sender,
                                current_slot,
                            )
                            .await;
                            match pending_anchor_for_recovery(&beacon_chain, current_slot).await {
                                Ok(Some(root)) => pending_roots.push(root),
                                Ok(None) => {},
                                Err(err) => warn!(%err, "Cannot schedule anchor column recovery"),
                            }
                            let finalized_slot =
                                compute_start_slot_at_epoch(finalized_checkpoint.epoch);
                            if maintenance_task.as_ref().is_some_and(|task| task.is_finished())
                                && let Some(task) = maintenance_task.take() {
                                    match task.await {
                                        Ok(Ok(())) => {},
                                        result => { warn!(?result, "Column retention maintenance failed"); maintenance_epoch = None; },
                                    }
                            }
                            let epoch = current_slot / SLOTS_PER_EPOCH;
                            if maintenance_task.is_none() && maintenance_epoch != Some(epoch) {
                                maintenance_epoch = Some(epoch);
                                let db = ream_db.clone();
                                maintenance_task = Some(executor.spawn_blocking(move || {
                                    maintain_historical_sidecars(&db, current_slot, finalized_slot, blob_retention_epochs)
                                }));
                            }

                            let pruned_pending = block_lookup_coordinator.prune(
                                current_slot,
                                finalized_slot,
                            );
                            if pruned_pending > 0 {
                                inc_int_counter_vec_by(
                                    &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                                    pruned_pending as u64,
                                    &[PENDING_AVAILABILITY_LOOKUP, "pruned"],
                                );
                            }
                            let pruned_unknown = unknown_parent_lookups
                                .prune()
                                .saturating_add(unknown_parent_lookups.prune_finalized(finalized_slot));
                            if pruned_unknown > 0 {
                                inc_int_counter_vec_by(
                                    &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                                    pruned_unknown as u64,
                                    &[UNKNOWN_PARENT_LOOKUP, "pruned"],
                                );
                            }
                            unknown_parent_columns.prune(current_slot);
                            column_fetch_tracker.retain_pending(&pending_roots);
                            for block_root in pending_roots {
                                column_fetch_tracker.enqueue(block_root);
                            }
                            spawn_queued_column_fetches(
                                &mut column_fetch_tracker,
                                &beacon_chain,
                                &p2p_sender,
                                &network_state,
                                &column_fetch_done_sender,
                            );
                            // A reconstruction that gave up after its retries is announced again
                            // only when another column arrives, which may never happen.
                            for block_root in beacon_chain.reserve_unannounced_reconstructions().await {
                                spawn_column_reconstruction(&beacon_chain, &cached_db, &p2p_sender, block_root);
                            }
                        }
                        (Err(err), _, _) => error!("Failed to read current slot: {err}"),
                        (_, Err(err), _) => error!("Failed to read finalized checkpoint: {err}"),
                    }
                }
                // Handle inbound network events.
                Some(err) = gossip_workers.stopped() => {
                    // A gossip worker only stops by panicking. Fail the service, as a panic on
                    // this loop would, rather than keep running with fewer workers.
                    if err.is_panic() {
                        std::panic::resume_unwind(err.into_panic());
                    }
                    error!("A gossip worker stopped: {err}");
                    return;
                }
                Some(err) = block_workers.stopped() => {
                    // A block worker also stops only by panicking.
                    if err.is_panic() {
                        std::panic::resume_unwind(err.into_panic());
                    }
                    error!("A gossip block worker stopped: {err}");
                    return;
                }
                // Blocks the block workers found without a known parent.
                Some(work) = unknown_parent_receiver.recv() => {
                    start_unknown_parent_lookup(
                        work.block,
                        work.propagation_source,
                        &network_state,
                        &lookup_refusals,
                        &mut unknown_parent_lookups,
                    );
                }
                Some(err) = column_workers.stopped() => {
                    // A column worker also stops only by panicking.
                    if err.is_panic() {
                        std::panic::resume_unwind(err.into_panic());
                    }
                    error!("A gossip column worker stopped: {err}");
                    return;
                }
                // Gossip that refers to blocks not seen yet.
                Some(hint) = hint_receiver.recv() => {
                    match hint {
                        GossipHint::UnknownParentColumn { column, peer } => {
                            let current_slot = beacon_chain.head().map_or(0, |head| head.current_slot);
                            unknown_parent_columns.insert(*column, peer, current_slot);
                        }
                        GossipHint::UnseenBlock(unseen) => {
                            schedule_unseen_block_lookup(unseen, &unseen_block_sender);
                        }
                    }
                }
                Some(unseen) = unseen_block_receiver.recv() => {
                    start_unseen_block_lookup(
                        unseen,
                        &beacon_chain,
                        &network_state,
                        &lookup_refusals,
                        &mut unknown_parent_lookups,
                        &block_lookup_coordinator,
                    )
                    .await;
                }
                // Lookup work from columns that the column workers validated.
                Some(item) = pending_item_receiver.recv() => {
                    insert_pending_gossip_item(
                        &beacon_chain,
                        &mut block_lookup_coordinator,
                        &mut unknown_parent_lookups,
                        item,
                    )
                    .await;
                }
                Some(event) = manager_receiver.recv() => {
                    match event {
                        // Handles Gossipsub messages from other peers.
                        ReamNetworkEvent::GossipsubMessage { propagation_source, message_id, message }
                            if is_data_column(&message.topic) =>
                        {
                            column_workers.submit(message, message_id, propagation_source);
                        }
                        ReamNetworkEvent::GossipsubMessage { propagation_source, message_id, message }
                            if is_handled_concurrently(&message.topic) =>
                        {
                            gossip_workers.submit(message, message_id, propagation_source);
                        }
                        ReamNetworkEvent::GossipsubMessage { propagation_source, message_id, message }
                            if is_gossip_block(&message.topic) =>
                        {
                            block_workers.submit(message, message_id, propagation_source);
                        }
                        ReamNetworkEvent::GossipsubMessage { propagation_source, message_id, message } => {
                            let mut pending_item = None;
                            let mut unknown_parent_block = None;
                            let mut hints = Vec::new();
                            let acceptance = handle_gossipsub_message(
                                message,
                                &beacon_chain,
                                &cached_db,
                                &mut pending_item,
                                &mut unknown_parent_block,
                                &mut hints,
                                propagation_source,
                                |block| {
                                    if fetch_execution_blobs && execution_fetches.reserve(block.message.tree_hash_root()) {
                                        spawn_execution_column_fetch(&beacon_chain, &cached_db, &p2p_sender, block);
                                    }
                                },
                            ).await;
                            for hint in hints {
                                let _ = hint_sender.try_send(hint);
                            }
                            p2p_sender.report_gossip_validation(
                                message_id,
                                propagation_source,
                                acceptance,
                            );

                            if let Some(unknown) = unknown_parent_block {
                                start_unknown_parent_lookup(
                                    unknown,
                                    propagation_source,
                                    &network_state,
                                    &lookup_refusals,
                                    &mut unknown_parent_lookups,
                                );
                            }

                            if let Some(item) = pending_item {
                                insert_pending_gossip_item(
                                    &beacon_chain,
                                    &mut block_lookup_coordinator,
                                    &mut unknown_parent_lookups,
                                    item,
                                )
                                .await;
                            }
                        }
                        // Handles Req/Resp messages from other peers.
                        ReamNetworkEvent::RequestMessage { peer_id, stream_id, connection_id, message } =>
                            handle_req_resp_message(peer_id, stream_id, connection_id, message, &p2p_sender, &ream_db, network_state.clone()).await,
                        ReamNetworkEvent::PeerDisconnected(peer_id) => {
                            column_fetch_tracker.peer_disconnected(peer_id);
                        }
                        // Log and skip unrecognized requests.
                        unhandled_request => {
                            info!("Unhandled request: {unhandled_request:?}");
                        }
                    }
                }
            }
            update_lookup_gauges(
                &block_lookup_coordinator,
                &unknown_parent_lookups,
                &column_fetch_tracker,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_head_state_is_advanced_in_the_last_slot_of_each_epoch() {
        assert_eq!(epoch_to_advance_into(SLOTS_PER_EPOCH - 1), Some(1));
        assert_eq!(epoch_to_advance_into(10 * SLOTS_PER_EPOCH - 1), Some(10));
        assert_eq!(epoch_to_advance_into(10 * SLOTS_PER_EPOCH), None);
        assert_eq!(epoch_to_advance_into(10 * SLOTS_PER_EPOCH - 2), None);
    }

    #[test]
    fn the_slot_tick_runs_just_after_each_slot_start() {
        let genesis = 1_000;
        let at = |seconds: u64, millis: u64| {
            Duration::from_secs(seconds) + Duration::from_millis(millis)
        };
        // Mid-slot: wait for the next slot start.
        assert_eq!(
            until_next_slot_tick(genesis, 12, at(1_005, 500)),
            at(6, 520)
        );
        // Exactly at a slot start: run now, after the margin.
        assert_eq!(
            until_next_slot_tick(genesis, 12, at(1_012, 0)),
            SLOT_TICK_DELAY
        );
        // Just after a slot start: wait for the following one.
        assert_eq!(until_next_slot_tick(genesis, 12, at(1_012, 1)), at(12, 19));
        // Before genesis: wait for genesis.
        assert_eq!(until_next_slot_tick(genesis, 12, at(990, 0)), at(10, 20));
    }
}

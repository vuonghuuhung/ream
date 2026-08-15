use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;
use libp2p::PeerId;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_misc::{
    constants::beacon::NUM_CUSTODY_GROUPS, misc::compute_start_slot_at_epoch,
};
use ream_discv5::{
    config::DiscoveryConfig,
    subnet::{AttestationSubnets, CustodyGroupCount, SyncCommitteeSubnets},
};
use ream_executor::ReamExecutor;
use ream_fork_choice_beacon::data_availability::AvailabilityEntryStatus;
use ream_metrics::{
    BEACON_BLOCK_LOOKUP_ENTRIES, BEACON_BLOCK_LOOKUP_EVENTS_TOTAL, BEACON_CUSTODY_GROUPS,
    BEACON_DATA_COLUMN_FETCH_ATTEMPTS_TOTAL, BEACON_DATA_COLUMN_FETCH_DURATION_SECONDS,
    BEACON_DATA_COLUMN_FETCH_ENTRIES, inc_int_counter_vec, inc_int_counter_vec_by,
    observe_histogram, set_int_gauge_vec,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::{
    config::NetworkConfig,
    network::beacon::{Network, ReamNetworkEvent, network_state::NetworkState},
};
use ream_storage::{
    cache::BeaconCacheDB,
    db::beacon::BeaconDB,
    tables::{field::REDBField, table::REDBTable},
};
use ream_sync_committee_pool::SyncCommitteePool;
use ream_syncer::{
    block_range::BlockRangeSyncer,
    unknown_parent_lookups::{MAX_LOOKUPS, UnknownBlockMeta, UnknownParentLookupCoordinator},
};
use tokio::{sync::mpsc, time::interval};
use tracing::{error, info, warn};
use tree_hash::TreeHash;

use crate::{
    block_lookup::{
        BlockLookupConfig, BlockLookupCoordinator, PendingGossipItem, apply_block_import_event,
        apply_coordinator_update, insert_pending_item, log_insert_outcome,
        spawn_block_lookup_worker,
    },
    config::ManagerConfig,
    data_availability_fetch::{ColumnFetchOutcome, ColumnFetchTracker, fetch_missing_columns},
    gossipsub::handle::{handle_gossipsub_message, init_gossipsub_config_with_topics},
    p2p_sender::P2PSender,
    req_resp::handle_req_resp_message,
    unknown_parent_lookup::{
        UnknownParentLookupUpdate, apply_unknown_parent_update, spawn_unknown_parent_action,
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
}

struct ReconciledBlockLookupState {
    imported_roots: Vec<alloy_primitives::B256>,
    pending_availability_roots: Vec<alloy_primitives::B256>,
}

fn spawn_queued_column_fetches(
    tracker: &mut ColumnFetchTracker,
    beacon_chain: &Arc<BeaconChain>,
    p2p_sender: &P2PSender,
    network_state: &NetworkState,
    done_sender: &mpsc::UnboundedSender<(B256, PeerId, ColumnFetchOutcome)>,
) {
    let connected_peers = network_state
        .connected_peers()
        .into_iter()
        .map(|peer| peer.peer_id)
        .collect::<Vec<_>>();
    while let Some((block_root, peer)) =
        tracker.next_fetch(&connected_peers, std::time::Instant::now())
    {
        let beacon_chain = beacon_chain.clone();
        let p2p_sender = p2p_sender.clone();
        let done_sender = done_sender.clone();
        tokio::spawn(async move {
            let started_at = std::time::Instant::now();
            let outcome = fetch_missing_columns(&beacon_chain, &p2p_sender, block_root, peer).await;
            observe_histogram(
                &BEACON_DATA_COLUMN_FETCH_DURATION_SECONDS,
                started_at.elapsed().as_secs_f64(),
            );
            let _ = done_sender.send((block_root, peer, outcome));
        });
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
            .get(*block_root)
            .is_ok_and(|block| block.is_some());
        let has_state = store
            .db
            .state_provider()
            .get(*block_root)
            .is_ok_and(|state| state.is_some());
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

        // Ream's DA checker currently runs as a supernode and requires every custody group.
        let custody_group_count = CustodyGroupCount(NUM_CUSTODY_GROUPS);
        BEACON_CUSTODY_GROUPS.set(custody_group_count.0 as i64);

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
            attestation_subnets: AttestationSubnets::new(),
            sync_committee_subnets: SyncCommitteeSubnets::new(),
            // Must match the count advertised in our MetaData: peers cross-check the ENR
            // `cgc` against it and treat a mismatch, or a value below CUSTODY_REQUIREMENT,
            // as a fault worth banning us for.
            custody_group_count,
        };

        let gossipsub_config = init_gossipsub_config_with_topics(config.gossipsub_history_length);

        let network_config = NetworkConfig {
            discv5_config,
            gossipsub_config,
            data_dir: ream_directory,
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
            ..
        } = self;

        let mut interval = interval(Duration::from_secs(
            beacon_network_spec().seconds_per_slot(),
        ));
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
        let (unknown_parent_update_sender, mut unknown_parent_update_receiver) =
            mpsc::channel(MAX_LOOKUPS);
        let mut column_fetch_tracker = ColumnFetchTracker::default();
        let (column_fetch_done_sender, mut column_fetch_done_receiver) =
            mpsc::unbounded_channel::<(B256, PeerId, ColumnFetchOutcome)>();
        let mut syncer_handle = block_range_syncer.start();
        // Avoid polling a completed JoinHandle after the syncer has caught up.
        let mut syncer_active = true;
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
                    apply_unknown_parent_update(
                        &mut unknown_parent_lookups,
                        &beacon_chain,
                        update,
                    ).await;
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
                                }
                                ream_chain_beacon::beacon_chain::BlockImportEvent::PendingAvailability { block_root } => {
                                    unknown_parent_lookups.block_pending_availability(block_root);
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
                            }
                            for block_root in reconciliation.pending_availability_roots {
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
                    let joined_result = match result {
                        Ok(joined_result) => joined_result,
                        Err(err) => {
                            error!("Block range syncer failed to join task: {err}");
                            continue;
                        }
                    };

                    let thread_result = match joined_result {
                        Ok(result) => result,
                        Err(err) => {
                            error!("Block range syncer thread failed: {err}");
                            continue;
                        }
                    };

                    let block_range_syncer = match thread_result {
                        Ok(syncer) => syncer,
                        Err(err) => {
                            error!("Block range syncer failed to start: {err}");
                            continue;
                        }
                    };

                    if !block_range_syncer.is_synced_to_head_slot().await {
                        syncer_handle = block_range_syncer.start();
                        syncer_active = true;
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
                        (Ok(current_slot), Ok(finalized_checkpoint), pending_roots) => {
                            let finalized_slot =
                                compute_start_slot_at_epoch(finalized_checkpoint.epoch);
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
                        }
                        (Err(err), _, _) => error!("Failed to read current slot: {err}"),
                        (_, Err(err), _) => error!("Failed to read finalized checkpoint: {err}"),
                    }
                }
                // Handle inbound network events.
                Some(event) = manager_receiver.recv() => {
                    match event {
                        // Handles Gossipsub messages from other peers.
                        ReamNetworkEvent::GossipsubMessage { propagation_source, message_id, message } => {
                            let mut pending_item = None;
                            let mut unknown_parent_block = None;
                            let acceptance = handle_gossipsub_message(
                                message,
                                &beacon_chain,
                                &cached_db,
                                &p2p_sender,
                                &mut pending_item,
                                &mut unknown_parent_block,
                            ).await;
                            p2p_sender.report_gossip_validation(
                                message_id,
                                propagation_source,
                                acceptance,
                            );

                            if let Some(unknown) = unknown_parent_block {
                                let meta = UnknownBlockMeta {
                                    block_root: unknown.block.message.tree_hash_root(),
                                    parent_root: unknown.parent_root,
                                    slot: unknown.block.message.slot,
                                };
                                let before = unknown_parent_lookups.len();
                                let outcome = unknown_parent_lookups.insert_gossip_block(
                                    meta,
                                    unknown.block,
                                    propagation_source,
                                );
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

                            if let Some(item) = pending_item {
                                let is_block = matches!(&item, PendingGossipItem::Block { .. });
                                let block_root = match &item {
                                    PendingGossipItem::Block { block, .. } => {
                                        block.block().message.tree_hash_root()
                                    }
                                    PendingGossipItem::Column { column, .. } => {
                                        column.sidecar().signed_block_header.message.tree_hash_root()
                                    }
                                };
                                let current_slot = {
                                    let store = beacon_chain.store.lock().await;
                                    store.get_current_slot()
                                };
                                match current_slot {
                                    Ok(current_slot) => {
                                        let entry_existed = block_lookup_coordinator
                                            .contains_entry(&block_root);
                                        let entries_before =
                                            block_lookup_coordinator.pending_entry_count();
                                        let outcome = insert_pending_item(
                                            &mut block_lookup_coordinator,
                                            item,
                                            current_slot,
                                        );
                                        let retained = matches!(
                                            outcome,
                                            ream_syncer::block_lookups::InsertOutcome::Inserted
                                                | ream_syncer::block_lookups::InsertOutcome::Duplicate
                                        );
                                        match outcome {
                                            ream_syncer::block_lookups::InsertOutcome::Inserted
                                                if !entry_existed =>
                                            {
                                                inc_int_counter_vec(
                                                    &BEACON_BLOCK_LOOKUP_EVENTS_TOTAL,
                                                    &[PENDING_AVAILABILITY_LOOKUP, "created"],
                                                );
                                                let evicted = entries_before
                                                    .saturating_add(1)
                                                    .saturating_sub(
                                                        block_lookup_coordinator
                                                            .pending_entry_count(),
                                                    );
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
                                            unknown_parent_lookups
                                                .block_deferred_elsewhere(block_root);
                                        }
                                    }
                                    Err(err) => {
                                        error!("Failed to read current slot for pending gossip: {err}")
                                    }
                                }
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

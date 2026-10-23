use std::time::{SystemTime, UNIX_EPOCH};

use prometheus_exporter::prometheus::{
    Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, default_registry,
    register_histogram_with_registry, register_int_counter_vec_with_registry,
    register_int_counter_with_registry, register_int_gauge_vec_with_registry,
    register_int_gauge_with_registry,
};

use crate::common::{set_int_gauge, set_int_gauge_vec};

// Provisioning each metrics
lazy_static::lazy_static! {
    pub static ref BEACON_BACKFILL_BLOCK_FRONTIER_SLOT: IntGauge = register_int_gauge_with_registry!(
        "beacon_backfill_block_frontier_slot", "Oldest verified historical block slot", default_registry()
    ).expect("backfill frontier metric");
    pub static ref BEACON_BACKFILL_SIDECAR_FRONTIER_SLOT: IntGauge = register_int_gauge_with_registry!(
        "beacon_backfill_sidecar_frontier_slot", "First slot covered by historical columns", default_registry()
    ).expect("backfill frontier metric");
    pub static ref BEACON_BACKFILL_BLOCKS_COMMITTED_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_backfill_blocks_committed_total", "Historical blocks committed", default_registry()
    ).expect("backfill counter metric");
    pub static ref BEACON_BACKFILL_COLUMNS_COMMITTED_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_backfill_columns_committed_total", "Historical columns committed", default_registry()
    ).expect("backfill counter metric");
    pub static ref BEACON_COLUMNS_PRUNED_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_columns_pruned_total", "Data columns pruned", default_registry()
    ).expect("backfill counter metric");
    pub static ref BEACON_BACKFILL_PENDING_BYTES: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "beacon_backfill_pending_bytes", "Reserved SSZ bytes by backfill pass", &["kind"], default_registry()
    ).expect("backfill pending metric");
    pub static ref BEACON_BACKFILL_PEER_BANS_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_backfill_peer_bans_total", "Backfill peer bans", &["reason"], default_registry()
    ).expect("backfill bans metric");
    pub static ref BEACON_BACKFILL_VERIFY_SECONDS: Histogram = register_histogram_with_registry!(
        "beacon_backfill_verify_seconds", "Historical signature and column verification seconds", default_registry()
    ).expect("backfill verify metric");

    // Node Info Metrics
    pub static ref BEACON_NODE_INFO: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "beacon_node_info", "Node information (always 1)", &["name", "version"], default_registry()
    ).expect("failed to create BEACON_NODE_INFO int gauge vec");

    pub static ref BEACON_NODE_START_TIME_SECONDS: IntGauge = register_int_gauge_with_registry!(
        "beacon_node_start_time_seconds", "Start timestamp", default_registry()
    ).expect("failed to create BEACON_NODE_START_TIME_SECONDS int gauge");

    // Sync / Head Metrics (beacon-metrics interop spec)
    pub static ref BEACON_HEAD_SLOT: IntGauge = register_int_gauge_with_registry!(
        "beacon_head_slot", "Latest slot of the beacon chain", default_registry()
    ).expect("failed to create BEACON_HEAD_SLOT int gauge");

    pub static ref BEACON_HEAD_EPOCH: IntGauge = register_int_gauge_with_registry!(
        "beacon_head_epoch", "Current head epoch of the beacon chain", default_registry()
    ).expect("failed to create BEACON_HEAD_EPOCH int gauge");

    pub static ref BEACON_FINALIZED_EPOCH: IntGauge = register_int_gauge_with_registry!(
        "beacon_finalized_epoch", "Current finalized epoch", default_registry()
    ).expect("failed to create BEACON_FINALIZED_EPOCH int gauge");

    pub static ref BEACON_CURRENT_JUSTIFIED_EPOCH: IntGauge = register_int_gauge_with_registry!(
        "beacon_current_justified_epoch", "Current justified epoch", default_registry()
    ).expect("failed to create BEACON_CURRENT_JUSTIFIED_EPOCH int gauge");

    pub static ref BEACON_PREVIOUS_JUSTIFIED_EPOCH: IntGauge = register_int_gauge_with_registry!(
        "beacon_previous_justified_epoch", "Current previously justified epoch", default_registry()
    ).expect("failed to create BEACON_PREVIOUS_JUSTIFIED_EPOCH int gauge");

    pub static ref BEACON_CURRENT_ACTIVE_VALIDATORS: IntGauge = register_int_gauge_with_registry!(
        "beacon_current_active_validators", "Current total active validators", default_registry()
    ).expect("failed to create BEACON_CURRENT_ACTIVE_VALIDATORS int gauge");

    pub static ref BEACON_SHUFFLING_CACHE_MISSES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_shuffling_cache_misses_total",
        "Epoch attester shufflings computed because no cached copy was available",
        default_registry()
    ).expect("failed to create BEACON_SHUFFLING_CACHE_MISSES_TOTAL int counter");

    pub static ref BEACON_REORGS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_reorgs_total", "Total number of chain reorganizations", default_registry()
    ).expect("failed to create BEACON_REORGS_TOTAL int counter");

    // Spec types this as a Gauge (not a Counter) despite the `_total` suffix — keep it a
    // gauge to stay conformant even though the naming looks counter-like.
    pub static ref BEACON_PROCESSED_DEPOSITS_TOTAL: IntGauge = register_int_gauge_with_registry!(
        "beacon_processed_deposits_total", "Total number of deposits processed", default_registry()
    ).expect("failed to create BEACON_PROCESSED_DEPOSITS_TOTAL int gauge");

    // Peer / Network Metrics
    // `BEACON_PEER_COUNT` is Ream's own metric name; `LIBP2P_PEERS` is the
    // beacon-metrics interop-spec name (mirrors Lighthouse's "_INTEROP" alias
    // pattern). Always update both via `set_peer_count()` below, never directly,
    // or the two will drift apart.
    pub static ref BEACON_PEER_COUNT: IntGauge = register_int_gauge_with_registry!(
        "beacon_connected_peers", "Number of connected peers", default_registry()
    ).expect("failed to create BEACON_PEER_COUNT int gauge");

    pub static ref LIBP2P_PEERS: IntGauge = register_int_gauge_with_registry!(
        "libp2p_peers", "Tracks the total number of libp2p peers", default_registry()
    ).expect("failed to create LIBP2P_PEERS int gauge");

    // PeerDAS: Data Column Sidecar Gossip Metrics
    pub static ref BEACON_DATA_COLUMN_SIDECAR_PROCESSING_REQUESTS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_column_sidecar_processing_requests_total",
        "Data column sidecars submitted for processing",
        default_registry()
    ).expect("failed to create BEACON_DATA_COLUMN_SIDECAR_PROCESSING_REQUESTS_TOTAL int counter");

    pub static ref BEACON_DATA_COLUMN_SIDECAR_PROCESSING_SUCCESSES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_column_sidecar_processing_successes_total",
        "Data column sidecars verified for gossip",
        default_registry()
    ).expect("failed to create BEACON_DATA_COLUMN_SIDECAR_PROCESSING_SUCCESSES_TOTAL int counter");

    pub static ref BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_gossip_pending_items_dropped_total",
        "Gossip columns waiting on their parent dropped because the manager loop's queue was full",
        default_registry()
    ).expect("failed to create BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL int counter");

    pub static ref BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_SKIPPED_COMPLETE_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_availability_reconstructions_skipped_complete_total",
        "Reconstructions skipped because every required column was stored before they ran",
        default_registry()
    ).expect("failed to create BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_SKIPPED_COMPLETE_TOTAL int counter");

    pub static ref BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_RUN_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_availability_reconstructions_run_total",
        "Reconstructions that rebuilt missing columns",
        default_registry()
    ).expect("failed to create BEACON_DATA_AVAILABILITY_RECONSTRUCTIONS_RUN_TOTAL int counter");

    pub static ref BEACON_DATA_AVAILABILITY_CROSS_SEEDED_COLUMNS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_availability_cross_seeded_columns_total",
        "Reconstructed columns published to their subnet meshes",
        default_registry()
    ).expect("failed to create BEACON_DATA_AVAILABILITY_CROSS_SEEDED_COLUMNS_TOTAL int counter");

    pub static ref BEACON_DATA_COLUMN_SIDECAR_GOSSIP_VERIFICATION_SECONDS: Histogram = {
        // Gossip verification is expected to be fast (sub-100ms typical case).
        // Starting point only — re-tune against real hardware benchmarks.
        let opts = HistogramOpts::new(
            "beacon_data_column_sidecar_gossip_verification_seconds",
            "Time spent verifying data column sidecars for gossip"
        ).buckets(vec![0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_DATA_COLUMN_SIDECAR_GOSSIP_VERIFICATION_SECONDS")
    };

    pub static ref BEACON_GOSSIP_VALIDATION_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_gossip_validation_total",
        "Gossip messages by topic kind and the validation result reported to gossipsub",
        &["topic", "result"],
        default_registry()
    ).expect("failed to create BEACON_GOSSIP_VALIDATION_TOTAL int counter vec");

    pub static ref BEACON_GOSSIPSUB_PEERS_BY_SCORE: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "beacon_gossipsub_peers_by_score",
        "Gossipsub peers by score band: graylisted, below_publish, below_gossip, negative or non_negative",
        &["band"],
        default_registry()
    ).expect("failed to create BEACON_GOSSIPSUB_PEERS_BY_SCORE int gauge vec");

    pub static ref BEACON_GOSSIPSUB_LOWEST_PEER_SCORE: IntGauge = register_int_gauge_with_registry!(
        "beacon_gossipsub_lowest_peer_score",
        "Lowest gossipsub score among connected peers, rounded",
        default_registry()
    ).expect("failed to create BEACON_GOSSIPSUB_LOWEST_PEER_SCORE int gauge");

    pub static ref BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_column_header_checks_total",
        "Data column headers checked against their parent state; the other columns of a block reuse the result",
        default_registry()
    ).expect("failed to create BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL int counter");

    // Block lookup recovery metrics
    pub static ref BEACON_BLOCK_LOOKUP_ENTRIES: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "beacon_block_lookup_entries",
        "Current number of retained block lookup entries by lookup kind",
        &["kind"],
        default_registry()
    ).expect("failed to create BEACON_BLOCK_LOOKUP_ENTRIES int gauge vec");

    pub static ref BEACON_BLOCK_LOOKUP_EVENTS_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_block_lookup_events_total",
        "Total block lookup lifecycle events by lookup kind and event",
        &["kind", "event"],
        default_registry()
    ).expect("failed to create BEACON_BLOCK_LOOKUP_EVENTS_TOTAL int counter vec");

    pub static ref BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_unknown_parent_columns_total",
        "Gossip columns that came before their parent block, by what became of them",
        &["event"],
        default_registry()
    ).expect("failed to create BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL int counter vec");

    pub static ref BEACON_UNSEEN_BLOCK_LOOKUPS_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_unseen_block_lookups_total",
        "Block roots that signed gossip referred to before the block came, by source and outcome",
        &["source", "outcome"],
        default_registry()
    ).expect("failed to create BEACON_UNSEEN_BLOCK_LOOKUPS_TOTAL int counter vec");

    pub static ref BEACON_EXECUTION_COLUMN_FETCHES_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_execution_column_fetches_total",
        "Column fetches from the execution client's blobs, by what started them",
        &["trigger"],
        default_registry()
    ).expect("failed to create BEACON_EXECUTION_COLUMN_FETCHES_TOTAL int counter vec");

    pub static ref BEACON_DATA_COLUMN_FETCH_ENTRIES: IntGaugeVec = register_int_gauge_vec_with_registry!(
        "beacon_data_column_fetch_entries",
        "Current number of data column fetch entries by state",
        &["state"],
        default_registry()
    ).expect("failed to create BEACON_DATA_COLUMN_FETCH_ENTRIES int gauge vec");

    pub static ref BEACON_DATA_COLUMN_FETCH_ATTEMPTS_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_data_column_fetch_attempts_total",
        "Total data column fetch attempts by outcome",
        &["outcome"],
        default_registry()
    ).expect("failed to create BEACON_DATA_COLUMN_FETCH_ATTEMPTS_TOTAL int counter vec");

    pub static ref BEACON_DATA_COLUMN_FETCH_DURATION_SECONDS: Histogram = {
        // Covers normal peer round trips through slow attempts approaching the request timeout.
        let opts = HistogramOpts::new(
            "beacon_data_column_fetch_duration_seconds",
            "Time spent requesting, verifying, and importing data columns from one peer"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_DATA_COLUMN_FETCH_DURATION_SECONDS")
    };

    // PeerDAS: Data Availability / Reconstruction Metrics
    pub static ref BEACON_DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_availability_reconstructed_columns_total",
        "Total count of reconstructed columns",
        default_registry()
    ).expect("failed to create BEACON_DATA_AVAILABILITY_RECONSTRUCTED_COLUMNS_TOTAL int counter");

    pub static ref BEACON_DATA_AVAILABILITY_RECONSTRUCTION_TIME_SECONDS: Histogram = {
        // Reconstruction can run into hundreds of ms to low seconds under load.
        let opts = HistogramOpts::new(
            "beacon_data_availability_reconstruction_time_seconds",
            "Time taken to reconstruct columns"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_DATA_AVAILABILITY_RECONSTRUCTION_TIME_SECONDS")
    };

    // PeerDAS: Data Column Sidecar Computation Metrics
    pub static ref BEACON_DATA_COLUMN_SIDECAR_COMPUTATION_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "beacon_data_column_sidecar_computation_seconds",
            "Time to compute data column sidecar (cells, proofs, inclusion proof)"
        ).buckets(vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_DATA_COLUMN_SIDECAR_COMPUTATION_SECONDS")
    };

    // PeerDAS: Inclusion proof verification metrics
    pub static ref BEACON_DATA_COLUMN_SIDECAR_INCLUSION_PROOF_VERIFICATION_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "beacon_data_column_sidecar_inclusion_proof_verification_seconds",
            "Time to verify data column sidecar inclusion proof"
        ).buckets(vec![0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_DATA_COLUMN_SIDECAR_INCLUSION_PROOF_VERIFICATION_SECONDS")
    };

    // PeerDAS: KZG Verification Metrics
    pub static ref BEACON_KZG_VERIFICATION_DATA_COLUMN_BATCH_SECONDS: Histogram = {
        // Scales with number of columns in the batch — wider range than a single-item check.
        let opts = HistogramOpts::new(
            "beacon_kzg_verification_data_column_batch_seconds",
           "Time spent verifying batched data column KZG proofs"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_KZG_VERIFICATION_DATA_COLUMN_BATCH_SECONDS")
    };

    // PeerDAS: Custody Metrics
    pub static ref BEACON_CUSTODY_GROUPS: IntGauge = register_int_gauge_with_registry!(
        "beacon_custody_groups", "Total number of custody groups within a node", default_registry()
    ).expect("failed to create BEACON_CUSTODY_GROUPS int gauge");

    pub static ref BEACON_CUSTODY_GROUPS_BACKFILLED: IntGauge = register_int_gauge_with_registry!(
        "beacon_custody_groups_backfilled", "Total number of custody groups backfilled by a node", default_registry()
    ).expect("failed to create BEACON_CUSTODY_GROUPS_BACKFILLED int gauge");

    // PeerDAS: Engine API — engine_getBlobsV2 Metrics
    pub static ref BEACON_ENGINE_GET_BLOBS_V2_REQUESTS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_engine_getBlobsV2_requests_total", "Total engine_getBlobsV2 requests sent", default_registry()
    ).expect("failed to create BEACON_ENGINE_GET_BLOBS_V2_REQUESTS_TOTAL int counter");

    pub static ref BEACON_ENGINE_GET_BLOBS_V2_RESPONSES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_engine_getBlobsV2_responses_total", "Total successful engine_getBlobsV2 responses received", default_registry()
    ).expect("failed to create BEACON_ENGINE_GET_BLOBS_V2_RESPONSES_TOTAL int counter");

    pub static ref BEACON_ENGINE_GET_BLOBS_V2_REQUEST_DURATION_SECONDS: Histogram = {
        // Round trip to the EL — expect low ms up to a couple seconds under load.
        let opts = HistogramOpts::new(
            "beacon_engine_getBlobsV2_request_duration_seconds",
            "Duration of engine_getBlobsV2 requests"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_ENGINE_GET_BLOBS_V2_REQUEST_DURATION_SECONDS")
    };

    // Columns built from blobs held by the execution client (Lighthouse's `beacon_blobs_from_el_*`)
    pub static ref BEACON_BLOBS_FROM_EL_HIT_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_blobs_from_el_hit_total", "Blocks whose blobs were all returned by the execution client", default_registry()
    ).expect("failed to create BEACON_BLOBS_FROM_EL_HIT_TOTAL int counter");

    pub static ref BEACON_BLOBS_FROM_EL_MISS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_blobs_from_el_miss_total", "Blocks with a blob the execution client did not have", default_registry()
    ).expect("failed to create BEACON_BLOBS_FROM_EL_MISS_TOTAL int counter");

    pub static ref BEACON_BLOBS_FROM_EL_ERROR_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_blobs_from_el_error_total", "Failed requests for blobs from the execution client", default_registry()
    ).expect("failed to create BEACON_BLOBS_FROM_EL_ERROR_TOTAL int counter");

    pub static ref BEACON_DATA_COLUMNS_FROM_EL_IMPORTED_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_data_columns_from_el_imported_total", "Data columns built from execution client blobs and imported", default_registry()
    ).expect("failed to create BEACON_DATA_COLUMNS_FROM_EL_IMPORTED_TOTAL int counter");

    // PeerDAS: Engine API — engine_get_blobs_v3 Metrics
    pub static ref BEACON_ENGINE_GET_BLOBS_V3_REQUESTS_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_engine_getBlobsV3_requests_total", "Total engine_getBlobsV3 requests sent", default_registry()
    ).expect("failed to create BEACON_ENGINE_GET_BLOBS_V3_REQUESTS_TOTAL int counter");

    pub static ref BEACON_ENGINE_GET_BLOBS_V3_COMPLETE_RESPONSES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_engine_getBlobsV3_complete_responses_total", "Total complete engine_getBlobsV3 responses", default_registry()
    ).expect("failed to create BEACON_ENGINE_GET_BLOBS_V3_COMPLETE_RESPONSES_TOTAL int counter");

    pub static ref BEACON_ENGINE_GET_BLOBS_V3_PARTIAL_RESPONSES_TOTAL: IntCounter = register_int_counter_with_registry!(
        "beacon_engine_getBlobsV3_partial_responses_total", "Total partial engine_getBlobsV3 responses", default_registry()
    ).expect("failed to create BEACON_ENGINE_GET_BLOBS_V3_PARTIAL_RESPONSES_TOTAL int counter");

    pub static ref BEACON_ENGINE_GET_BLOBS_V3_REQUEST_DURATION_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "beacon_engine_getBlobsV3_request_duration_seconds",
            "Duration of engine_getBlobsV3 requests"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_ENGINE_GET_BLOBS_V3_REQUEST_DURATION_SECONDS")
    };

    // PeerDAS: Partial Data Column Metrics (Cell-Level Dissemination)
    pub static ref BEACON_PARTIAL_MESSAGE_USEFUL_CELLS_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_partial_message_useful_cells_total", "Useful cells received via a partial message", &["column_index"], default_registry()
    ).expect("failed to create BEACON_PARTIAL_MESSAGE_USEFUL_CELLS_TOTAL int counter vec");

    pub static ref BEACON_PARTIAL_MESSAGE_CELLS_RECEIVED_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_partial_message_cells_received_total", "Total cells received via a partial message", &["column_index"], default_registry()
    ).expect("failed to create BEACON_PARTIAL_MESSAGE_CELLS_RECEIVED_TOTAL int counter vec");

    pub static ref BEACON_USEFUL_FULL_COLUMNS_RECEIVED_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_useful_full_columns_received_total", "Useful full columns received", &["column_index"], default_registry()
    ).expect("failed to create BEACON_USEFUL_FULL_COLUMNS_RECEIVED_TOTAL int counter vec");

    pub static ref BEACON_PARTIAL_MESSAGE_COLUMN_COMPLETIONS_TOTAL: IntCounterVec = register_int_counter_vec_with_registry!(
        "beacon_partial_message_column_completions_total", "Times a partial message first completed a column", &["column_index"], default_registry()
    ).expect("failed to create BEACON_PARTIAL_MESSAGE_COLUMN_COMPLETIONS_TOTAL int counter vec");

    pub static ref BEACON_STORE_LOCK_WAIT_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "beacon_store_lock_wait_seconds",
            "Time spent waiting to acquire the shared Store lock"
        ).buckets(vec![0.0001, 0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_STORE_LOCK_WAIT_SECONDS")
    };

    pub static ref BEACON_BLOCK_PROCESSING_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "beacon_block_processing_seconds",
            "Full runtime of process_block, lock acquisition through commit"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_BLOCK_PROCESSING_SECONDS")
    };

    pub static ref BEACON_BLOCK_STATE_TRANSITION_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "beacon_block_state_transition_seconds",
            "Time spent in state_transition (process_slots + process_block), excluding lock wait"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_BLOCK_STATE_TRANSITION_SECONDS")
    };

    pub static ref BEACON_BLOCK_STATE_ROOT_SECONDS: Histogram = {
        // Full SSZ hash_tree_root of the post-state, checked against block.state_root.
        let opts = HistogramOpts::new(
            "beacon_block_state_root_seconds",
            "Time spent computing/verifying the post-state hash tree root"
        ).buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_BLOCK_STATE_ROOT_SECONDS")
    };

    pub static ref BEACON_ENGINE_NEW_PAYLOAD_REQUEST_DURATION_SECONDS: Histogram = {
        // Round trip to the EL for engine_newPayload — same bucket range as the
        // existing getBlobsV2/V3 request histograms for consistency.
        let opts = HistogramOpts::new(
            "beacon_engine_new_payload_request_duration_seconds",
            "Duration of verify_and_notify_new_payload (engine_newPayload) requests"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_ENGINE_NEW_PAYLOAD_REQUEST_DURATION_SECONDS")
    };

    pub static ref BEACON_EXECUTION_FORKCHOICE_UPDATE_SECONDS: Histogram = {
        let opts = HistogramOpts::new(
            "beacon_execution_forkchoice_update_seconds",
            "Duration of update_execution_forkchoice (engine_forkchoiceUpdated) calls"
        ).buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 4.0, 8.0]);
        register_histogram_with_registry!(
            opts,
            default_registry()
        ).expect("failed to create BEACON_EXECUTION_FORKCHOICE_UPDATE_SECONDS")
    };
}

/// Zero-initializes gauges so dashboards show `0` instead of "no data" before the
/// first real observation. Mirrors `lean::init_aggregate_coverage_metrics`.
pub fn init_beacon_metrics() {
    set_int_gauge(&BEACON_CUSTODY_GROUPS, 0);
    set_int_gauge(&BEACON_CUSTODY_GROUPS_BACKFILLED, 0);
    set_int_gauge_vec(&BEACON_BLOCK_LOOKUP_ENTRIES, 0, &["pending_availability"]);
    set_int_gauge_vec(&BEACON_BLOCK_LOOKUP_ENTRIES, 0, &["unknown_parent"]);
    set_int_gauge_vec(&BEACON_DATA_COLUMN_FETCH_ENTRIES, 0, &["tracked"]);
    set_int_gauge_vec(&BEACON_DATA_COLUMN_FETCH_ENTRIES, 0, &["in_flight"]);
    set_peer_count(0);
}

/// Sets `BEACON_PEER_COUNT` and `LIBP2P_PEERS` (the beacon-metrics
/// interop-spec name) together, so the two can't drift apart.
pub fn set_peer_count(count: i64) {
    set_int_gauge(&BEACON_PEER_COUNT, count);
    set_int_gauge(&LIBP2P_PEERS, count);
}

pub fn init_node_metrics() {
    init_beacon_metrics();

    BEACON_NODE_INFO
        .with_label_values(&["ream", env!("CARGO_PKG_VERSION")])
        .set(1);

    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    BEACON_NODE_START_TIME_SECONDS.set(start_time as i64);
}

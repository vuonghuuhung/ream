//! A bounded sidecar pass over the verified block hash chain. A few consecutive batches below
//! the frontier download together and commit in order, so coverage stays contiguous.
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use anyhow::{anyhow, ensure};
use libp2p::PeerId;
use ream_consensus_beacon::{
    data_column_sidecar::DataColumnSidecar, electra::beacon_block::SignedBeaconBlock,
};
use ream_consensus_misc::{
    beacon_block_header::SignedBeaconBlockHeader,
    polynomial_commitments::kzg_commitment::KZGCommitment,
};
use ream_fork_choice_beacon::store::get_current_slot_from_db;
use ream_metrics::{
    BEACON_BACKFILL_COLUMNS_COMMITTED_TOTAL, BEACON_BACKFILL_PEER_BANS_TOTAL,
    BEACON_BACKFILL_PENDING_BYTES, BEACON_BACKFILL_SIDECAR_FRONTIER_SLOT,
    BEACON_BACKFILL_VERIFY_SECONDS,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_p2p::network::beacon::{
    channel::{P2PCallbackError, P2PCallbackResponse, P2PMessage, P2PRequest},
    network_state::NetworkState,
    peer::CachedPeer,
};
use ream_polynomial_commitments::handlers::verify_data_column_sidecars_kzg_proofs;
use ream_req_resp::{
    beacon::messages::{BeaconResponseMessage, data_column_sidecars::DataColumnsByRootIdentifier},
    error::ReqRespError,
};
use ream_storage::{
    db::{beacon::BeaconDB, beacon_backfill::CommitError},
    tables::{
        beacon::backfill::{BackfillMeta, BackfillMode},
        field::REDBField,
        table::REDBTable,
    },
};
use ssz::Encode;
use tokio::{
    sync::{Semaphore, mpsc, watch},
    task::JoinSet,
    time::{sleep, timeout},
};
use tracing::{debug, info, warn};
use tree_hash::TreeHash;

use super::{BAN_DURATION, ColumnCustody, scheduler::BackfillConfig};

/// Sidecars per batch, as Prysm: four blocks for a supernode, more for smaller custody.
const MAX_BATCH_SIDECARS: usize = 128 * 4;
const MAX_BATCH_SLOTS: u64 = 32;

struct Batch {
    from: u64,
    to: u64,
    blocks: BTreeMap<B256, ColumnTarget>,
    max_bytes: usize,
}

/// What a block's columns must match. Taken once per block: the header hashes the whole body.
#[derive(Clone)]
struct ColumnTarget {
    header: SignedBeaconBlockHeader,
    commitments: Vec<KZGCommitment>,
}

impl ColumnTarget {
    fn new(block: &SignedBeaconBlock) -> Self {
        Self {
            header: block.signed_header(),
            commitments: block.message.body.blob_kzg_commitments.to_vec(),
        }
    }
}

/// Slots without a block or without commitments are crossed only by walking authenticated
/// parents. A missing parent waits for block backfill; it is never treated as a skipped slot.
fn plan_batch(
    db: &BeaconDB,
    meta: &BackfillMeta,
    da_start: u64,
    budget: usize,
    column_count: usize,
) -> anyhow::Result<Option<Batch>> {
    let Some(to) = meta.sidecars.frontier else {
        return Ok(None);
    };
    let floor = da_start.max(meta.blocks.frontier.oldest_block_slot);
    if to <= floor {
        return Ok(None);
    }
    // Above the origin the canonical index only knows finalized slots.
    if to > meta.origin.slot {
        let finalized = db.finalized_checkpoint_provider().get()?;
        if to > finalized.epoch * ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH + 1 {
            return Ok(None);
        }
    }
    let Some(mut root) = db.canonical_root_before(to)? else {
        return Ok(None);
    };
    let mut from = to;
    let mut blocks = BTreeMap::new();
    let mut max_bytes = 0usize;
    loop {
        let block = db
            .block_provider()
            .get(root)?
            .ok_or_else(|| anyhow!("Missing verified historical block {root}"))?;
        let slot = block.message.slot;
        ensure!(slot < from, "Non-descending historical ancestry");
        if slot < floor {
            from = floor;
            break;
        }
        let batch_start = floor.max(to.saturating_sub(MAX_BATCH_SLOTS));
        if slot < batch_start {
            from = batch_start;
            break;
        }
        let commitments = block.message.body.blob_kzg_commitments.len();
        if commitments > 0 {
            // SSZ: cells + commitments + proofs, fixed offsets, header and inclusion branch.
            let bytes = (commitments * (2048 + 48 + 48) + 512) * column_count;
            if max_bytes + bytes > budget || (blocks.len() + 1) * column_count > MAX_BATCH_SIDECARS
            {
                ensure!(
                    !blocks.is_empty(),
                    "Column byte budget cannot fit one blob block"
                );
                break;
            }
            max_bytes += bytes;
        }
        from = slot;
        let parent = block.message.parent_root;
        if commitments > 0 {
            blocks.insert(root, ColumnTarget::new(&block));
        }
        if from == floor || to - from >= MAX_BATCH_SLOTS {
            break;
        }
        root = parent;
    }
    Ok(Some(Batch {
        from,
        to,
        blocks,
        max_bytes,
    }))
}

/// Batches downloaded ahead of processing, as Lighthouse's backfill buffer.
const MAX_QUEUED_BATCHES: usize = 5;
/// Requests per column group: one by range, then by root from other peers.
const MAX_COLUMN_ATTEMPTS: usize = 3;

/// Consecutive batches below the sidecar frontier, sharing one byte budget.
fn plan_batches(
    db: &BeaconDB,
    meta: &BackfillMeta,
    da_start: u64,
    budget: usize,
    column_count: usize,
) -> anyhow::Result<Vec<Batch>> {
    let mut cursor = meta.clone();
    let mut remaining = budget;
    let mut batches = Vec::new();
    while batches.len() < MAX_QUEUED_BATCHES {
        let batch = match plan_batch(db, &cursor, da_start, remaining, column_count) {
            Ok(Some(batch)) => batch,
            Ok(None) => break,
            Err(err) if batches.is_empty() => return Err(err),
            Err(_) => break,
        };
        remaining -= batch.max_bytes;
        cursor.sidecars.frontier = Some(batch.from);
        batches.push(batch);
    }
    Ok(batches)
}

/// Custody columns assigned to each peer.
type Groups = BTreeMap<PeerId, Vec<u64>>;

/// Columns of one batch, grouped by the peer that sent them.
type Responses = Vec<(PeerId, Vec<DataColumnSidecar>)>;

/// Verifies and commits downloaded batches; returns the committed coverage and a faulty peer.
type Worker = tokio::task::JoinHandle<anyhow::Result<(Option<BackfillMeta>, Option<PeerId>)>>;

/// Verifies and commits complete batches in order. Any pause or resume since the step started
/// cancels it, before verification and again before anything is published.
fn process(
    db: &BeaconDB,
    downloaded: Vec<(Batch, Responses)>,
    running: &watch::Receiver<bool>,
) -> anyhow::Result<(Option<BackfillMeta>, Option<PeerId>)> {
    let cancelled = || !*running.borrow() || running.has_changed().unwrap_or(true);
    let mut committed = None;
    for (batch, responses) in downloaded {
        if cancelled() {
            break;
        }
        let started = Instant::now();
        let verify_timer = BEACON_BACKFILL_VERIFY_SECONDS.start_timer();
        let invalid = invalid_supplier(&responses);
        drop(verify_timer);
        let verified = started.elapsed();
        if invalid.is_some() {
            return Ok((committed, invalid));
        }
        if cancelled() {
            break;
        }
        let columns = responses
            .into_iter()
            .flat_map(|(_, columns)| columns)
            .collect::<Vec<_>>();
        let count = columns.len();
        db.column_sidecars_provider().insert_batch(columns)?;
        let inserted = started.elapsed();
        let coverage = commit_coverage(db, batch.from, batch.to)?;
        debug!(
            from = batch.from,
            columns = count,
            verify_ms = verified.as_millis() as u64,
            insert_ms = (inserted - verified).as_millis() as u64,
            commit_ms = (started.elapsed() - inserted).as_millis() as u64,
            "Column batch processed"
        );
        match coverage {
            Some(meta) => {
                BEACON_BACKFILL_COLUMNS_COMMITTED_TOTAL.inc_by(count as u64);
                committed = Some(meta);
            }
            None => break,
        }
    }
    Ok((committed, None))
}

/// Returns the first peer whose columns fail the proofs. Headers and commitments were matched
/// against stored blocks on receipt.
fn invalid_supplier(responses: &Responses) -> Option<PeerId> {
    responses.iter().find_map(|(peer, columns)| {
        let valid = columns.iter().all(|column| column.verify_inclusion_proof())
            && verify_data_column_sidecars_kzg_proofs(columns).unwrap_or(false);
        (!valid).then_some(*peer)
    })
}

pub(super) struct ColumnBackfill {
    pub db: BeaconDB,
    pub sender: mpsc::UnboundedSender<P2PMessage>,
    pub network: Arc<NetworkState>,
    pub config: BackfillConfig,
    pub rate_limit: bool,
    pub custody: ColumnCustody,
}

/// A step's batches being verified and committed while the next step downloads.
struct InFlight {
    worker: Worker,
    /// The frontier once all of them commit; the next step plans below it.
    frontier: u64,
    bytes: usize,
}

fn set_pending_bytes(bytes: usize) {
    BEACON_BACKFILL_PENDING_BYTES
        .with_label_values(&["columns"])
        .set(bytes as i64);
}

impl ColumnBackfill {
    pub async fn run(self, mut running: watch::Receiver<bool>) {
        let mut banned = HashMap::new();
        let mut requests = HashMap::<PeerId, u64>::new();
        let mut last_log = Instant::now();
        let mut in_flight = None;
        loop {
            if !*running.borrow_and_update() {
                // A paused worker stops at its next check; its payloads go before new ones.
                let _ = self.finish(&mut in_flight, &mut banned).await;
                set_pending_bytes(0);
                if running.changed().await.is_err() {
                    return;
                }
                continue;
            }
            if let Ok(BackfillMode::Checkpoint(meta)) = self.db.cached_backfill_mode()
                && let Ok(slot) = get_current_slot_from_db(&self.db)
                && meta.sidecars.frontier.is_some_and(|frontier| {
                    frontier
                        <= beacon_network_spec().data_column_retention_start_slot(
                            slot / ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH,
                        )
                })
            {
                let _ = self.finish(&mut in_flight, &mut banned).await;
                set_pending_bytes(0);
                ream_metrics::BEACON_CUSTODY_GROUPS_BACKFILLED.set(self.custody.group_count as i64);
                info!(frontier_slot = ?meta.sidecars.frontier, "Column backfill complete");
                return;
            }
            // Dropping the batch future drops every callback and aborts its download tasks.
            let active = running.clone();
            let result = tokio::select! {
                biased;
                changed = running.changed() => { if changed.is_err() { return; } continue; },
                result = self.step(&active, &mut banned, &mut requests, &mut in_flight) => result,
            };
            match result {
                Ok(Some(meta)) => {
                    if last_log.elapsed() >= Duration::from_secs(60) {
                        info!(frontier_slot = ?meta.sidecars.frontier, "Column backfill progress");
                        last_log = Instant::now();
                    }
                }
                Ok(None) if in_flight.is_some() => {}
                Ok(None) => sleep(Duration::from_secs(1)).await,
                Err(err) => {
                    warn!(%err, "Column backfill waiting to retry");
                    sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Downloads up to `MAX_QUEUED_BATCHES` batches below those a worker is still committing,
    /// then hands them to a new worker that verifies and commits them in order inside the
    /// backfill window. Returns the coverage the previous worker committed.
    async fn step(
        &self,
        running: &watch::Receiver<bool>,
        banned: &mut HashMap<PeerId, Instant>,
        requests: &mut HashMap<PeerId, u64>,
        in_flight: &mut Option<InFlight>,
    ) -> anyhow::Result<Option<BackfillMeta>> {
        let mut meta = match self.db.cached_backfill_mode()? {
            BackfillMode::Checkpoint(meta) => meta,
            _ => return self.finish(in_flight, banned).await,
        };
        let mut budget = self.config.max_pending_bytes;
        let mut held = 0;
        if let Some(flight) = in_flight.as_ref() {
            meta.sidecars.frontier = Some(flight.frontier);
            held = flight.bytes;
            budget = budget.saturating_sub(held);
        }
        let epoch = get_current_slot_from_db(&self.db)?
            / ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        let da_start = beacon_network_spec().data_column_retention_start_slot(epoch);
        let db = self.db.clone();
        let column_count = self.custody.columns.len();
        let planned = tokio::task::spawn_blocking(move || {
            plan_batches(&db, &meta, da_start, budget, column_count)
        })
        .await?;
        let batches = match planned {
            Ok(batches) => batches,
            // The budget the worker holds comes back once it finishes.
            Err(_) if in_flight.is_some() => Vec::new(),
            Err(err) => return Err(err),
        };
        if batches.is_empty() {
            let committed = self.finish(in_flight, banned).await;
            set_pending_bytes(0);
            return committed;
        }
        set_pending_bytes(held + batches.iter().map(|batch| batch.max_bytes).sum::<usize>());
        banned.retain(|_, at| at.elapsed() < BAN_DURATION);
        let planned = batches.len();
        let started = Instant::now();
        let load = Mutex::new(Load::default());
        // Column requests are small, so each batch of the step gets `max_inflight` of them.
        let permits = Arc::new(Semaphore::new(
            self.config.max_inflight.saturating_mul(MAX_QUEUED_BATCHES),
        ));
        let mut assigned = Vec::new();
        for batch in batches {
            match self.assign(&batch, banned, requests, &load) {
                Some((peers, groups)) => assigned.push((batch, peers, groups)),
                None => break,
            }
        }
        let fetched = futures::future::join_all(assigned.iter().map(|(batch, peers, groups)| {
            self.fetch(batch, peers, groups.clone(), banned, &load, &permits)
        }))
        .await;
        let mut downloaded = Vec::new();
        let mut complete = true;
        for ((batch, ..), result) in assigned.into_iter().zip(fetched) {
            let (responses, faults) = result?;
            for (peer, reason) in faults {
                warn!(?peer, %reason, "Banning peer from column backfill");
                banned.insert(peer, Instant::now());
                BEACON_BACKFILL_PEER_BANS_TOTAL
                    .with_label_values(&["invalid_column"])
                    .inc();
            }
            // Coverage is contiguous: nothing below an incomplete batch can be committed.
            match responses {
                Some(responses) if complete => downloaded.push((batch, responses)),
                _ => complete = false,
            }
        }
        debug!(
            planned,
            complete = downloaded.len(),
            download_ms = started.elapsed().as_millis() as u64,
            "Column backfill downloads"
        );
        // The previous batches commit first; these only extend what they committed.
        let expected = in_flight.as_ref().map(|flight| flight.frontier);
        let committed = self.finish(in_flight, banned).await?;
        if expected.is_some()
            && committed.as_ref().and_then(|meta| meta.sidecars.frontier) != expected
        {
            set_pending_bytes(0);
            return Ok(committed);
        }
        let bytes = downloaded
            .iter()
            .map(|(batch, _)| batch.max_bytes)
            .sum::<usize>();
        set_pending_bytes(bytes);
        let Some(frontier) = downloaded.last().map(|(batch, _)| batch.from) else {
            set_pending_bytes(0);
            return Ok(committed);
        };
        if self.rate_limit {
            super::wait_for_backfill_window(&self.db, running).await?;
        }
        if !*running.borrow() || running.has_changed().is_err() {
            set_pending_bytes(0);
            return Ok(committed);
        }
        let db = self.db.clone();
        let running = running.clone();
        *in_flight = Some(InFlight {
            worker: tokio::task::spawn_blocking(move || process(&db, downloaded, &running)),
            frontier,
            bytes,
        });
        Ok(committed)
    }

    /// Waits for the batches a worker is committing; returns the coverage it committed.
    async fn finish(
        &self,
        in_flight: &mut Option<InFlight>,
        banned: &mut HashMap<PeerId, Instant>,
    ) -> anyhow::Result<Option<BackfillMeta>> {
        let Some(flight) = in_flight.as_mut() else {
            return Ok(None);
        };
        // Kept in `in_flight` until it ends, so a dropped step leaves it to the next one.
        let result = (&mut flight.worker).await;
        *in_flight = None;
        let (meta, invalid) = result??;
        if let Some(peer) = invalid {
            warn!(?peer, "Invalid historical column proof");
            banned.insert(peer, Instant::now());
            BEACON_BACKFILL_PEER_BANS_TOTAL
                .with_label_values(&["invalid_column"])
                .inc();
        }
        Ok(meta)
    }

    /// Picks a custody peer for every column of the batch, or `None` when some column has none.
    fn assign(
        &self,
        batch: &Batch,
        banned: &HashMap<PeerId, Instant>,
        requests: &mut HashMap<PeerId, u64>,
        load: &Mutex<Load>,
    ) -> Option<(Vec<CachedPeer>, Groups)> {
        let mut groups = Groups::new();
        if batch.blocks.is_empty() {
            return Some((Vec::new(), groups));
        }
        let peers = self
            .network
            .connected_peers()
            .into_iter()
            .filter(|peer| {
                !banned.contains_key(&peer.peer_id)
                    && peer
                        .status
                        .as_ref()
                        .is_some_and(|status| status.earliest_available_slot <= batch.from)
            })
            .collect::<Vec<_>>();
        let mut load = lock(load);
        for &index in &self.custody.columns {
            let peer = peers
                .iter()
                .filter(|peer| {
                    peer.custody().custodies_column(index)
                        && (groups.contains_key(&peer.peer_id)
                            || !load.range.contains(&peer.peer_id))
                })
                .min_by_key(|peer| {
                    (
                        groups.len() >= self.config.max_inflight
                            && !groups.contains_key(&peer.peer_id),
                        groups.get(&peer.peer_id).map_or(0, Vec::len),
                        requests.get(&peer.peer_id).copied().unwrap_or_default(),
                    )
                })?;
            groups.entry(peer.peer_id).or_default().push(index);
        }
        for peer in groups.keys() {
            load.range.insert(*peer);
            let count = requests.entry(*peer).or_default();
            *count = count.saturating_add(1);
        }
        Some((peers, groups))
    }

    /// Returns every custody column of the batch's blob blocks, or `None` when some stay
    /// missing, with the peers that sent invalid or incomplete responses. Missing columns are
    /// requested by root from other custody peers, a bounded number of times.
    async fn fetch(
        &self,
        batch: &Batch,
        peers: &[CachedPeer],
        groups: Groups,
        banned: &HashMap<PeerId, Instant>,
        load: &Mutex<Load>,
        permits: &Arc<Semaphore>,
    ) -> anyhow::Result<(Option<Responses>, Vec<(PeerId, String)>)> {
        let mut responses = Responses::new();
        let mut faults = Vec::<(PeerId, String)>::new();
        if batch.blocks.is_empty() {
            return Ok((Some(responses), faults));
        }
        let mut tried = HashMap::<PeerId, usize>::new();
        let mut received = HashSet::new();
        let mut tasks = JoinSet::new();
        let mut queue = groups
            .into_iter()
            .map(|(peer, columns)| (peer, columns, None::<BTreeMap<B256, Vec<u64>>>, 1))
            .collect::<VecDeque<_>>();
        loop {
            while let Some((peer, columns, roots, attempt)) = queue.pop_front() {
                *tried.entry(peer).or_default() += 1;
                let sender = self.sender.clone();
                let (want, blocks, limit) = match &roots {
                    None => (
                        Want::Range(columns.clone()),
                        batch.blocks.clone(),
                        // The sum of group budgets is the batch budget, independent of
                        // concurrency.
                        batch.max_bytes * columns.len() / self.custody.columns.len(),
                    ),
                    Some(roots) => {
                        let mut blocks = BTreeMap::new();
                        let mut limit = 0;
                        for (root, missing) in roots {
                            let Some(block) = batch.blocks.get(root) else {
                                continue;
                            };
                            limit +=
                                (block.commitments.len() * (2048 + 48 + 48) + 512) * missing.len();
                            blocks.insert(*root, block.clone());
                        }
                        (Want::Roots(roots.clone()), blocks, limit)
                    }
                };
                let by_root = roots.is_some();
                let range = batch.from..batch.to;
                let permits = permits.clone();
                tasks.spawn(async move {
                    let _permit = permits.acquire_owned().await;
                    let started = Instant::now();
                    let response =
                        receive_columns(sender, peer, range.clone(), want, Arc::new(blocks), limit)
                            .await;
                    debug!(
                        ?peer,
                        from = range.start,
                        count = range.end - range.start,
                        ?columns,
                        by_root,
                        outcome = response.label(),
                        elapsed_ms = started.elapsed().as_millis() as u64,
                        "Column response"
                    );
                    (peer, columns, roots, attempt, response)
                });
            }
            let Some(response) = tasks.join_next().await else {
                break;
            };
            let (peer, columns, roots, attempt, response) = response?;
            {
                let mut load = lock(load);
                match roots {
                    None => load.range.remove(&peer),
                    Some(_) => load.root.remove(&peer),
                };
            }
            let answered = match response {
                ColumnResponse::Columns(values) => {
                    keep(&mut responses, &mut received, peer, values);
                    true
                }
                ColumnResponse::Fault(reason) => {
                    faults.push((peer, reason));
                    false
                }
                ColumnResponse::Unavailable(_) => false,
            };
            let scope = roots.unwrap_or_else(|| {
                batch
                    .blocks
                    .keys()
                    .map(|root| (*root, columns.clone()))
                    .collect()
            });
            let missing_roots = scope
                .into_iter()
                .filter_map(|(root, wanted)| {
                    let missing = wanted
                        .into_iter()
                        .filter(|index| !received.contains(&(root, *index)))
                        .collect::<Vec<_>>();
                    (!missing.is_empty()).then_some((root, missing))
                })
                .collect::<BTreeMap<_, _>>();
            if missing_roots.is_empty() {
                continue;
            }
            // A range answer must hold every column the peer custodies from its earliest slot.
            if answered && attempt == 1 {
                faults.push((peer, "missing custody columns".into()));
            }
            if attempt >= MAX_COLUMN_ATTEMPTS {
                continue;
            }
            let missing = missing_roots
                .values()
                .flatten()
                .copied()
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let mut load = lock(load);
            let Some(replacement) = peers
                .iter()
                .filter(|candidate| {
                    candidate.peer_id != peer
                        && !banned.contains_key(&candidate.peer_id)
                        && !faults
                            .iter()
                            .any(|(faulty, _)| *faulty == candidate.peer_id)
                        && !load.root.contains(&candidate.peer_id)
                        && missing
                            .iter()
                            .all(|index| candidate.custody().custodies_column(*index))
                })
                .min_by_key(|candidate| tried.get(&candidate.peer_id).copied().unwrap_or_default())
                .map(|candidate| candidate.peer_id)
            else {
                continue;
            };
            load.root.insert(replacement);
            queue.push_back((replacement, missing, Some(missing_roots), attempt + 1));
        }
        let complete = received.len() == batch.blocks.len() * self.custody.columns.len();
        Ok((complete.then_some(responses), faults))
    }
}

/// Requests in flight per peer and protocol, shared by the batches of one step. One per
/// protocol stays under the two concurrent requests peers allow.
#[derive(Default)]
struct Load {
    range: HashSet<PeerId>,
    root: HashSet<PeerId>,
}

fn lock(load: &Mutex<Load>) -> std::sync::MutexGuard<'_, Load> {
    load.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn keep(
    responses: &mut Responses,
    received: &mut HashSet<(B256, u64)>,
    peer: PeerId,
    values: Vec<DataColumnSidecar>,
) {
    let values = values
        .into_iter()
        .filter(|column| {
            received.insert((
                column.signed_block_header.message.tree_hash_root(),
                column.index,
            ))
        })
        .collect::<Vec<_>>();
    if !values.is_empty() {
        responses.push((peer, values));
    }
}

/// Moves the frontier from `to` down to `from`, unless another writer moved it first.
fn commit_coverage(db: &BeaconDB, from: u64, to: u64) -> anyhow::Result<Option<BackfillMeta>> {
    for _ in 0..3 {
        let BackfillMode::Checkpoint(meta) = db.cached_backfill_mode()? else {
            return Ok(None);
        };
        if meta.sidecars.frontier != Some(to) {
            return Ok(None);
        }
        match db.commit_sidecar_coverage(meta.revision, from) {
            Ok(meta) => {
                BEACON_BACKFILL_SIDECAR_FRONTIER_SLOT.set(from as i64);
                return Ok(Some(meta));
            }
            Err(CommitError::Conflict { .. }) => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(None)
}

enum ColumnResponse {
    Columns(Vec<DataColumnSidecar>),
    Fault(String),
    Unavailable(String),
}

impl ColumnResponse {
    fn label(&self) -> String {
        match self {
            Self::Columns(values) => format!("columns:{}", values.len()),
            Self::Fault(reason) => format!("fault:{reason}"),
            Self::Unavailable(reason) => format!("unavailable:{reason}"),
        }
    }
}

/// The columns one request asks for: the same columns for a slot range, or exact columns per root.
enum Want {
    Range(Vec<u64>),
    Roots(BTreeMap<B256, Vec<u64>>),
}

impl Want {
    fn contains(&self, root: &B256, index: u64) -> bool {
        match self {
            Self::Range(columns) => columns.contains(&index),
            Self::Roots(roots) => roots
                .get(root)
                .is_some_and(|columns| columns.contains(&index)),
        }
    }
}

async fn receive_columns(
    sender: mpsc::UnboundedSender<P2PMessage>,
    peer: PeerId,
    range: std::ops::Range<u64>,
    want: Want,
    blocks: Arc<BTreeMap<B256, ColumnTarget>>,
    limit: usize,
) -> ColumnResponse {
    let (callback, mut receiver) = mpsc::channel(1);
    let by_root = matches!(want, Want::Roots(_));
    let request = if let Want::Roots(roots) = &want {
        let identifiers = roots
            .iter()
            .map(|(root, columns)| DataColumnsByRootIdentifier::new(*root, columns.clone()))
            .collect::<Result<Vec<_>, _>>();
        let Ok(identifiers) = identifiers else {
            return ColumnResponse::Unavailable("bad identifiers".into());
        };
        P2PRequest::DataColumnIdentifiers {
            peer_id: peer,
            column_identifiers: identifiers,
            callback,
        }
    } else {
        let Want::Range(columns) = &want else {
            unreachable!("by-root requests are built above");
        };
        P2PRequest::DataColumnRange {
            peer_id: peer,
            start: range.start,
            count: range.end - range.start,
            columns: columns.clone(),
            callback,
        }
    };
    if sender.send(P2PMessage::Request(request)).is_err() {
        return ColumnResponse::Unavailable("network closed".into());
    }
    let mut values = Vec::new();
    let mut seen = HashSet::new();
    let mut bytes = 0usize;
    let result = timeout(Duration::from_secs(60), async {
        while let Some(message) = receiver.recv().await {
            match message {
                Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                    let column = match (by_root, message.as_ref()) {
                        (false, BeaconResponseMessage::DataColumnSidecarsByRange(column))
                        | (true, BeaconResponseMessage::DataColumnSidecarsByRoot(column)) => column,
                        _ => return ColumnResponse::Fault("unexpected response type".into()),
                    };
                    let root = column.signed_block_header.message.tree_hash_root();
                    let Some(block) = blocks.get(&root) else {
                        return ColumnResponse::Fault("unrequested block root".into());
                    };
                    if !want.contains(&root, column.index) || !seen.insert((root, column.index)) {
                        return ColumnResponse::Fault("unrequested or duplicate column".into());
                    }
                    if !column.verify()
                        || column.kzg_commitments[..] != block.commitments[..]
                        || column.signed_block_header != block.header
                    {
                        return ColumnResponse::Fault(
                            "column does not match verified block".into(),
                        );
                    }
                    let size = column.ssz_bytes_len();
                    if size > limit.saturating_sub(bytes) {
                        return ColumnResponse::Unavailable("byte limit".into());
                    }
                    bytes += size;
                    values.push(column.clone());
                }
                Ok(P2PCallbackResponse::EndOfStream) => return ColumnResponse::Columns(values),
                Err(P2PCallbackError::ReqResp(ReqRespError::InvalidData(reason))) => {
                    return ColumnResponse::Fault(reason);
                }
                Err(err) => return ColumnResponse::Unavailable(err.to_string()),
                Ok(_) => return ColumnResponse::Unavailable("unexpected callback".into()),
            }
        }
        ColumnResponse::Unavailable("callback closed".into())
    })
    .await;
    result.unwrap_or_else(|_| ColumnResponse::Unavailable("timeout".into()))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use ream_consensus_beacon::{
        data_column_sidecar::get_data_column_sidecars_from_block,
        electra::beacon_block::BeaconBlock,
        matrix_entry::{compute_cells_and_kzg_proofs, das_context},
    };
    use ream_consensus_misc::polynomial_commitments::kzg_commitment::KZGCommitment;
    use ream_execution_rpc_types::get_blobs::Blob;
    use ream_network_spec::networks::initialize_test_network_spec;
    use ream_peer::{ConnectionState, Direction};
    use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};
    use ream_storage::{
        db::ReamDB,
        tables::{
            beacon::backfill::{
                BlockBackfillState, BlockCoverage, Frontier, Origin, SidecarCoverage,
            },
            field::REDBField,
            table::CustomTable,
        },
    };

    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        db: BeaconDB,
        network: Arc<NetworkState>,
        meta: BackfillMeta,
        columns: Vec<DataColumnSidecar>,
    }

    fn fixture() -> Fixture {
        initialize_test_network_spec();
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let base = beacon_network_spec().fulu_fork_epoch
            * ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
        let blob = Blob::default();
        let commitment = KZGCommitment(
            das_context()
                .blob_to_kzg_commitment(&blob.to_fixed_bytes())
                .unwrap(),
        );
        let cells = compute_cells_and_kzg_proofs(&blob, das_context()).unwrap();
        let mut parent = B256::ZERO;
        let mut blocks = Vec::new();
        let mut columns = Vec::new();
        for offset in 0..=4 {
            let mut block = SignedBeaconBlock {
                message: BeaconBlock {
                    slot: base + offset,
                    parent_root: parent,
                    ..Default::default()
                },
                signature: Default::default(),
            };
            if offset == 1 || offset == 3 {
                block
                    .message
                    .body
                    .blob_kzg_commitments
                    .push(commitment)
                    .unwrap();
                columns.extend(
                    get_data_column_sidecars_from_block(&block, vec![cells.clone()]).unwrap(),
                );
            }
            parent = block.message.tree_hash_root();
            db.block_provider().insert(parent, block.clone()).unwrap();
            blocks.push((parent, block));
        }
        db.record_finalized_canonical(parent).unwrap();
        let meta = BackfillMeta {
            revision: 0,
            origin: Origin {
                slot: base + 4,
                root: parent,
                state_root: blocks[4].1.message.state_root,
            },
            blocks: BlockCoverage {
                frontier: Frontier {
                    oldest_block_slot: base,
                    oldest_block_root: blocks[0].0,
                    oldest_block_parent: B256::ZERO,
                },
                state: BlockBackfillState::BlocksComplete,
            },
            sidecars: SidecarCoverage {
                frontier: Some(base + 4),
            },
        };
        let write = db.db.begin_write().unwrap();
        {
            let mut table = write
                .open_table(redb::TableDefinition::<&str, &[u8]>::new(
                    "beacon_bootstrap",
                ))
                .unwrap();
            table.insert("mode", &[1u8][..]).unwrap();
            table
                .insert(
                    "genesis_validators_root",
                    B256::ZERO.as_ssz_bytes().as_slice(),
                )
                .unwrap();
            table
                .insert("backfill_meta", meta.as_ssz_bytes().as_slice())
                .unwrap();
        }
        write.commit().unwrap();
        db.genesis_time_provider().insert(0).unwrap();
        db.time_provider()
            .insert((base + 4) * beacon_network_spec().seconds_per_slot())
            .unwrap();
        let key = discv5::enr::CombinedKey::generate_secp256k1();
        let enr = discv5::Enr::builder().build(&key).unwrap();
        let network = Arc::new(NetworkState {
            local_enr: enr.into(),
            peer_table: Default::default(),
            meta_data: Default::default(),
            status: Default::default(),
            data_dir: dir.path().to_path_buf(),
        });
        add_supernode(&network);
        Fixture {
            _dir: dir,
            db,
            network,
            meta,
            columns,
        }
    }

    fn add_supernode(network: &NetworkState) -> PeerId {
        let peer = libp2p::identity::Keypair::generate_secp256k1()
            .public()
            .to_peer_id();
        network.upsert_peer(
            peer,
            None,
            ConnectionState::Connected,
            Direction::Outbound,
            None,
        );
        network.update_peer_meta_data(
            peer,
            GetMetaDataV3 {
                custody_group_count: 128,
                ..Default::default()
            },
        );
        network.peer_table.write().get_mut(&peer).unwrap().status = Some(Status::default());
        peer
    }

    fn current(db: &BeaconDB) -> BackfillMeta {
        match db.backfill_mode().unwrap() {
            BackfillMode::Checkpoint(meta) => meta,
            _ => unreachable!(),
        }
    }

    /// One step, then the commit of what it downloaded.
    async fn run_step(driver: &ColumnBackfill) -> Option<BackfillMeta> {
        let (_sender, running) = watch::channel(true);
        let (mut banned, mut in_flight) = (HashMap::new(), None);
        let committed = driver
            .step(&running, &mut banned, &mut HashMap::new(), &mut in_flight)
            .await
            .unwrap();
        if in_flight.is_none() {
            return committed;
        }
        driver.finish(&mut in_flight, &mut banned).await.unwrap()
    }

    #[tokio::test]
    async fn missing_columns_do_not_advance_then_root_fallback_completes_all_128_columns() {
        let fixture = fixture();
        // Short range answers are recovered by root from another custody peer.
        add_supernode(&fixture.network);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let complete = Arc::new(AtomicBool::new(false));
        let serve_complete = complete.clone();
        let columns = fixture.columns.clone();
        let server = tokio::spawn(async move {
            while let Some(P2PMessage::Request(request)) = receiver.recv().await {
                let (selected, callback, by_root) = match request {
                    P2PRequest::DataColumnRange {
                        columns: indices,
                        callback,
                        ..
                    } => (
                        columns
                            .iter()
                            .filter(|column| column.index != 127 && indices.contains(&column.index))
                            .cloned()
                            .collect::<Vec<_>>(),
                        callback,
                        false,
                    ),
                    P2PRequest::DataColumnIdentifiers {
                        column_identifiers,
                        callback,
                        ..
                    } => (
                        columns
                            .iter()
                            .filter(|column| {
                                serve_complete.load(Ordering::SeqCst)
                                    && column_identifiers.iter().any(|id| {
                                        id.block_root
                                            == column.signed_block_header.message.tree_hash_root()
                                            && id.columns.contains(&column.index)
                                    })
                            })
                            .cloned()
                            .collect(),
                        callback,
                        true,
                    ),
                    _ => panic!("unexpected request"),
                };
                for column in selected {
                    let response = if by_root {
                        BeaconResponseMessage::DataColumnSidecarsByRoot(column)
                    } else {
                        BeaconResponseMessage::DataColumnSidecarsByRange(column)
                    };
                    if callback
                        .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(response))))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                let _ = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await;
            }
        });
        // A crash may publish files before committing coverage. Existing files alone must not
        // advance the frontier; the next pass authenticates downloaded replacements.
        fixture
            .db
            .column_sidecars_provider()
            .insert_batch(vec![fixture.columns[0].clone()])
            .unwrap();
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network,
            config: BackfillConfig::default(),
            rate_limit: false,
            custody: ColumnCustody::all(),
        };
        let (_running_sender, running) = watch::channel(true);
        let mut banned = HashMap::new();
        assert!(
            driver
                .step(&running, &mut banned, &mut HashMap::new(), &mut None)
                .await
                .unwrap()
                .is_none()
        );
        // Only the short range responder is excluded; an empty by-root answer is not a fault.
        assert_eq!(banned.len(), 1);
        assert_eq!(current(&fixture.db).sidecars, fixture.meta.sidecars);
        complete.store(true, Ordering::SeqCst);
        let committed = run_step(&driver).await.unwrap();
        assert_eq!(
            committed.sidecars.frontier,
            Some(fixture.meta.blocks.frontier.oldest_block_slot)
        );
        assert_eq!(
            committed.earliest_available_slot(fixture.meta.blocks.frontier.oldest_block_slot),
            fixture.meta.blocks.frontier.oldest_block_slot
        );
        for column in fixture.columns {
            let key = ream_consensus_beacon::data_column_sidecar::ColumnIdentifier::new(
                column.signed_block_header.message.tree_hash_root(),
                column.index,
            );
            assert_eq!(
                fixture.db.column_sidecars_provider().get(key).unwrap(),
                Some(column)
            );
        }
        assert!(run_step(&driver).await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn only_custody_columns_are_requested_stored_and_required() {
        let fixture = fixture();
        let custody = vec![0, 5, 77];
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let requested = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let seen = requested.clone();
        let columns = fixture.columns.clone();
        let server = tokio::spawn(async move {
            while let Some(P2PMessage::Request(request)) = receiver.recv().await {
                let P2PRequest::DataColumnRange {
                    columns: indices,
                    callback,
                    ..
                } = request
                else {
                    panic!("unexpected request");
                };
                seen.lock().unwrap().extend(indices.iter().copied());
                for column in columns
                    .iter()
                    .filter(|column| indices.contains(&column.index))
                {
                    let response = BeaconResponseMessage::DataColumnSidecarsByRange(column.clone());
                    let _ = callback
                        .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(response))))
                        .await;
                }
                let _ = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await;
            }
        });
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network,
            config: BackfillConfig::default(),
            rate_limit: false,
            custody: ColumnCustody {
                group_count: 4,
                columns: custody.clone(),
            },
        };
        let committed = run_step(&driver).await.unwrap();
        assert_eq!(
            committed.sidecars.frontier,
            Some(fixture.meta.blocks.frontier.oldest_block_slot)
        );
        assert_eq!(
            *requested.lock().unwrap(),
            custody.iter().copied().collect::<HashSet<_>>()
        );
        for column in fixture.columns {
            let key = ream_consensus_beacon::data_column_sidecar::ColumnIdentifier::new(
                column.signed_block_header.message.tree_hash_root(),
                column.index,
            );
            assert_eq!(
                fixture
                    .db
                    .column_sidecars_provider()
                    .get(key)
                    .unwrap()
                    .is_some(),
                custody.contains(&column.index)
            );
        }
        server.abort();
    }

    #[test]
    fn invalid_proofs_blame_only_the_supplier() {
        let fixture = fixture();
        let honest = PeerId::random();
        let faulty = PeerId::random();
        let mut column = fixture.columns[0].clone();
        column.kzg_proofs[0][0] ^= 1;
        let valid = vec![(honest, fixture.columns[1..].to_vec())];
        assert_eq!(invalid_supplier(&valid), None);
        let mixed = vec![valid[0].clone(), (faulty, vec![column])];
        assert_eq!(invalid_supplier(&mixed), Some(faulty));
    }

    #[tokio::test]
    async fn pausing_cancels_download_callbacks_without_moving_the_frontier() {
        let fixture = fixture();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network,
            config: BackfillConfig::default(),
            rate_limit: false,
            custody: ColumnCustody::all(),
        };
        let (running, active) = watch::channel(true);
        let task = tokio::spawn(driver.run(active));
        let callback = match timeout(Duration::from_secs(10), receiver.recv())
            .await
            .unwrap()
            .unwrap()
        {
            P2PMessage::Request(P2PRequest::DataColumnRange { callback, .. }) => callback,
            _ => panic!("expected column range"),
        };
        running.send(false).unwrap();
        timeout(Duration::from_secs(5), callback.closed())
            .await
            .unwrap();
        assert_eq!(current(&fixture.db), fixture.meta);
        drop(running);
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn batch_planning_respects_da_boundary_and_the_byte_budget() {
        let fixture = fixture();
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let batch = plan_batch(&fixture.db, &fixture.meta, base + 2, 128 * 1024 * 1024, 128)
            .unwrap()
            .unwrap();
        assert_eq!(batch.from, base + 2);
        assert_eq!(batch.blocks.len(), 1);
        assert!(
            plan_batch(&fixture.db, &fixture.meta, base + 4, 128 * 1024 * 1024, 128)
                .unwrap()
                .is_none()
        );
        assert!(plan_batch(&fixture.db, &fixture.meta, base, 1, 128).is_err());
        // Both blob blocks fit the sidecar cap; a cap of one block stops after the first.
        let full = plan_batch(&fixture.db, &fixture.meta, base, 128 * 1024 * 1024, 8)
            .unwrap()
            .unwrap();
        assert_eq!((full.from, full.blocks.len()), (base, 2));
        let capped = plan_batch(
            &fixture.db,
            &fixture.meta,
            base,
            128 * 1024 * 1024,
            MAX_BATCH_SIDECARS / 2 + 1,
        )
        .unwrap()
        .unwrap();
        assert_eq!((capped.from, capped.blocks.len()), (base + 2, 1));
        let mut pending = fixture.meta.clone();
        pending.sidecars.frontier = None;
        assert!(
            plan_batch(&fixture.db, &pending, base, 128 * 1024 * 1024, 128)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn coverage_above_the_origin_waits_for_finality() {
        let fixture = fixture();
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let fulu = beacon_network_spec().fulu_fork_epoch;
        let mut grown = fixture.meta.clone();
        grown.sidecars.frontier = Some(base + 5);
        let finalize = |epoch| {
            fixture
                .db
                .finalized_checkpoint_provider()
                .insert(ream_consensus_misc::checkpoint::Checkpoint {
                    epoch,
                    root: B256::ZERO,
                })
                .unwrap();
        };
        finalize(fulu);
        assert!(
            plan_batch(&fixture.db, &grown, base, 128 * 1024 * 1024, 8)
                .unwrap()
                .is_none()
        );
        finalize(fulu + 1);
        let batch = plan_batch(&fixture.db, &grown, base, 128 * 1024 * 1024, 8)
            .unwrap()
            .unwrap();
        assert_eq!(
            (batch.from, batch.to, batch.blocks.len()),
            (base, base + 5, 2)
        );
    }

    #[tokio::test]
    async fn max_inflight_bounds_requests_across_batches() {
        let fixture = fixture();
        let second = add_supernode(&fixture.network);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (serve_active, serve_peak) = (active.clone(), peak.clone());
        let columns = fixture.columns.clone();
        let server = tokio::spawn(async move {
            while let Some(P2PMessage::Request(P2PRequest::DataColumnRange {
                start,
                count,
                columns: indices,
                callback,
                ..
            })) = receiver.recv().await
            {
                let now = serve_active.fetch_add(1, Ordering::SeqCst) + 1;
                serve_peak.fetch_max(now, Ordering::SeqCst);
                let selected = columns
                    .iter()
                    .filter(|column| {
                        (start..start + count).contains(&column.signed_block_header.message.slot)
                            && indices.contains(&column.index)
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                let serve_active = serve_active.clone();
                tokio::spawn(async move {
                    sleep(Duration::from_millis(50)).await;
                    for column in selected {
                        let response = BeaconResponseMessage::DataColumnSidecarsByRange(column);
                        let _ = callback
                            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(response))))
                            .await;
                    }
                    serve_active.fetch_sub(1, Ordering::SeqCst);
                    let _ = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await;
                });
            }
        });
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network.clone(),
            config: BackfillConfig {
                max_inflight: 1,
                ..BackfillConfig::default()
            },
            rate_limit: false,
            custody: ColumnCustody {
                group_count: 2,
                columns: vec![0, 1],
            },
        };
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let batch = |from: u64, slot: u64| {
            let (root, block) = fixture
                .db
                .block_provider()
                .get(
                    fixture
                        .columns
                        .iter()
                        .find(|column| column.signed_block_header.message.slot == slot)
                        .unwrap()
                        .signed_block_header
                        .message
                        .tree_hash_root(),
                )
                .unwrap()
                .map(|block| (block.message.tree_hash_root(), block))
                .unwrap();
            Batch {
                from,
                to: from + 2,
                blocks: BTreeMap::from([(root, ColumnTarget::new(&block))]),
                max_bytes: (2048 + 48 + 48 + 512) * 2,
            }
        };
        let (upper, lower) = (batch(base + 2, base + 3), batch(base, base + 1));
        let first = fixture.network.connected_peers()[0].peer_id;
        let peers = fixture.network.connected_peers();
        let load = Mutex::new(Load::default());
        let permits = Arc::new(Semaphore::new(1));
        let banned = HashMap::new();
        let (a, b) = tokio::join!(
            driver.fetch(
                &upper,
                &peers,
                Groups::from([(first, vec![0, 1])]),
                &banned,
                &load,
                &permits
            ),
            driver.fetch(
                &lower,
                &peers,
                Groups::from([(second, vec![0, 1])]),
                &banned,
                &load,
                &permits
            ),
        );
        assert!(a.unwrap().0.is_some() && b.unwrap().0.is_some());
        assert_eq!(peak.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn root_retries_ask_only_for_each_roots_missing_columns() {
        let fixture = fixture();
        let second = add_supernode(&fixture.network);
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let batch = plan_batch(&fixture.db, &fixture.meta, base, 128 * 1024 * 1024, 2)
            .unwrap()
            .unwrap();
        let roots = batch.blocks.keys().copied().collect::<Vec<_>>();
        // The range answer lacks column 0 of the first block and column 1 of the second.
        let dropped = [(roots[0], 0), (roots[1], 1)];
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = asked.clone();
        let columns = fixture.columns.clone();
        let server = tokio::spawn(async move {
            while let Some(P2PMessage::Request(request)) = receiver.recv().await {
                let (selected, callback, by_root) = match request {
                    P2PRequest::DataColumnRange {
                        columns: indices,
                        callback,
                        ..
                    } => (
                        columns
                            .iter()
                            .filter(|column| {
                                indices.contains(&column.index)
                                    && !dropped.contains(&(
                                        column.signed_block_header.message.tree_hash_root(),
                                        column.index,
                                    ))
                            })
                            .cloned()
                            .collect::<Vec<_>>(),
                        callback,
                        false,
                    ),
                    P2PRequest::DataColumnIdentifiers {
                        column_identifiers,
                        callback,
                        ..
                    } => {
                        let wanted = column_identifiers
                            .iter()
                            .flat_map(|id| id.columns.iter().map(|index| (id.block_root, *index)))
                            .collect::<Vec<_>>();
                        record.lock().unwrap().extend(wanted.iter().copied());
                        (
                            columns
                                .iter()
                                .filter(|column| {
                                    wanted.contains(&(
                                        column.signed_block_header.message.tree_hash_root(),
                                        column.index,
                                    ))
                                })
                                .cloned()
                                .collect(),
                            callback,
                            true,
                        )
                    }
                    _ => panic!("unexpected request"),
                };
                for column in selected {
                    let response = if by_root {
                        BeaconResponseMessage::DataColumnSidecarsByRoot(column)
                    } else {
                        BeaconResponseMessage::DataColumnSidecarsByRange(column)
                    };
                    let _ = callback
                        .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(response))))
                        .await;
                }
                let _ = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await;
            }
        });
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network.clone(),
            config: BackfillConfig::default(),
            rate_limit: false,
            custody: ColumnCustody {
                group_count: 2,
                columns: vec![0, 1],
            },
        };
        let first = fixture
            .network
            .connected_peers()
            .into_iter()
            .find(|peer| peer.peer_id != second)
            .unwrap()
            .peer_id;
        let (responses, faults) = driver
            .fetch(
                &batch,
                &fixture.network.connected_peers(),
                Groups::from([(first, vec![0, 1])]),
                &HashMap::new(),
                &Mutex::new(Load::default()),
                &Arc::new(Semaphore::new(5)),
            )
            .await
            .unwrap();
        assert!(responses.is_some());
        assert_eq!(faults.len(), 1);
        let mut asked = asked.lock().unwrap().clone();
        asked.sort();
        let mut expected = dropped.to_vec();
        expected.sort();
        assert_eq!(asked, expected);
        server.abort();
    }

    #[test]
    fn a_pause_or_resume_cancels_processing_before_publication() {
        let fixture = fixture();
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let downloaded = || {
            let batch = plan_batch(&fixture.db, &fixture.meta, base, 128 * 1024 * 1024, 128)
                .unwrap()
                .unwrap();
            vec![(batch, vec![(PeerId::random(), fixture.columns.clone())])]
        };
        let (sender, running) = watch::channel(true);
        let session = running.clone();
        sender.send(false).unwrap();
        sender.send(true).unwrap();
        assert_eq!(
            process(&fixture.db, downloaded(), &session).unwrap(),
            (None, None)
        );
        assert_eq!(current(&fixture.db).sidecars, fixture.meta.sidecars);
        let mut fresh = running.clone();
        fresh.borrow_and_update();
        let (committed, invalid) = process(&fixture.db, downloaded(), &fresh).unwrap();
        assert!(invalid.is_none());
        assert_eq!(committed.unwrap().sidecars.frontier, Some(base));
    }

    #[test]
    fn queued_batches_are_contiguous() {
        let fixture = fixture();
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        // A sidecar cap of one blob block per batch splits the two blob blocks.
        let batches = plan_batches(
            &fixture.db,
            &fixture.meta,
            base,
            128 * 1024 * 1024,
            MAX_BATCH_SIDECARS / 2 + 1,
        )
        .unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].to, fixture.meta.sidecars.frontier.unwrap());
        assert_eq!(batches[1].to, batches[0].from);
        assert_eq!(batches[1].from, base);
    }

    type Ranges = Arc<Mutex<Vec<(u64, u64)>>>;

    /// Serves every requested column of a range and records the ranges asked for.
    fn serve_ranges(
        columns: Vec<DataColumnSidecar>,
    ) -> (
        mpsc::UnboundedSender<P2PMessage>,
        Ranges,
        tokio::task::JoinHandle<()>,
    ) {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let ranges = Arc::new(Mutex::new(Vec::new()));
        let seen = ranges.clone();
        let server = tokio::spawn(async move {
            while let Some(P2PMessage::Request(P2PRequest::DataColumnRange {
                start,
                count,
                columns: indices,
                callback,
                ..
            })) = receiver.recv().await
            {
                seen.lock().unwrap().push((start, count));
                for column in columns.iter().filter(|column| {
                    (start..start + count).contains(&column.signed_block_header.message.slot)
                        && indices.contains(&column.index)
                }) {
                    let response = BeaconResponseMessage::DataColumnSidecarsByRange(column.clone());
                    let _ = callback
                        .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(response))))
                        .await;
                }
                let _ = callback.send(Ok(P2PCallbackResponse::EndOfStream)).await;
            }
        });
        (sender, ranges, server)
    }

    #[tokio::test]
    async fn the_next_step_downloads_below_batches_still_committing() {
        let fixture = fixture();
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let (sender, ranges, server) = serve_ranges(fixture.columns.clone());
        let block_bytes = (2048 + 48 + 48 + 512) * 128;
        let driver = |max_pending_bytes| ColumnBackfill {
            db: fixture.db.clone(),
            sender: sender.clone(),
            network: fixture.network.clone(),
            config: BackfillConfig {
                max_pending_bytes,
                ..BackfillConfig::default()
            },
            rate_limit: false,
            custody: ColumnCustody::all(),
        };
        let (_running_sender, running) = watch::channel(true);
        let (mut banned, mut requests, mut in_flight) = (HashMap::new(), HashMap::new(), None);
        // The budget fits only the block at base + 3; a worker commits it.
        driver(block_bytes)
            .step(&running, &mut banned, &mut requests, &mut in_flight)
            .await
            .unwrap();
        assert_eq!(
            in_flight.as_ref().map(|flight| flight.frontier),
            Some(base + 2)
        );
        // The next step plans below it within what the worker leaves of the budget.
        let next = driver(2 * block_bytes);
        let committed = next
            .step(&running, &mut banned, &mut requests, &mut in_flight)
            .await
            .unwrap();
        assert_eq!(committed.unwrap().sidecars.frontier, Some(base + 2));
        let committed = next.finish(&mut in_flight, &mut banned).await.unwrap();
        assert_eq!(committed.unwrap().sidecars.frontier, Some(base));
        assert_eq!(*ranges.lock().unwrap(), vec![(base + 2, 2), (base, 2)]);
        server.abort();
    }

    #[tokio::test]
    async fn downloads_below_an_uncommitted_worker_are_dropped() {
        let fixture = fixture();
        let base = fixture.meta.blocks.frontier.oldest_block_slot;
        let (sender, _ranges, server) = serve_ranges(fixture.columns.clone());
        let driver = ColumnBackfill {
            db: fixture.db.clone(),
            sender,
            network: fixture.network.clone(),
            config: BackfillConfig::default(),
            rate_limit: false,
            custody: ColumnCustody::all(),
        };
        let (_running_sender, running) = watch::channel(true);
        let mut banned = HashMap::new();
        // A worker that committed nothing, as after a pause.
        let mut in_flight = Some(InFlight {
            worker: tokio::spawn(async { Ok((None, None)) }),
            frontier: base + 2,
            bytes: 0,
        });
        let committed = driver
            .step(&running, &mut banned, &mut HashMap::new(), &mut in_flight)
            .await
            .unwrap();
        assert!(committed.is_none() && in_flight.is_none());
        assert_eq!(current(&fixture.db), fixture.meta);
        let column = &fixture.columns[0];
        let key = ream_consensus_beacon::data_column_sidecar::ColumnIdentifier::new(
            column.signed_block_header.message.tree_hash_root(),
            column.index,
        );
        assert_eq!(
            fixture.db.column_sidecars_provider().get(key).unwrap(),
            None
        );
        server.abort();
    }
}

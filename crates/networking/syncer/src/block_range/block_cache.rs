use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use anyhow::{bail, ensure};
use libp2p::PeerId;
use ream_chain_beacon::beacon_chain::is_data_availability_check_required;
use ream_consensus_beacon::{
    blob_sidecar::{BlobIdentifier, BlobSidecar},
    data_column_sidecar::{ColumnIdentifier, DataColumnSidecar},
    electra::beacon_block::SignedBeaconBlock,
};
use ream_consensus_misc::misc::compute_epoch_at_slot;
use ream_network_spec::networks::beacon_network_spec;
use ream_polynomial_commitments::handlers::{
    verify_blob_kzg_proof_batch, verify_data_column_sidecar_kzg_proofs,
};
use ssz::Encode;
use tree_hash::TreeHash;

use super::{FrontierObservation, MAX_BLOCKS_PER_REQUEST, peer_range_downloader::Range};

const ATTEMPT_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct CoverageAnchor {
    pub frontier: FrontierObservation,
    pub original_parent_root: B256,
    pub original_parent_slot: u64,
    pub covered_through_slot: u64,
    pub confirming_peers: HashSet<PeerId>,
}

#[derive(Debug)]
pub enum AddBlocksError {
    InvalidBatch(anyhow::Error),
    CoverageDivergence {
        expected_parent: B256,
        actual_parent: B256,
        anchor: Box<CoverageAnchor>,
    },
}

impl std::fmt::Display for AddBlocksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddBlocksError::InvalidBatch(err) => write!(f, "invalid batch: {err:?}"),
            AddBlocksError::CoverageDivergence {
                expected_parent,
                actual_parent,
                ..
            } => write!(
                f,
                "coverage divergence: expected parent {expected_parent}, got {actual_parent}"
            ),
        }
    }
}

impl From<anyhow::Error> for AddBlocksError {
    fn from(err: anyhow::Error) -> Self {
        AddBlocksError::InvalidBatch(err)
    }
}

pub(super) fn validate_range_chain(blocks: &[SignedBeaconBlock]) -> anyhow::Result<()> {
    for (index, block) in blocks.iter().enumerate().rev() {
        if index > 0 {
            ensure!(
                block.message.parent_root == blocks[index - 1].message.tree_hash_root(),
                "Block at index {index} has a parent root that does not match the previous block's tree hash root",
            );
            ensure!(
                block.message.slot > blocks[index - 1].message.slot,
                "Block at index {index} does not have a strictly increasing slot",
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKey {
    BlockRange(Range),
    ColumnRange(Range),
    BlockRoot(B256),
    Blob(BlobIdentifier),
    Column(ColumnIdentifier),
}

#[derive(Default)]
struct AttemptState {
    attempted_peers: HashSet<PeerId>,
    cooldown_until: Option<Instant>,
}

pub struct BlockAndBlobBundle {
    pub block: SignedBeaconBlock,
    pub blobs: HashMap<BlobIdentifier, BlobSidecar>,
    pub columns: HashMap<ColumnIdentifier, DataColumnSidecar>,
    pub source_peer: PeerId,
}

impl BlockAndBlobBundle {
    pub fn new(block: SignedBeaconBlock, source_peer: PeerId) -> Self {
        Self {
            block,
            blobs: HashMap::new(),
            columns: HashMap::new(),
            source_peer,
        }
    }
}

pub struct BlockCache {
    blocks_and_blobs: HashMap<B256, BlockAndBlobBundle>,
    current_cache_size: u64,
    initial_parent_root: B256,
    block_ranges_to_retry: Vec<Range>,
    initial_slot: u64,
    next_start_slot: u64,
    block_ranges_in_progress: HashSet<Range>,
    block_roots_in_progress: HashSet<B256>,
    blob_identifiers_in_progress: HashSet<BlobIdentifier>,
    column_ranges_to_fetch: Vec<Range>,
    column_ranges_in_progress: HashSet<Range>,
    data_column_identifiers_in_progress: HashSet<ColumnIdentifier>,
    attempts: HashMap<RequestKey, AttemptState>,
    coverage_anchor: Option<CoverageAnchor>,
}

impl BlockCache {
    pub fn new(initial_parent_root: B256, next_start_slot: u64) -> Self {
        Self {
            blocks_and_blobs: HashMap::new(),
            current_cache_size: 0,
            initial_parent_root,
            block_ranges_to_retry: vec![],
            initial_slot: next_start_slot,
            next_start_slot,
            block_ranges_in_progress: HashSet::new(),
            block_roots_in_progress: HashSet::new(),
            blob_identifiers_in_progress: HashSet::new(),
            column_ranges_to_fetch: vec![],
            column_ranges_in_progress: HashSet::new(),
            data_column_identifiers_in_progress: HashSet::new(),
            attempts: HashMap::new(),
            coverage_anchor: None,
        }
    }

    pub fn from_recovery_seed(seed: super::recovery::RecoverySeed) -> anyhow::Result<Self> {
        let super::recovery::RecoverySeed {
            ancestor_root,
            ancestor_slot,
            forward_blocks,
            target_slot,
            source_peer,
        } = seed;

        ensure!(
            !forward_blocks.is_empty(),
            "a recovery seed must contain at least one new block"
        );
        validate_range_chain(&forward_blocks)?;

        let first = &forward_blocks[0];
        ensure!(
            first.message.parent_root == ancestor_root,
            "recovery seed's first block does not connect to the ancestor root"
        );
        ensure!(
            first.message.slot > ancestor_slot,
            "recovery seed's first block is not after the ancestor slot"
        );

        let mut seen_roots = HashSet::new();
        for block in &forward_blocks {
            ensure!(
                block.message.slot <= target_slot,
                "recovery seed block at slot {} exceeds target_slot {target_slot}",
                block.message.slot
            );
            ensure!(
                seen_roots.insert(block.message.tree_hash_root()),
                "duplicate root in recovery seed"
            );
        }

        let tip_slot = forward_blocks
            .last()
            .expect("checked non-empty above")
            .message
            .slot;

        let mut cache = BlockCache::new(ancestor_root, ancestor_slot);
        cache
            .add_blocks(forward_blocks, true, source_peer)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        cache.next_start_slot = tip_slot;
        Ok(cache)
    }

    fn is_pristine_for_advance(&self) -> bool {
        self.blocks_and_blobs.is_empty()
            && self.block_ranges_to_retry.is_empty()
            && self.block_ranges_in_progress.is_empty()
            && self.block_roots_in_progress.is_empty()
            && self.blob_identifiers_in_progress.is_empty()
            && self.column_ranges_to_fetch.is_empty()
            && self.column_ranges_in_progress.is_empty()
            && self.data_column_identifiers_in_progress.is_empty()
    }

    pub fn is_pristine_for_restore(&self) -> bool {
        self.coverage_anchor.is_none() && self.is_pristine_for_advance()
    }

    pub fn advance_empty_coverage(
        &mut self,
        frontier: FrontierObservation,
        parent_root: B256,
        covered_through_slot: u64,
        confirming_peers: HashSet<PeerId>,
    ) -> anyhow::Result<()> {
        match &mut self.coverage_anchor {
            Some(anchor) => {
                anchor.covered_through_slot = covered_through_slot;
                anchor.confirming_peers.extend(confirming_peers);
            }
            None => {
                ensure!(
                    self.is_pristine_for_advance(),
                    "advance_empty_coverage requires a pristine cache to start a new generation"
                );
                self.coverage_anchor = Some(CoverageAnchor {
                    frontier,
                    original_parent_root: self.initial_parent_root,
                    original_parent_slot: self.initial_slot,
                    covered_through_slot,
                    confirming_peers,
                });
            }
        }

        self.initial_parent_root = parent_root;
        self.next_start_slot = covered_through_slot;
        self.initial_slot = covered_through_slot;
        Ok(())
    }

    fn refresh_attempt_round(&mut self, key: &RequestKey, now: Instant) {
        if let Some(state) = self.attempts.get_mut(key)
            && let Some(cooldown_until) = state.cooldown_until
            && now >= cooldown_until
        {
            state.attempted_peers.clear();
            state.cooldown_until = None;
        }
    }

    fn is_schedulable(
        &mut self,
        key: RequestKey,
        candidate_peers: &[PeerId],
        now: Instant,
    ) -> bool {
        self.refresh_attempt_round(&key, now);
        match self.attempts.get(&key) {
            None => true,
            Some(state) => candidate_peers
                .iter()
                .any(|peer_id| !state.attempted_peers.contains(peer_id)),
        }
    }

    pub fn attempted_peers_for(&self, key: RequestKey) -> HashSet<PeerId> {
        self.attempts
            .get(&key)
            .map(|state| state.attempted_peers.clone())
            .unwrap_or_default()
    }

    pub fn mark_attempted(
        &mut self,
        key: RequestKey,
        peer_id: PeerId,
        candidate_peers: &[PeerId],
        now: Instant,
    ) {
        let state = self.attempts.entry(key).or_default();
        state.attempted_peers.insert(peer_id);
        if candidate_peers
            .iter()
            .all(|peer_id| state.attempted_peers.contains(peer_id))
        {
            state.cooldown_until = Some(now + ATTEMPT_COOLDOWN);
        }
    }

    pub fn clear_attempted(&mut self, key: RequestKey) {
        self.attempts.remove(&key);
    }

    pub fn add_blocks(
        &mut self,
        blocks: Vec<SignedBeaconBlock>,
        is_range: bool,
        source_peer: PeerId,
    ) -> Result<(), AddBlocksError> {
        // Ensure that all blocks form a chain
        if is_range {
            validate_range_chain(&blocks)?;

            if self.blocks_and_blobs.is_empty()
                && let Some(anchor) = &self.coverage_anchor
                && let Some(first) = blocks.first()
            {
                if first.message.parent_root != self.initial_parent_root {
                    return Err(AddBlocksError::CoverageDivergence {
                        expected_parent: self.initial_parent_root,
                        actual_parent: first.message.parent_root,
                        anchor: Box::new(anchor.clone()),
                    });
                }
                self.coverage_anchor = None;
            }
        }

        for block in blocks {
            self.current_cache_size += block.as_ssz_bytes().len() as u64;
            self.blocks_and_blobs.insert(
                block.message.tree_hash_root(),
                BlockAndBlobBundle::new(block, source_peer),
            );
        }

        Ok(())
    }

    pub fn add_blobs(&mut self, blobs: Vec<BlobSidecar>) -> anyhow::Result<()> {
        let mut validated = Vec::with_capacity(blobs.len());
        for blob_sidecar in blobs {
            let block_root = blob_sidecar.signed_block_header.message.tree_hash_root();
            let Some(bundle) = self.blocks_and_blobs.get(&block_root) else {
                bail!("Block root {block_root} not found in cache, this should be impossible");
            };

            ensure!(
                blob_sidecar.signed_block_header == bundle.block.signed_header(),
                "Blob sidecar {} does not belong to block {block_root}",
                blob_sidecar.index
            );
            let commitments = &bundle.block.message.body.blob_kzg_commitments;
            let index = blob_sidecar.index as usize;
            ensure!(
                index < commitments.len(),
                "Blob sidecar index {} out of range for block {block_root}",
                blob_sidecar.index
            );
            ensure!(
                blob_sidecar.kzg_commitment == commitments[index],
                "Blob sidecar {} commitment does not match block {block_root}",
                blob_sidecar.index
            );
            ensure!(
                blob_sidecar.verify_blob_sidecar_inclusion_proof(),
                "Invalid inclusion proof for blob {} of block {block_root}",
                blob_sidecar.index
            );
            ensure!(
                verify_blob_kzg_proof_batch(
                    std::slice::from_ref(&blob_sidecar.blob),
                    std::slice::from_ref(&blob_sidecar.kzg_commitment),
                    std::slice::from_ref(&blob_sidecar.kzg_proof),
                )?,
                "Invalid KZG proof for blob {} of block {block_root}",
                blob_sidecar.index
            );

            validated.push((block_root, blob_sidecar));
        }

        for (block_root, blob_sidecar) in validated {
            let bundle = self
                .blocks_and_blobs
                .get_mut(&block_root)
                .expect("presence already checked in the validation pass above");
            bundle.blobs.insert(
                BlobIdentifier {
                    block_root,
                    index: blob_sidecar.index,
                },
                blob_sidecar,
            );
        }

        Ok(())
    }

    pub fn add_data_columns(
        &mut self,
        columns: Vec<DataColumnSidecar>,
        required_columns: &HashSet<u64>,
    ) -> anyhow::Result<()> {
        let mut validated = Vec::with_capacity(columns.len());
        for column in columns {
            if !required_columns.contains(&column.index) {
                continue;
            }

            let block_root = column.signed_block_header.message.tree_hash_root();
            if !self.blocks_and_blobs.contains_key(&block_root) {
                continue;
            }

            let bundle = self
                .blocks_and_blobs
                .get(&block_root)
                .expect("presence just checked above");
            ensure!(
                column.signed_block_header == bundle.block.signed_header(),
                "Data column sidecar {} does not belong to block {block_root}",
                column.index
            );
            ensure!(
                column.verify_inclusion_proof(),
                "Invalid inclusion proof for column {} of block {block_root}",
                column.index
            );
            ensure!(
                verify_data_column_sidecar_kzg_proofs(&column)?,
                "Invalid KZG proof for column {} of block {block_root}",
                column.index
            );

            validated.push((block_root, column));
        }

        for (block_root, column) in validated {
            let bundle = self
                .blocks_and_blobs
                .get_mut(&block_root)
                .expect("presence already checked in the validation pass above");
            bundle
                .columns
                .insert(ColumnIdentifier::new(block_root, column.index), column);
        }

        Ok(())
    }

    pub fn extend_block_roots_in_progress(&mut self, block_roots: &[B256]) {
        self.block_roots_in_progress.extend(block_roots);
    }

    pub fn remove_block_roots_in_progress(&mut self, block_roots: &[B256]) {
        for root in block_roots {
            self.block_roots_in_progress.remove(root);
        }
    }

    pub fn extend_blob_identifiers_in_progress(&mut self, blob_identifiers: &[BlobIdentifier]) {
        self.blob_identifiers_in_progress.extend(blob_identifiers);
    }

    pub fn remove_blob_identifiers_in_progress(&mut self, blob_identifiers: &[BlobIdentifier]) {
        for identifier in blob_identifiers {
            self.blob_identifiers_in_progress.remove(identifier);
        }
    }

    pub fn push_column_range(&mut self, range: Range) {
        self.column_ranges_to_fetch.push(range);
    }

    pub fn mark_column_range_in_progress(&mut self, range: Range) {
        self.column_ranges_in_progress.insert(range);
    }

    pub fn remove_column_range_in_progress(&mut self, range: &Range) {
        self.column_ranges_in_progress.remove(range);
    }

    pub fn extend_data_column_identifiers_in_progress(&mut self, identifiers: &[ColumnIdentifier]) {
        self.data_column_identifiers_in_progress.extend(identifiers);
    }

    pub fn remove_data_column_identifiers_in_progress(&mut self, identifiers: &[ColumnIdentifier]) {
        for identifier in identifiers {
            self.data_column_identifiers_in_progress.remove(identifier);
        }
    }

    pub fn block_count(&self) -> u64 {
        self.blocks_and_blobs.len() as u64
    }

    pub fn blob_count(&self) -> u64 {
        self.blocks_and_blobs
            .values()
            .map(|bundle| bundle.block.message.body.blob_kzg_commitments.len() as u64)
            .sum()
    }

    pub fn downloaded_blob_count(&self) -> u64 {
        self.blocks_and_blobs
            .values()
            .map(|bundle| bundle.blobs.len() as u64)
            .sum()
    }

    pub fn next_start_slot(&self) -> u64 {
        self.next_start_slot
    }

    pub fn initial_parent_root(&self) -> B256 {
        self.initial_parent_root
    }

    pub fn estimated_blocks_to_fetch(&self) -> u64 {
        if self.next_start_slot.saturating_sub(self.initial_slot) > 30 {
            return 0;
        }

        MAX_BLOCKS_PER_REQUEST
    }

    pub fn push_retry_range(&mut self, range: Range) {
        self.block_ranges_to_retry.push(range);
    }

    pub fn mark_block_range_in_progress(&mut self, range: Range) {
        self.block_ranges_in_progress.insert(range);
    }

    pub fn remove_block_range_in_progress(&mut self, range: &Range) {
        self.block_ranges_in_progress.remove(range);
    }

    fn take_schedulable_retry_range(
        &mut self,
        candidate_peers: &[PeerId],
        now: Instant,
    ) -> Option<Range> {
        let ranges = self.block_ranges_to_retry.clone();
        for (index, range) in ranges.iter().enumerate().rev() {
            if self.is_schedulable(RequestKey::BlockRange(*range), candidate_peers, now) {
                return Some(self.block_ranges_to_retry.remove(index));
            }
        }
        None
    }

    fn take_schedulable_column_range(
        &mut self,
        candidate_peers: &[PeerId],
        now: Instant,
    ) -> Option<Range> {
        let ranges = self.column_ranges_to_fetch.clone();
        for (index, range) in ranges.iter().enumerate().rev() {
            if self.is_schedulable(RequestKey::ColumnRange(*range), candidate_peers, now) {
                return Some(self.column_ranges_to_fetch.remove(index));
            }
        }
        None
    }

    pub fn data_to_fetch(
        &mut self,
        target_slot: u64,
        current_epoch: u64,
        required_columns: &HashSet<u64>,
        candidate_peers: &[PeerId],
        now: Instant,
        frontier_tracked: bool,
    ) -> DataToFetch {
        let single_flight = frontier_tracked || self.coverage_anchor.is_some();
        if single_flight && !self.block_ranges_in_progress.is_empty() {
            return DataToFetch::DownloadsInProgress;
        }

        if let Some(range) = self.take_schedulable_retry_range(candidate_peers, now) {
            return DataToFetch::BlockRange(range);
        }

        let estimated_blocks_to_fetch = self.estimated_blocks_to_fetch();
        if estimated_blocks_to_fetch > 0 && self.next_start_slot < target_slot {
            let blocks_to_fill = estimated_blocks_to_fetch
                .min(MAX_BLOCKS_PER_REQUEST.min(target_slot - self.next_start_slot));
            let start_slot = self.next_start_slot + 1;
            self.next_start_slot += blocks_to_fill;
            return DataToFetch::BlockRange(Range::new(start_slot, blocks_to_fill));
        }

        if let Some(range) = self.take_schedulable_column_range(candidate_peers, now) {
            return DataToFetch::DataColumnRange(range);
        }

        let mut block_roots_left_to_fetch = self.get_missing_block_roots();
        let missing_block_roots_len = block_roots_left_to_fetch.len();
        block_roots_left_to_fetch.retain(|root| {
            !self.block_roots_in_progress.contains(root)
                && self.is_schedulable(RequestKey::BlockRoot(*root), candidate_peers, now)
        });

        let mut blob_identifiers_left_to_fetch = self.get_missing_blob_identifiers(current_epoch);
        let missing_blob_identifiers_len = blob_identifiers_left_to_fetch.len();
        blob_identifiers_left_to_fetch.retain(|blob_identifier| {
            !self.blob_identifiers_in_progress.contains(blob_identifier)
                && self.is_schedulable(RequestKey::Blob(*blob_identifier), candidate_peers, now)
        });

        let mut data_column_identifiers_left_to_fetch =
            self.get_missing_data_column_identifiers(current_epoch, required_columns);
        let missing_data_column_identifiers_len = data_column_identifiers_left_to_fetch.len();
        data_column_identifiers_left_to_fetch.retain(|identifier| {
            !self
                .data_column_identifiers_in_progress
                .contains(identifier)
                && self.is_schedulable(RequestKey::Column(*identifier), candidate_peers, now)
        });

        if !block_roots_left_to_fetch.is_empty() {
            return DataToFetch::MissingBlockRoots(block_roots_left_to_fetch);
        }

        if !blob_identifiers_left_to_fetch.is_empty() {
            return DataToFetch::MissingBlobIdentifiers(blob_identifiers_left_to_fetch);
        }

        if !data_column_identifiers_left_to_fetch.is_empty() {
            return DataToFetch::MissingDataColumnIdentifiers(
                data_column_identifiers_left_to_fetch,
            );
        }

        if missing_block_roots_len > 0
            || missing_blob_identifiers_len > 0
            || missing_data_column_identifiers_len > 0
            || !self.block_ranges_in_progress.is_empty()
            || !self.column_ranges_in_progress.is_empty()
            || !self.block_ranges_to_retry.is_empty()
            || !self.column_ranges_to_fetch.is_empty()
        {
            return DataToFetch::DownloadsInProgress;
        }

        DataToFetch::Finished
    }

    /// Return the blocks in sorted order to be processed.
    pub fn get_blocks_and_blobs(mut self) -> anyhow::Result<Vec<BlockAndBlobBundle>> {
        let missing_block_roots = self.get_missing_block_roots();
        if !missing_block_roots.is_empty() {
            bail!("Missing block roots: {}", missing_block_roots.len());
        } else {
            let mut blocks_and_blobs = self
                .blocks_and_blobs
                .drain()
                .map(|(_, block)| block)
                .collect::<Vec<_>>();
            blocks_and_blobs.sort_by_key(|block| block.block.message.slot);
            Ok(blocks_and_blobs)
        }
    }

    fn get_missing_block_roots(&self) -> Vec<B256> {
        let mut missing_roots = Vec::new();
        for block in self.blocks_and_blobs.values() {
            if !self
                .blocks_and_blobs
                .contains_key(&block.block.message.parent_root)
                && block.block.message.parent_root != self.initial_parent_root
            {
                missing_roots.push(block.block.message.parent_root);
            }
        }
        missing_roots
    }

    fn get_missing_blob_identifiers(&self, current_epoch: u64) -> Vec<BlobIdentifier> {
        let network_spec = beacon_network_spec();
        let mut missing_roots = Vec::new();
        for block in self.blocks_and_blobs.values() {
            if !is_data_availability_check_required(
                compute_epoch_at_slot(block.block.message.slot),
                current_epoch,
                network_spec.fulu_fork_epoch,
                network_spec.min_epochs_for_data_column_sidecars_requests,
            ) {
                continue;
            }

            // blob_sidecars_by_root only serves pre-Fulu blobs; post-Fulu data is distributed
            // as data column sidecars instead, fetched separately via the DA checker.
            if compute_epoch_at_slot(block.block.message.slot)
                >= beacon_network_spec().fulu_fork_epoch
            {
                continue;
            }

            let block_root = block.block.message.tree_hash_root();
            for index in 0..block.block.message.body.blob_kzg_commitments.len() {
                let blob_identifier = BlobIdentifier {
                    block_root,
                    index: index as u64,
                };
                if block.blobs.contains_key(&blob_identifier) {
                    continue;
                }
                missing_roots.push(blob_identifier);
            }
        }
        missing_roots
    }

    /// ByRoot fallback for columns a range fetch missed (e.g. root-fetched blocks).
    fn get_missing_data_column_identifiers(
        &self,
        current_epoch: u64,
        required_columns: &HashSet<u64>,
    ) -> Vec<ColumnIdentifier> {
        let network_spec = beacon_network_spec();
        let mut missing_identifiers = Vec::new();
        for block in self.blocks_and_blobs.values() {
            if block.block.message.body.blob_kzg_commitments.is_empty() {
                continue;
            }

            if !is_data_availability_check_required(
                compute_epoch_at_slot(block.block.message.slot),
                current_epoch,
                network_spec.fulu_fork_epoch,
                network_spec.min_epochs_for_data_column_sidecars_requests,
            ) {
                continue;
            }

            if compute_epoch_at_slot(block.block.message.slot) < network_spec.fulu_fork_epoch {
                continue;
            }

            let block_root = block.block.message.tree_hash_root();
            for column_index in required_columns {
                let identifier = ColumnIdentifier::new(block_root, *column_index);
                if block.columns.contains_key(&identifier) {
                    continue;
                }
                missing_identifiers.push(identifier);
            }
        }
        missing_identifiers
    }

    pub fn expected_column_identifiers_in_range(
        &self,
        range: Range,
        required_columns: &HashSet<u64>,
    ) -> Vec<ColumnIdentifier> {
        let range_end = range.start_slot + range.count;
        let mut expected = Vec::new();
        for block in self.blocks_and_blobs.values() {
            if block.block.message.slot < range.start_slot || block.block.message.slot >= range_end
            {
                continue;
            }
            let block_root = block.block.message.tree_hash_root();
            for column_index in required_columns {
                let identifier = ColumnIdentifier::new(block_root, *column_index);
                if !block.columns.contains_key(&identifier) {
                    expected.push(identifier);
                }
            }
        }
        expected
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataToFetch {
    BlockRange(Range),
    DataColumnRange(Range),
    MissingBlockRoots(Vec<B256>),
    MissingBlobIdentifiers(Vec<BlobIdentifier>),
    MissingDataColumnIdentifiers(Vec<ColumnIdentifier>),
    DownloadsInProgress,
    Finished,
}

impl std::fmt::Display for DataToFetch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DataToFetch::BlockRange(range) => write!(f, "BlockRange({range:?})"),
            DataToFetch::DataColumnRange(range) => write!(f, "DataColumnRange({range:?})"),
            DataToFetch::MissingBlockRoots(roots) => {
                write!(f, "MissingBlockRoots({})", roots.len())
            }
            DataToFetch::MissingBlobIdentifiers(identifiers) => {
                write!(f, "MissingBlobIdentifiers({})", identifiers.len())
            }
            DataToFetch::MissingDataColumnIdentifiers(identifiers) => {
                write!(f, "MissingDataColumnIdentifiers({})", identifiers.len())
            }
            DataToFetch::DownloadsInProgress => write!(f, "DownloadsInProgress"),
            DataToFetch::Finished => write!(f, "Finished"),
        }
    }
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::{
        electra::beacon_block::BeaconBlock,
        matrix_entry::{compute_cells_and_kzg_proofs, das_context},
    };
    use ream_consensus_misc::{
        misc::compute_start_slot_at_epoch, polynomial_commitments::kzg_commitment::KZGCommitment,
    };
    use ream_execution_rpc_types::get_blobs::Blob;
    use ream_network_spec::networks::beacon::initialize_test_network_spec;

    use super::*;

    #[test]
    fn data_to_fetch_finishes_at_target_slot() {
        initialize_test_network_spec();
        let mut cache = BlockCache::new(B256::ZERO, 10);

        assert_eq!(
            cache.data_to_fetch(10, 0, &HashSet::new(), &[], Instant::now(), false),
            DataToFetch::Finished
        );
    }

    /// `Finished` must not fire while a `BlockRange` is still in flight, or the download (and
    /// its peer) gets silently orphaned.
    #[test]
    fn data_to_fetch_waits_for_in_flight_block_ranges_before_finishing() {
        initialize_test_network_spec();
        let mut cache = BlockCache::new(B256::ZERO, 10);
        let range = Range::new(11, 10);
        cache.mark_block_range_in_progress(range);

        assert_eq!(
            cache.data_to_fetch(10, 0, &HashSet::new(), &[], Instant::now(), false),
            DataToFetch::DownloadsInProgress
        );

        cache.remove_block_range_in_progress(&range);
        assert_eq!(
            cache.data_to_fetch(10, 0, &HashSet::new(), &[], Instant::now(), false),
            DataToFetch::Finished
        );
    }

    #[test]
    fn data_to_fetch_requests_contiguous_non_empty_ranges() {
        initialize_test_network_spec();
        let mut cache = BlockCache::new(B256::ZERO, 10);

        assert_eq!(
            cache.data_to_fetch(25, 0, &HashSet::new(), &[], Instant::now(), false),
            DataToFetch::BlockRange(Range::new(11, 10))
        );
        assert_eq!(
            cache.data_to_fetch(25, 0, &HashSet::new(), &[], Instant::now(), false),
            DataToFetch::BlockRange(Range::new(21, 5))
        );
        assert_eq!(
            cache.data_to_fetch(25, 0, &HashSet::new(), &[], Instant::now(), false),
            DataToFetch::Finished
        );
    }

    #[test]
    fn post_fulu_blob_commitments_never_request_legacy_blob_identifiers() {
        initialize_test_network_spec();
        let network_spec = beacon_network_spec();
        let current_epoch = network_spec.fulu_fork_epoch
            + network_spec.min_epochs_for_data_column_sidecars_requests
            + 10;
        let boundary_epoch =
            current_epoch - network_spec.min_epochs_for_data_column_sidecars_requests;
        let parent_root = B256::repeat_byte(1);

        let block_with_blob = |slot| {
            let mut block = SignedBeaconBlock {
                message: BeaconBlock {
                    slot,
                    parent_root,
                    ..Default::default()
                },
                signature: Default::default(),
            };
            block
                .message
                .body
                .blob_kzg_commitments
                .push(KZGCommitment::empty_for_testing())
                .expect("one commitment should fit");
            block
        };

        let boundary_slot = compute_start_slot_at_epoch(boundary_epoch);
        let mut retained = BlockCache::new(parent_root, boundary_slot);
        retained
            .add_blocks(
                vec![block_with_blob(boundary_slot)],
                false,
                PeerId::random(),
            )
            .expect("boundary block should enter cache");
        assert_eq!(
            retained.data_to_fetch(
                boundary_slot,
                current_epoch,
                &HashSet::new(),
                &[],
                Instant::now(),
                false
            ),
            DataToFetch::Finished
        );

        let expired_slot = compute_start_slot_at_epoch(boundary_epoch - 1);
        let mut expired = BlockCache::new(parent_root, expired_slot);
        expired
            .add_blocks(vec![block_with_blob(expired_slot)], false, PeerId::random())
            .expect("expired block should enter cache");
        assert_eq!(
            expired.data_to_fetch(
                expired_slot,
                current_epoch,
                &HashSet::new(),
                &[],
                Instant::now(),
                false
            ),
            DataToFetch::Finished
        );
    }

    #[test]
    fn post_fulu_blob_commitments_request_required_data_column_identifiers() {
        initialize_test_network_spec();
        let network_spec = beacon_network_spec();
        let current_epoch = network_spec.fulu_fork_epoch
            + network_spec.min_epochs_for_data_column_sidecars_requests
            + 10;
        let boundary_epoch =
            current_epoch - network_spec.min_epochs_for_data_column_sidecars_requests;
        let parent_root = B256::repeat_byte(1);
        let boundary_slot = compute_start_slot_at_epoch(boundary_epoch);

        let mut block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: boundary_slot,
                parent_root,
                ..Default::default()
            },
            signature: Default::default(),
        };
        block
            .message
            .body
            .blob_kzg_commitments
            .push(KZGCommitment::empty_for_testing())
            .expect("one commitment should fit");
        let block_root = block.message.tree_hash_root();

        let mut cache = BlockCache::new(parent_root, boundary_slot);
        cache
            .add_blocks(vec![block], false, PeerId::random())
            .expect("boundary block should enter cache");

        let required_columns = HashSet::from([1, 5]);
        match cache.data_to_fetch(
            boundary_slot,
            current_epoch,
            &required_columns,
            &[],
            Instant::now(),
            false,
        ) {
            DataToFetch::MissingDataColumnIdentifiers(identifiers) => {
                let mut identifiers = identifiers;
                identifiers.sort();
                assert_eq!(
                    identifiers,
                    vec![
                        ColumnIdentifier::new(block_root, 1),
                        ColumnIdentifier::new(block_root, 5),
                    ]
                );
            }
            other => panic!("expected MissingDataColumnIdentifiers, got {other:?}"),
        }

        // Unneeded columns never count as missing.
        assert_eq!(
            cache.data_to_fetch(
                boundary_slot,
                current_epoch,
                &HashSet::new(),
                &[],
                Instant::now(),
                false
            ),
            DataToFetch::Finished
        );
    }

    #[test]
    fn add_data_columns_ignores_extras_and_rejects_bad_proofs() {
        use ream_consensus_beacon::data_column_sidecar::get_data_column_sidecars_from_block;

        let blob = Blob::default();
        let blob_bytes = blob.to_fixed_bytes();
        let raw_commitment = das_context()
            .blob_to_kzg_commitment(&blob_bytes)
            .expect("test blob should produce a commitment");
        let commitment = KZGCommitment(raw_commitment);

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

        let cells_and_kzg_proofs = compute_cells_and_kzg_proofs(&blob, das_context())
            .expect("test blob should produce cells and proofs");
        let columns = get_data_column_sidecars_from_block(&block, vec![cells_and_kzg_proofs])
            .expect("test block should produce data columns");

        let mut cache = BlockCache::new(B256::ZERO, 0);
        cache
            .add_blocks(vec![block], false, PeerId::random())
            .expect("block should enter cache");

        // Only column 0 was requested; extra columns in the response are ignored, not fatal.
        let required_columns = HashSet::from([0]);
        cache
            .add_data_columns(columns.clone(), &required_columns)
            .expect("valid, requested column should be accepted");
        assert_eq!(
            cache
                .blocks_and_blobs
                .get(&block_root)
                .expect("block should be cached")
                .columns
                .len(),
            1
        );

        let mut tampered = columns[0].clone();
        tampered.kzg_proofs[0][0] ^= 1;
        assert!(
            cache
                .add_data_columns(vec![tampered], &required_columns)
                .is_err()
        );
    }

    #[test]
    fn add_data_columns_is_atomic_a_bad_item_does_not_leave_earlier_items_mutated() {
        use ream_consensus_beacon::data_column_sidecar::get_data_column_sidecars_from_block;

        let blob = Blob::default();
        let blob_bytes = blob.to_fixed_bytes();
        let raw_commitment = das_context()
            .blob_to_kzg_commitment(&blob_bytes)
            .expect("test blob should produce a commitment");
        let commitment = KZGCommitment(raw_commitment);

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

        let cells_and_kzg_proofs = compute_cells_and_kzg_proofs(&blob, das_context())
            .expect("test blob should produce cells and proofs");
        let columns = get_data_column_sidecars_from_block(&block, vec![cells_and_kzg_proofs])
            .expect("test block should produce data columns");
        let block_root = block.message.tree_hash_root();

        let mut cache = BlockCache::new(B256::ZERO, 0);
        cache
            .add_blocks(vec![block], false, PeerId::random())
            .expect("block should enter cache");

        let mut tampered = columns[1].clone();
        tampered.kzg_proofs[0][0] ^= 1;
        let required_columns = HashSet::from([0, 1]);

        let result = cache.add_data_columns(vec![columns[0].clone(), tampered], &required_columns);
        assert!(result.is_err(), "the batch as a whole must fail");

        assert!(
            cache
                .blocks_and_blobs
                .get(&block_root)
                .expect("block should still be cached")
                .columns
                .is_empty(),
            "a failed batch must not partially mutate the cache"
        );
    }

    #[test]
    fn is_schedulable_false_only_when_every_candidate_is_attempted() {
        let mut cache = BlockCache::new(B256::ZERO, 0);
        let key = RequestKey::BlockRoot(B256::repeat_byte(1));
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let candidates = [peer_a, peer_b];
        let now = Instant::now();

        assert!(cache.is_schedulable(key, &candidates, now));

        cache.mark_attempted(key, peer_a, &candidates, now);
        assert!(cache.is_schedulable(key, &candidates, now));

        cache.mark_attempted(key, peer_b, &candidates, now);
        assert!(!cache.is_schedulable(key, &candidates, now));
    }

    #[test]
    fn cooldown_expiring_resets_the_attempted_set_for_a_fresh_round() {
        let mut cache = BlockCache::new(B256::ZERO, 0);
        let key = RequestKey::BlockRoot(B256::repeat_byte(1));
        let peer_a = PeerId::random();
        let candidates = [peer_a];
        let now = Instant::now();

        cache.mark_attempted(key, peer_a, &candidates, now);
        assert!(!cache.is_schedulable(key, &candidates, now));

        assert!(!cache.is_schedulable(key, &candidates, now + Duration::from_secs(1)));

        assert!(cache.is_schedulable(
            key,
            &candidates,
            now + ATTEMPT_COOLDOWN + Duration::from_secs(1)
        ));
    }

    #[test]
    fn a_new_peer_makes_an_exhausted_key_schedulable_without_waiting_for_cooldown() {
        let mut cache = BlockCache::new(B256::ZERO, 0);
        let key = RequestKey::BlockRoot(B256::repeat_byte(1));
        let peer_a = PeerId::random();
        let peer_b = PeerId::random();
        let now = Instant::now();

        cache.mark_attempted(key, peer_a, &[peer_a], now);
        assert!(!cache.is_schedulable(key, &[peer_a], now));

        assert!(cache.is_schedulable(key, &[peer_a, peer_b], now));
    }

    #[test]
    fn clear_attempted_starts_a_clean_round() {
        let mut cache = BlockCache::new(B256::ZERO, 0);
        let key = RequestKey::BlockRoot(B256::repeat_byte(1));
        let peer_a = PeerId::random();
        let now = Instant::now();

        cache.mark_attempted(key, peer_a, &[peer_a], now);
        assert!(!cache.is_schedulable(key, &[peer_a], now));

        cache.clear_attempted(key);
        assert!(cache.is_schedulable(key, &[peer_a], now));
        assert!(cache.attempted_peers_for(key).is_empty());
    }

    #[test]
    fn take_schedulable_retry_range_skips_backed_off_ranges_but_keeps_them_queued() {
        let mut cache = BlockCache::new(B256::ZERO, 0);
        let backed_off = Range::new(1, 10);
        let schedulable = Range::new(11, 10);
        let peer_a = PeerId::random();
        let now = Instant::now();

        cache.push_retry_range(backed_off);
        cache.push_retry_range(schedulable);
        cache.mark_attempted(RequestKey::BlockRange(backed_off), peer_a, &[peer_a], now);

        assert_eq!(
            cache.take_schedulable_retry_range(&[peer_a], now),
            Some(schedulable)
        );
        assert_eq!(cache.block_ranges_to_retry, vec![backed_off]);
        assert_eq!(cache.take_schedulable_retry_range(&[peer_a], now), None);
    }

    #[test]
    fn an_exhausted_backed_off_root_does_not_starve_other_tiers_or_cause_false_finished() {
        initialize_test_network_spec();
        let parent_root = B256::repeat_byte(1);
        let mut block = SignedBeaconBlock {
            message: BeaconBlock {
                slot: 1,
                parent_root,
                ..Default::default()
            },
            signature: Default::default(),
        };
        block.message.parent_root = B256::repeat_byte(2);
        let mut cache = BlockCache::new(parent_root, 1);
        cache
            .add_blocks(vec![block], false, PeerId::random())
            .expect("block should enter cache");

        let peer_a = PeerId::random();
        let now = Instant::now();
        let missing_root = B256::repeat_byte(2);

        cache.mark_attempted(RequestKey::BlockRoot(missing_root), peer_a, &[peer_a], now);

        assert_eq!(
            cache.data_to_fetch(1, 0, &HashSet::new(), &[peer_a], now, false),
            DataToFetch::DownloadsInProgress
        );
    }

    #[test]
    fn data_to_fetch_filters_out_only_the_exhausted_root_not_the_whole_tier() {
        initialize_test_network_spec();
        let parent_root = B256::repeat_byte(1);
        let root_a = B256::repeat_byte(2);
        let root_b = B256::repeat_byte(3);
        let block1 = SignedBeaconBlock {
            message: BeaconBlock {
                slot: 1,
                parent_root: root_a,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let block2 = SignedBeaconBlock {
            message: BeaconBlock {
                slot: 2,
                parent_root: root_b,
                ..Default::default()
            },
            signature: Default::default(),
        };

        let mut cache = BlockCache::new(parent_root, 2);
        cache
            .add_blocks(vec![block1, block2], false, PeerId::random())
            .expect("blocks should enter cache");

        let peer_a = PeerId::random();
        let now = Instant::now();
        cache.mark_attempted(RequestKey::BlockRoot(root_a), peer_a, &[peer_a], now);

        match cache.data_to_fetch(2, 0, &HashSet::new(), &[peer_a], now, false) {
            DataToFetch::MissingBlockRoots(roots) => {
                assert_eq!(roots, vec![root_b]);
            }
            other => panic!("expected MissingBlockRoots, got {other:?}"),
        }
    }

    #[test]
    fn add_data_columns_drops_a_column_for_an_unknown_block_without_erroring_or_banning() {
        use ream_consensus_beacon::data_column_sidecar::get_data_column_sidecars_from_block;

        let blob = Blob::default();
        let blob_bytes = blob.to_fixed_bytes();
        let raw_commitment = das_context()
            .blob_to_kzg_commitment(&blob_bytes)
            .expect("test blob should produce a commitment");
        let commitment = KZGCommitment(raw_commitment);

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

        let cells_and_kzg_proofs = compute_cells_and_kzg_proofs(&blob, das_context())
            .expect("test blob should produce cells and proofs");
        let columns = get_data_column_sidecars_from_block(&block, vec![cells_and_kzg_proofs])
            .expect("test block should produce data columns");

        let mut cache = BlockCache::new(B256::ZERO, 0);
        let required_columns = HashSet::from([0]);
        let result = cache.add_data_columns(vec![columns[0].clone()], &required_columns);

        assert!(
            result.is_ok(),
            "a column for a block not yet in the cache must be dropped, not erroring the batch"
        );
    }

    fn test_observation(anchor_root: B256, anchor_slot: u64) -> FrontierObservation {
        FrontierObservation {
            anchor_root,
            anchor_slot,
            phase: super::super::SyncPhase::Finalized,
            scan_start_slot: anchor_slot,
            target_slot: anchor_slot + 100,
        }
    }

    fn child_block(parent_root: B256, slot: u64) -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                parent_root,
                ..Default::default()
            },
            signature: Default::default(),
        }
    }

    #[test]
    fn advance_empty_coverage_opens_a_coverage_anchor_that_a_connecting_block_clears() {
        let root = B256::repeat_byte(1);
        let mut cache = BlockCache::new(root, 10);
        assert!(cache.coverage_anchor.is_none());

        cache
            .advance_empty_coverage(test_observation(root, 10), root, 20, HashSet::new())
            .expect("advancing a pristine cache should succeed");
        assert!(
            cache.coverage_anchor.is_some(),
            "a coverage advance must open an anchor pending confirmation"
        );
        assert_eq!(cache.next_start_slot(), 20);
        assert_eq!(
            cache.initial_parent_root(),
            root,
            "an empty span never changes the anchor root"
        );

        cache
            .add_blocks(vec![child_block(root, 21)], true, PeerId::random())
            .expect("a directly-connecting block must be accepted");
        assert!(
            cache.coverage_anchor.is_none(),
            "a connecting first block after the advance must clear the anchor"
        );
    }

    #[test]
    fn a_non_connecting_block_after_a_coverage_advance_is_reported_as_divergence_not_a_missing_parent()
     {
        let root = B256::repeat_byte(1);
        let mut cache = BlockCache::new(root, 10);
        cache
            .advance_empty_coverage(test_observation(root, 10), root, 20, HashSet::new())
            .expect("advancing a pristine cache should succeed");

        let wrong_parent = B256::repeat_byte(2);
        let result = cache.add_blocks(vec![child_block(wrong_parent, 21)], true, PeerId::random());

        match result {
            Err(AddBlocksError::CoverageDivergence {
                expected_parent,
                actual_parent,
                ..
            }) => {
                assert_eq!(expected_parent, root);
                assert_eq!(actual_parent, wrong_parent);
            }
            other => panic!("expected CoverageDivergence, got {other:?}"),
        }
        assert_eq!(
            cache.block_count(),
            0,
            "a divergent batch must not be committed to the cache"
        );
    }

    #[test]
    fn advance_empty_coverage_extends_within_the_same_generation_without_losing_the_original_anchor()
     {
        let root = B256::repeat_byte(1);
        let mut cache = BlockCache::new(root, 10);
        cache
            .advance_empty_coverage(
                test_observation(root, 10),
                root,
                20,
                HashSet::from([PeerId::random()]),
            )
            .expect("first advance should succeed");
        let second_peer = PeerId::random();
        cache
            .advance_empty_coverage(
                test_observation(root, 10),
                root,
                30,
                HashSet::from([second_peer]),
            )
            .expect("a second advance within the same generation should succeed");

        assert_eq!(cache.next_start_slot(), 30);
        let anchor = cache
            .coverage_anchor
            .as_ref()
            .expect("anchor should still be open");
        assert_eq!(
            anchor.original_parent_root, root,
            "the original pre-generation anchor must survive a second advance"
        );
        assert_eq!(anchor.covered_through_slot, 30);
        assert!(anchor.confirming_peers.contains(&second_peer));
    }

    #[test]
    fn single_flight_blocks_a_second_block_range_while_a_frontier_is_tracked() {
        let mut untracked = BlockCache::new(B256::ZERO, 10);
        untracked.mark_block_range_in_progress(Range::new(11, 10));
        assert_ne!(
            untracked.data_to_fetch(100, 0, &HashSet::new(), &[], Instant::now(), false),
            DataToFetch::DownloadsInProgress,
        );

        let mut tracked = BlockCache::new(B256::ZERO, 10);
        tracked.mark_block_range_in_progress(Range::new(11, 10));
        assert_eq!(
            tracked.data_to_fetch(100, 0, &HashSet::new(), &[], Instant::now(), true),
            DataToFetch::DownloadsInProgress,
        );
    }
}

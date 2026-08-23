use std::collections::{HashMap, HashSet};

use alloy_primitives::B256;
use anyhow::{bail, ensure};
use ream_chain_beacon::beacon_chain::is_data_availability_check_required;
use ream_consensus_beacon::{
    blob_sidecar::{BlobIdentifier, BlobSidecar},
    data_column_sidecar::{ColumnIdentifier, DataColumnSidecar},
    electra::beacon_block::SignedBeaconBlock,
};
use ream_consensus_misc::misc::compute_epoch_at_slot;
use ream_network_spec::networks::beacon_network_spec;
use ream_polynomial_commitments::handlers::verify_data_column_sidecar_kzg_proofs;
use ssz::Encode;
use tree_hash::TreeHash;

use super::{MAX_BLOCKS_PER_REQUEST, peer_range_downloader::Range};

pub struct BlockAndBlobBundle {
    pub block: SignedBeaconBlock,
    pub blobs: HashMap<BlobIdentifier, BlobSidecar>,
    pub columns: HashMap<ColumnIdentifier, DataColumnSidecar>,
}

impl BlockAndBlobBundle {
    pub fn new(block: SignedBeaconBlock) -> Self {
        Self {
            block,
            blobs: HashMap::new(),
            columns: HashMap::new(),
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
        }
    }

    pub fn add_blocks(
        &mut self,
        blocks: Vec<SignedBeaconBlock>,
        is_range: bool,
    ) -> anyhow::Result<()> {
        // Ensure that all blocks form a chain
        if is_range {
            for (index, block) in blocks.iter().enumerate().rev() {
                if index > 0 {
                    ensure!(
                        block.message.parent_root == blocks[index - 1].message.tree_hash_root(),
                        "Block at index {index} has a parent root that does not match the previous block's tree hash root",
                    );
                }
            }
        }

        for block in blocks {
            self.current_cache_size += block.as_ssz_bytes().len() as u64;
            self.blocks_and_blobs.insert(
                block.message.tree_hash_root(),
                BlockAndBlobBundle::new(block),
            );
        }

        Ok(())
    }

    pub fn add_blobs(&mut self, blobs: Vec<BlobSidecar>) -> anyhow::Result<()> {
        for blob_sidecar in blobs {
            let block_root = blob_sidecar.signed_block_header.message.tree_hash_root();

            if let Some(bundle) = self.blocks_and_blobs.get_mut(&block_root) {
                bundle.blobs.insert(
                    BlobIdentifier {
                        block_root,
                        index: blob_sidecar.index,
                    },
                    blob_sidecar,
                );
            } else {
                bail!("Block root {block_root} not found in cache, this should be impossible");
            }
        }

        Ok(())
    }

    pub fn add_data_columns(
        &mut self,
        columns: Vec<DataColumnSidecar>,
        required_columns: &HashSet<u64>,
    ) -> anyhow::Result<()> {
        for column in columns {
            if !required_columns.contains(&column.index) {
                continue;
            }

            let block_root = column.signed_block_header.message.tree_hash_root();
            let Some(bundle) = self.blocks_and_blobs.get_mut(&block_root) else {
                bail!("Block root {block_root} not found in cache, this should be impossible");
            };

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

    pub fn data_to_fetch(
        &mut self,
        target_slot: u64,
        current_epoch: u64,
        required_columns: &HashSet<u64>,
    ) -> DataToFetch {
        match self.block_ranges_to_retry.pop() {
            Some(range) => return DataToFetch::BlockRange(range),
            None => {
                let estimated_blocks_to_fetch = self.estimated_blocks_to_fetch();
                if estimated_blocks_to_fetch > 0 && self.next_start_slot < target_slot {
                    let blocks_to_fill = estimated_blocks_to_fetch
                        .min(MAX_BLOCKS_PER_REQUEST.min(target_slot - self.next_start_slot));
                    let start_slot = self.next_start_slot + 1;
                    self.next_start_slot += blocks_to_fill;
                    return DataToFetch::BlockRange(Range::new(start_slot, blocks_to_fill));
                }
            }
        }

        if let Some(range) = self.column_ranges_to_fetch.pop() {
            return DataToFetch::DataColumnRange(range);
        }

        let mut block_roots_left_to_fetch = self.get_missing_block_roots();
        let missing_block_roots_len = block_roots_left_to_fetch.len();
        block_roots_left_to_fetch.retain(|root| !self.block_roots_in_progress.contains(root));

        let mut blob_identifiers_left_to_fetch = self.get_missing_blob_identifiers(current_epoch);
        let missing_blob_identifiers_len = blob_identifiers_left_to_fetch.len();
        blob_identifiers_left_to_fetch
            .retain(|blob_identifier| !self.blob_identifiers_in_progress.contains(blob_identifier));

        let mut data_column_identifiers_left_to_fetch =
            self.get_missing_data_column_identifiers(current_epoch, required_columns);
        let missing_data_column_identifiers_len = data_column_identifiers_left_to_fetch.len();
        data_column_identifiers_left_to_fetch.retain(|identifier| {
            !self
                .data_column_identifiers_in_progress
                .contains(identifier)
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
            cache.data_to_fetch(10, 0, &HashSet::new()),
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
            cache.data_to_fetch(10, 0, &HashSet::new()),
            DataToFetch::DownloadsInProgress
        );

        cache.remove_block_range_in_progress(&range);
        assert_eq!(
            cache.data_to_fetch(10, 0, &HashSet::new()),
            DataToFetch::Finished
        );
    }

    #[test]
    fn data_to_fetch_requests_contiguous_non_empty_ranges() {
        initialize_test_network_spec();
        let mut cache = BlockCache::new(B256::ZERO, 10);

        assert_eq!(
            cache.data_to_fetch(25, 0, &HashSet::new()),
            DataToFetch::BlockRange(Range::new(11, 10))
        );
        assert_eq!(
            cache.data_to_fetch(25, 0, &HashSet::new()),
            DataToFetch::BlockRange(Range::new(21, 5))
        );
        assert_eq!(
            cache.data_to_fetch(25, 0, &HashSet::new()),
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
            .add_blocks(vec![block_with_blob(boundary_slot)], false)
            .expect("boundary block should enter cache");
        assert_eq!(
            retained.data_to_fetch(boundary_slot, current_epoch, &HashSet::new()),
            DataToFetch::Finished
        );

        let expired_slot = compute_start_slot_at_epoch(boundary_epoch - 1);
        let mut expired = BlockCache::new(parent_root, expired_slot);
        expired
            .add_blocks(vec![block_with_blob(expired_slot)], false)
            .expect("expired block should enter cache");
        assert_eq!(
            expired.data_to_fetch(expired_slot, current_epoch, &HashSet::new()),
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
            .add_blocks(vec![block], false)
            .expect("boundary block should enter cache");

        let required_columns = HashSet::from([1, 5]);
        match cache.data_to_fetch(boundary_slot, current_epoch, &required_columns) {
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
            cache.data_to_fetch(boundary_slot, current_epoch, &HashSet::new()),
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
            .add_blocks(vec![block], false)
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
}

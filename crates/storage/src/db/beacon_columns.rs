//! Column retention. File deletion precedes index deletion so interrupted pruning is retryable.
use std::{collections::HashSet, fs, path::PathBuf};

use alloy_primitives::B256;
use ream_consensus_beacon::data_column_sidecar::{ColumnIdentifier, NUMBER_OF_COLUMNS};
use redb::{Durability, ReadableDatabase, ReadableTable};

use super::beacon::BeaconDB;
use crate::{
    errors::StoreError,
    tables::{
        beacon::{
            column_roots_by_slot::{
                COLUMN_MAINTENANCE, COLUMN_ROOTS_BY_SLOT, COLUMN_WRITER, INDEX_VERSION,
                PRUNED_BEFORE,
            },
            column_sidecars::column_directories,
        },
        table::REDBTable,
    },
};

impl BeaconDB {
    /// Runs before network writers start. The marker commits only after the entire directory has
    /// been indexed; repeating a partially completed migration is safe.
    pub(crate) fn migrate_column_index(&self) -> Result<(), StoreError> {
        let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
        if self
            .db
            .begin_read()?
            .open_table(COLUMN_MAINTENANCE)?
            .get(INDEX_VERSION)?
            .is_some()
        {
            return Ok(());
        }
        let mut roots = HashSet::new();
        for directory in column_directories(&self.data_dir) {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                let name = entry.file_name();
                let Some((root, index)) = name
                    .to_str()
                    .and_then(|name| name.strip_suffix(".ssz_snappy"))
                    .and_then(|name| name.rsplit_once('_'))
                else {
                    continue;
                };
                let root = root.parse::<B256>().map_err(|err| {
                    std::io::Error::other(format!("Invalid column file root: {err}"))
                })?;
                let index = index.parse::<u64>().map_err(|err| {
                    std::io::Error::other(format!("Invalid column file index: {err}"))
                })?;
                if index >= NUMBER_OF_COLUMNS {
                    return Err(std::io::Error::other("Column file index out of bounds").into());
                }
                roots.insert(root);
            }
        }
        for root in roots {
            match self.block_provider().get(root)? {
                Some(block) => {
                    let mut write = self.db.begin_write()?;
                    write.set_durability(Durability::Immediate)?;
                    write
                        .open_multimap_table(COLUMN_ROOTS_BY_SLOT)?
                        .insert(block.message.slot, root)?;
                    write.commit()?;
                }
                None => {
                    crate::tables::sidecar_file::remove_published_batch(&self.column_paths(root))?;
                }
            }
        }
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        write
            .open_table(COLUMN_MAINTENANCE)?
            .insert(INDEX_VERSION, 1)?;
        write.commit()?;
        Ok(())
    }

    fn column_paths(&self, root: B256) -> Vec<PathBuf> {
        let table = self.column_sidecars_provider();
        (0..NUMBER_OF_COLUMNS)
            .flat_map(|index| table.file_paths(&ColumnIdentifier::new(root, index)))
            .collect()
    }

    /// Prunes at most `max_roots` per invocation, taking the writer lock for one root at a time
    /// so a large backlog does not starve live column publication. Never crosses finality.
    pub fn prune_columns(
        &self,
        da_start: u64,
        finalized_slot: u64,
        max_roots: usize,
    ) -> Result<usize, StoreError> {
        let cutoff = da_start.min(finalized_slot);
        let roots = {
            let read = self.db.begin_read()?;
            let table = read.open_multimap_table(COLUMN_ROOTS_BY_SLOT)?;
            let mut roots = Vec::new();
            'slots: for entry in table.range(..cutoff)? {
                let (slot, values) = entry?;
                for root in values {
                    if roots.len() >= max_roots {
                        break 'slots;
                    }
                    roots.push((slot.value(), root?.value()));
                }
            }
            roots
        };
        {
            let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
            // Publish the watermark first: interrupted pruning leaves its index for retry.
            let mut write = self.db.begin_write()?;
            write.set_durability(Durability::Immediate)?;
            {
                let mut table = write.open_table(COLUMN_MAINTENANCE)?;
                let previous = table
                    .get(PRUNED_BEFORE)?
                    .map(|value| value.value())
                    .unwrap_or_default();
                table.insert(PRUNED_BEFORE, cutoff.max(previous))?;
            }
            write.commit()?;
        }
        let mut removed = 0;
        for (slot, root) in roots {
            let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
            removed +=
                crate::tables::sidecar_file::remove_published_batch(&self.column_paths(root))?;
            let mut write = self.db.begin_write()?;
            write.set_durability(Durability::Immediate)?;
            write
                .open_multimap_table(COLUMN_ROOTS_BY_SLOT)?
                .remove(slot, root)?;
            write.commit()?;
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use ream_consensus_beacon::{
        data_column_sidecar::{ColumnIdentifier, DataColumnSidecar},
        electra::beacon_block::{BeaconBlock, SignedBeaconBlock},
    };
    use tree_hash::TreeHash;

    use super::*;
    use crate::{db::ReamDB, tables::table::CustomTable};

    fn column(slot: u64) -> (B256, SignedBeaconBlock, DataColumnSidecar) {
        let block = SignedBeaconBlock {
            message: BeaconBlock {
                slot,
                ..Default::default()
            },
            signature: Default::default(),
        };
        let root = block.message.tree_hash_root();
        let column = DataColumnSidecar {
            index: 0,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: block.signed_header(),
            kzg_commitments_inclusion_proof: Default::default(),
        };
        (root, block, column)
    }

    #[test]
    fn pruning_respects_retention_finality_and_rejects_late_republication() {
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        for slot in [9, 10, 11] {
            let (_, _, column) = column(slot);
            db.column_sidecars_provider()
                .insert_batch(vec![column])
                .unwrap();
        }
        assert_eq!(db.prune_columns(11, 10, 256).unwrap(), 1);
        assert_eq!(db.prune_columns(10, 11, 256).unwrap(), 0);
        for slot in [10, 11] {
            assert!(
                db.column_sidecars_provider()
                    .get(ColumnIdentifier::new(column(slot).0, 0))
                    .unwrap()
                    .is_some()
            );
        }
        db.column_sidecars_provider()
            .insert_batch(vec![column(9).2])
            .unwrap();
        assert!(
            db.column_sidecars_provider()
                .get(ColumnIdentifier::new(column(9).0, 0))
                .unwrap()
                .is_none()
        );
        assert_eq!(db.prune_columns(12, 12, 1).unwrap(), 1);
        assert_eq!(db.prune_columns(12, 12, 1).unwrap(), 1);
    }

    #[test]
    fn migration_indexes_forks_and_removes_orphans_and_pruning_retries_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let (root, block, sidecar) = column(9);
        db.block_provider().insert(root, block).unwrap();
        db.column_sidecars_provider()
            .insert_batch(vec![sidecar, column(10).2])
            .unwrap();
        let (_, mut fork, mut fork_sidecar) = column(9);
        fork.message.state_root = B256::repeat_byte(42);
        let fork_root = fork.message.tree_hash_root();
        fork_sidecar.signed_block_header = fork.signed_header();
        db.block_provider().insert(fork_root, fork).unwrap();
        db.column_sidecars_provider()
            .insert_batch(vec![fork_sidecar])
            .unwrap();
        // Simulate an old database without an index, including an orphan from a failed import.
        let write = db.db.begin_write().unwrap();
        write
            .open_multimap_table(COLUMN_ROOTS_BY_SLOT)
            .unwrap()
            .remove_all(9)
            .unwrap();
        write
            .open_multimap_table(COLUMN_ROOTS_BY_SLOT)
            .unwrap()
            .remove_all(10)
            .unwrap();
        write
            .open_table(COLUMN_MAINTENANCE)
            .unwrap()
            .remove(INDEX_VERSION)
            .unwrap();
        write.commit().unwrap();
        drop(db);
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert!(
            db.column_sidecars_provider()
                .get(ColumnIdentifier::new(column(10).0, 0))
                .unwrap()
                .is_none()
        );
        assert!(
            db.column_sidecars_provider()
                .get(ColumnIdentifier::new(root, 0))
                .unwrap()
                .is_some()
        );
        // Simulate a crash after unlink but before the index transaction commits.
        fs::remove_file(db.column_paths(root)[0].clone()).unwrap();
        assert_eq!(db.prune_columns(10, 10, 256).unwrap(), 1);
        assert!(
            db.db
                .begin_read()
                .unwrap()
                .open_multimap_table(COLUMN_ROOTS_BY_SLOT)
                .unwrap()
                .get(9)
                .unwrap()
                .next()
                .is_none()
        );
    }
    #[test]
    fn pruning_removes_legacy_and_sharded_files() {
        let dir = tempfile::tempdir().unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        let table = db.column_sidecars_provider();
        for slot in [9, 10] {
            let (root, _, sidecar) = column(slot);
            table.insert_batch(vec![sidecar]).unwrap();
            if slot == 9 {
                let [current, legacy] = table.file_paths(&ColumnIdentifier::new(root, 0));
                fs::rename(current, legacy).unwrap();
            }
        }
        assert_eq!(db.prune_columns(11, 11, 256).unwrap(), 2);
        for slot in [9, 10] {
            let key = ColumnIdentifier::new(column(slot).0, 0);
            assert!(table.get(key).unwrap().is_none());
            assert!(table.file_paths(&key).iter().all(|path| !path.exists()));
        }
    }
}

use std::{
    fs::{self, File},
    sync::Arc,
};

use alloy_primitives::B256;
use anyhow::{bail, ensure};
use redb::{Durability, MultimapTableHandle, ReadableDatabase, ReadableTable, TableHandle};
use ssz::{Decode, Encode};
use tree_hash::TreeHash;

use super::{ReamDB, beacon::BeaconDB};
use crate::{
    errors::StoreError,
    tables::{
        beacon::{
            backfill::{
                BOOTSTRAP, BackfillMeta, BackfillMode, GVR, IN_PROGRESS, MARKER, META,
                SIDECAR_CUSTODY,
            },
            beacon_state::STATE_FOLDER_NAME,
            blobs_and_proofs::BLOB_FOLDER_NAME,
            column_sidecars::column_directories,
            latest_messages::LatestMessagesTable,
        },
        table::REDBTable,
    },
};

impl BeaconDB {
    pub fn genesis_validators_root(&self) -> anyhow::Result<Option<B256>> {
        let read = self.db.begin_read()?;
        let table = read.open_table(BOOTSTRAP)?;
        table
            .get(GVR)?
            .map(|v| B256::from_ssz_bytes(v.value()).map_err(|err| StoreError::from(err).into()))
            .transpose()
    }

    /// Cache independently verified network identity without asserting historical coverage.
    pub fn cache_genesis_validators_root(&self, root: B256) -> anyhow::Result<()> {
        if let Some(existing) = self.genesis_validators_root()? {
            ensure!(existing == root, "Genesis validators root mismatch");
            return Ok(());
        }
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            let mut table = write.open_table(BOOTSTRAP)?;
            ensure!(table.get(IN_PROGRESS)?.is_none(), "Bootstrap is incomplete");
            if let Some(existing) = table.get(GVR)? {
                ensure!(
                    B256::from_ssz_bytes(existing.value()).map_err(StoreError::from)? == root,
                    "Genesis validators root mismatch"
                );
            }
            table.insert(GVR, root.as_ssz_bytes().as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    pub fn bootstrap_in_progress(&self) -> anyhow::Result<bool> {
        let read = self.db.begin_read()?;
        let table = read.open_table(BOOTSTRAP)?;
        Ok(table.get(IN_PROGRESS)?.is_some())
    }

    /// Call before starting any networking. Incomplete bootstrap is never a legacy database.
    pub fn backfill_mode(&self) -> anyhow::Result<BackfillMode> {
        let read = self.db.begin_read()?;
        let table = read.open_table(BOOTSTRAP)?;
        ensure!(
            table.get(IN_PROGRESS)?.is_none(),
            "Bootstrap is incomplete; retry bootstrap"
        );
        let marker = table.get(MARKER)?;
        let meta = table.get(META)?;
        let gvr = table.get(GVR)?;
        match marker.as_ref().map(|v| v.value()) {
            None => {
                ensure!(
                    meta.is_none(),
                    "Bootstrap metadata missing completion marker"
                );
                if let Some(gvr) = gvr {
                    B256::from_ssz_bytes(gvr.value()).map_err(StoreError::from)?;
                }
                Ok(BackfillMode::Legacy)
            }
            Some([0]) => {
                ensure!(
                    meta.is_none() && gvr.is_some(),
                    "Invalid genesis bootstrap metadata"
                );
                B256::from_ssz_bytes(
                    gvr.as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing genesis validators root"))?
                        .value(),
                )
                .map_err(StoreError::from)?;
                Ok(BackfillMode::GenesisSynced)
            }
            Some([1]) => {
                ensure!(gvr.is_some(), "Missing genesis validators root");
                B256::from_ssz_bytes(
                    gvr.as_ref()
                        .ok_or_else(|| anyhow::anyhow!("Missing genesis validators root"))?
                        .value(),
                )
                .map_err(StoreError::from)?;
                let meta = meta.ok_or_else(|| anyhow::anyhow!("Missing backfill metadata"))?;
                let meta = BackfillMeta::from_ssz_bytes(meta.value()).map_err(StoreError::from)?;
                self.validate_backfill_meta(&meta)?;
                Ok(BackfillMode::Checkpoint(meta))
            }
            _ => bail!("Unknown bootstrap completion marker"),
        }
    }

    /// Runtime progress snapshot. Bootstrap mutations invalidate the shared cache under
    /// the same lock, so a reader cannot republish a stale snapshot after a commit.
    /// Startup continues to call backfill_mode() for full on-disk validation.
    pub fn cached_backfill_mode(&self) -> anyhow::Result<BackfillMode> {
        let mut cache = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if let Some(mode) = cache.as_ref() {
            return Ok(mode.clone());
        }
        let mode = self.backfill_mode()?;
        *cache = Some(mode.clone());
        Ok(mode)
    }

    /// Resume anchor recovery after every restart until coverage is committed.
    pub fn pending_anchor_root(&self) -> anyhow::Result<Option<B256>> {
        Ok(match self.cached_backfill_mode()? {
            BackfillMode::Checkpoint(meta) if meta.sidecars.frontier.is_none() => {
                Some(meta.origin.root)
            }
            _ => None,
        })
    }

    /// The caller must verify and durably publish all required anchor columns first.
    pub fn confirm_anchor_sidecars(&self, root: B256) -> anyhow::Result<()> {
        let mut cache = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *cache = None;
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            let mut table = write.open_table(BOOTSTRAP)?;
            let mut meta = {
                let raw = table
                    .get(META)?
                    .ok_or_else(|| anyhow::anyhow!("Missing backfill metadata"))?;
                BackfillMeta::from_ssz_bytes(raw.value()).map_err(StoreError::from)?
            };
            ensure!(
                meta.origin.root == root,
                "Anchor changed during sidecar recovery"
            );
            if meta.sidecars.frontier.is_some() {
                return Ok(());
            }
            meta.sidecars.frontier = Some(meta.origin.slot);
            meta.revision = meta
                .revision
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Backfill revision overflow"))?;
            table.insert(META, meta.as_ssz_bytes().as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    fn validate_backfill_meta(&self, meta: &BackfillMeta) -> anyhow::Result<()> {
        let f = &meta.blocks.frontier;
        ensure!(
            f.oldest_block_slot <= meta.origin.slot,
            "Block frontier is after origin"
        );
        if let Some(sidecar) = meta.sidecars.frontier {
            // A custody increase restarts coverage above the origin.
            ensure!(f.oldest_block_slot <= sidecar, "Invalid backfill coverage");
        }
        let origin = self
            .block_provider()
            .get(meta.origin.root)?
            .ok_or_else(|| anyhow::anyhow!("Missing origin block"))?;
        ensure!(
            origin.message.tree_hash_root() == meta.origin.root
                && origin.message.slot == meta.origin.slot
                && origin.message.state_root == meta.origin.state_root,
            "Origin block does not match metadata"
        );
        let frontier = self
            .block_provider()
            .get(f.oldest_block_root)?
            .ok_or_else(|| anyhow::anyhow!("Missing frontier block"))?;
        ensure!(
            frontier.message.tree_hash_root() == f.oldest_block_root
                && frontier.message.slot == f.oldest_block_slot
                && frontier.message.parent_root == f.oldest_block_parent,
            "Frontier block does not match metadata"
        );
        Ok(())
    }

    /// Persist this before the first bootstrap data write. Only a fresh DB may enter this state.
    pub fn begin_bootstrap(&self) -> anyhow::Result<()> {
        let mut cache = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *cache = None;
        ensure!(
            self.slot_index_provider().get_highest_slot()?.is_none(),
            "Refusing to bootstrap over existing blocks"
        );
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            let mut table = write.open_table(BOOTSTRAP)?;
            ensure!(
                table.get(MARKER)?.is_none()
                    && table.get(META)?.is_none()
                    && table.get(GVR)?.is_none(),
                "Database already has bootstrap metadata"
            );
            table.insert(IN_PROGRESS, &[1u8][..])?;
        }
        write.commit()?;
        Ok(())
    }

    /// Some sidecar coverage requires verified, durable DA; None schedules anchor recovery.
    /// GVR, mode, coverage and clearing the in-progress flag are one durable transaction.
    pub fn finish_bootstrap(
        &self,
        genesis_validators_root: B256,
        meta: Option<&BackfillMeta>,
    ) -> anyhow::Result<()> {
        let mut cache = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *cache = None;
        if let Some(meta) = meta {
            self.validate_backfill_meta(meta)?;
            ensure!(
                meta.revision == 0
                    && meta.blocks.frontier.oldest_block_root == meta.origin.root
                    && meta
                        .sidecars
                        .frontier
                        .is_none_or(|slot| slot == meta.origin.slot),
                "Invalid initial backfill coverage"
            );
        }
        let root = if let Some(meta) = meta {
            meta.origin.root
        } else {
            self.slot_index_provider()
                .get(0)?
                .ok_or_else(|| anyhow::anyhow!("Missing genesis block"))?
        };
        let block = self
            .block_provider()
            .get(root)?
            .ok_or_else(|| anyhow::anyhow!("Missing bootstrap block"))?;
        let state = self
            .state_provider()
            .get(root)?
            .ok_or_else(|| anyhow::anyhow!("Missing bootstrap state"))?;
        ensure!(
            state.slot == block.message.slot
                && state.tree_hash_root() == block.message.state_root
                && state.genesis_validators_root == genesis_validators_root,
            "Bootstrap state does not match anchor or genesis validators root"
        );
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        {
            let mut table = write.open_table(BOOTSTRAP)?;
            ensure!(
                table.get(IN_PROGRESS)?.is_some() && table.get(MARKER)?.is_none(),
                "Bootstrap was not started"
            );
            table.insert(GVR, genesis_validators_root.as_ssz_bytes().as_slice())?;
            // No columns are held yet; the first startup records the custody.
            table.insert(SIDECAR_CUSTODY, Vec::<u64>::new().as_ssz_bytes().as_slice())?;
            if let Some(meta) = meta {
                table.insert(META, meta.as_ssz_bytes().as_slice())?;
                table.insert(MARKER, &[1u8][..])?;
            } else {
                table.insert(MARKER, &[0u8][..])?;
            }
            table.remove(IN_PROGRESS)?;
        }
        write.commit()?;
        Ok(())
    }

    /// Startup-only recovery. Preserve the flag until a later successful bootstrap, so another
    /// crash during cleanup is also recoverable. Never touch legacy data or lean tables.
    pub fn recover_interrupted_bootstrap(&self) -> anyhow::Result<bool> {
        let mut cache = self
            .bootstrap_cache
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        *cache = None;
        if !self.bootstrap_in_progress()? {
            return Ok(false);
        }
        {
            let read = self.db.begin_read()?;
            let table = read.open_table(BOOTSTRAP)?;
            ensure!(
                table.get(MARKER)?.is_none()
                    && table.get(META)?.is_none()
                    && table.get(GVR)?.is_none(),
                "Conflicting bootstrap markers; refusing recovery"
            );
        }
        for dir in [BLOB_FOLDER_NAME, STATE_FOLDER_NAME]
            .into_iter()
            .map(|folder| self.data_dir.join(folder))
            .chain(column_directories(&self.data_dir))
        {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                ensure!(
                    entry.file_type()?.is_file(),
                    "Unexpected directory in bootstrap sidecars"
                );
                fs::remove_file(entry.path())?;
            }
            File::open(dir)?.sync_all()?;
        }
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        let tables = write
            .list_tables()?
            .filter(|t| t.name().starts_with("beacon_") && t.name() != BOOTSTRAP.name())
            .collect::<Vec<_>>();
        let multimaps = write
            .list_multimap_tables()?
            .filter(|t| t.name().starts_with("beacon_"))
            .collect::<Vec<_>>();
        for table in tables {
            write.delete_table(table)?;
        }
        for table in multimaps {
            write.delete_multimap_table(table)?;
        }
        write.commit()?;
        // Fork choice votes live in a database of their own.
        let write = self.votes_db.begin_write()?;
        write.delete_table(LatestMessagesTable::TABLE_DEFINITION)?;
        write.open_table(LatestMessagesTable::TABLE_DEFINITION)?;
        write.commit()?;
        ReamDB {
            db: self.db.clone(),
            votes_db: Arc::new(std::sync::Mutex::new(Some(self.votes_db.clone()))),
            // The state folder was emptied above.
            state_files_checked: Arc::new(std::sync::Mutex::new(true)),
            data_dir: self.data_dir.clone(),
            bootstrap_cache: self.bootstrap_cache.clone(),
        }
        .init_beacon_db()?;
        if let Some(cache) = &self.cache {
            cache
                .blocks
                .lock()
                .map_err(|err| anyhow::anyhow!("Poisoned block cache: {err}"))?
                .clear();
            cache
                .states
                .lock()
                .map_err(|err| anyhow::anyhow!("Poisoned state cache: {err}"))?
                .clear();
            cache
                .pending_state_snapshots
                .lock()
                .map_err(|err| anyhow::anyhow!("Poisoned state snapshot cache: {err}"))?
                .clear();
            cache
                .checkpoint_states
                .lock()
                .map_err(|err| anyhow::anyhow!("Poisoned checkpoint state cache: {err}"))?
                .clear();
            cache
                .pending_latest_messages
                .lock()
                .map_err(|err| anyhow::anyhow!("Poisoned pending vote cache: {err}"))?
                .messages
                .clear();
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use tempdir::TempDir;

    use super::*;

    #[test]
    fn recovery_is_restartable_and_preserves_non_beacon_tables() {
        let dir = TempDir::new("bootstrap_recovery").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf()).unwrap();
        let beacon = db.init_beacon_db().unwrap();
        let other = redb::TableDefinition::<u64, u64>::new("lean_test_data");
        let write = beacon.db.begin_write().unwrap();
        write.open_table(other).unwrap().insert(1, 2).unwrap();
        write.commit().unwrap();
        beacon.begin_bootstrap().unwrap();
        fs::write(
            beacon
                .data_dir
                .join(crate::tables::beacon::column_sidecars::COLUMN_FOLDER_NAME)
                .join("partial"),
            [1],
        )
        .unwrap();
        // An abandoned checkpoint may already be indexed as canonical.
        let write = beacon.db.begin_write().unwrap();
        write
            .open_table(crate::db::beacon_canonical::CANONICAL_ROOTS)
            .unwrap()
            .insert(7, B256::repeat_byte(7))
            .unwrap();
        write.commit().unwrap();
        assert!(beacon.recover_interrupted_bootstrap().unwrap());
        assert!(beacon.recover_interrupted_bootstrap().unwrap());
        assert!(beacon.bootstrap_in_progress().unwrap());
        let read = beacon.db.begin_read().unwrap();
        assert_eq!(
            read.open_table(other)
                .unwrap()
                .get(1)
                .unwrap()
                .unwrap()
                .value(),
            2
        );
        assert_eq!(
            fs::read_dir(
                beacon
                    .data_dir
                    .join(crate::tables::beacon::column_sidecars::COLUMN_FOLDER_NAME)
            )
            .unwrap()
            .count(),
            0
        );
        assert_eq!(beacon.canonical_root_before(u64::MAX).unwrap(), None);
    }

    #[test]
    fn malformed_completion_marker_is_not_legacy_or_recoverable() {
        let dir = TempDir::new("bootstrap_corrupt").unwrap();
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert!(db.finish_bootstrap(B256::ZERO, None).is_err());
        assert!(db.genesis_validators_root().unwrap().is_none());
        db.begin_bootstrap().unwrap();
        let write = db.db.begin_write().unwrap();
        write
            .open_table(BOOTSTRAP)
            .unwrap()
            .insert(MARKER, &[99u8][..])
            .unwrap();
        write.commit().unwrap();
        assert!(db.backfill_mode().is_err());
        assert!(db.recover_interrupted_bootstrap().is_err());
    }
}

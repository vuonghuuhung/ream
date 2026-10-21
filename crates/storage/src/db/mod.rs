pub mod beacon;
pub mod beacon_backfill;
mod beacon_bootstrap;
mod beacon_canonical;
mod beacon_columns;
pub mod lean;

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::Result;
use beacon::BeaconDB;
use lean::LeanDB;
use redb::{Builder, Database, ReadableDatabase, ReadableTable};
use tracing::info;

use crate::{
    errors::StoreError,
    tables::{
        beacon::{
            beacon_block::BeaconBlockTable,
            beacon_state::{BeaconStateTable, STATE_FOLDER_NAME},
            blobs_and_proofs::BLOB_FOLDER_NAME,
            block_timeliness::BlockTimelinessTable,
            checkpoint_states::CheckpointStatesTable,
            column_sidecars::{SHARDED_COLUMN_FOLDER_NAME, column_directories},
            equivocating_indices::EQUIVOCATING_INDICES_FIELD,
            finalized_checkpoint::FinalizedCheckpointField,
            genesis_time::GenesisTimeField,
            justified_checkpoint::JustifiedCheckpointField,
            latest_messages::LatestMessagesTable,
            parent_root_index::PARENT_ROOT_INDEX_MULTIMAP_TABLE,
            proposer_boost_root::ProposerBoostRootField,
            slot_index::BeaconSlotIndexTable,
            state_root_index::BeaconStateRootIndexTable,
            state_summaries::BeaconStateSummariesTable,
            time::TimeField,
            unrealized_finalized_checkpoint::UnrealizedFinalizedCheckpointField,
            unrealized_justifications::UnrealizedJustificationsTable,
            unrealized_justified_checkpoint::UnrealizedJustifiedCheckpointField,
        },
        field::REDBField,
        lean::{
            aggregated_payloads::AggregatedPayloadsTable,
            attestation_data_by_root::LeanAttestationDataByRootTable, block::LeanBlockTable,
            gossip_signatures::GossipSignaturesTable, head::LeanHeadField,
            latest_finalized::LatestFinalizedField, latest_justified::LatestJustifiedField,
            latest_known_aggregated_payloads::LeanLatestKnownAggregatedPayloadsTable,
            latest_known_attestation::LatestKnownAttestationTable,
            latest_new_aggregated_payloads::LeanLatestNewAggregatedPayloadsTable,
            latest_new_attestations::LeanLatestNewAttestationsTable,
            pending_blocks::LeanPendingBlocksTable, safe_target::LeanSafeTargetField,
            slot_index::LeanSlotIndexTable, state::LeanStateTable,
            state_root_index::LeanStateRootIndexTable, time::LeanTimeField,
            validator_id::LeanValidatorIdField,
        },
        table::REDBTable,
    },
};

pub const REDB_FILE: &str = "ream.redb";

/// Validators' latest messages, kept apart from `REDB_FILE`. A redb database has a single write
/// lock, and writing a block's tens of thousands of votes held it while block import waited.
pub const VOTES_REDB_FILE: &str = "fork_choice_votes.redb";

/// The size of the cache for the votes database
///
/// 256 MiB
pub const VOTES_REDB_CACHE_SIZE: usize = 256 * 1_024 * 1_024;

/// The size of the cache for the database
///
/// 1 GiB
pub const REDB_CACHE_SIZE: usize = 1_024 * 1_024 * 1_024;

#[derive(Clone, Debug)]
pub struct ReamDB {
    db: Arc<Database>,
    /// The votes database, opened by the first `init_beacon_db`.
    votes_db: Arc<Mutex<Option<Arc<Database>>>>,
    /// Whether `init_beacon_db` has deleted the state files a crash left behind. Clones share it,
    /// because a later call can run while a clone's writers have state files in flight.
    state_files_checked: Arc<Mutex<bool>>,
    data_dir: PathBuf,
    bootstrap_cache: Arc<std::sync::Mutex<Option<crate::tables::beacon::backfill::BackfillMode>>>,
}

impl ReamDB {
    pub fn new(data_dir: PathBuf) -> Result<Self, StoreError> {
        let db = Builder::new()
            .set_cache_size(REDB_CACHE_SIZE)
            .create(data_dir.join(REDB_FILE))?;

        for directory in
            std::iter::once(data_dir.join(BLOB_FOLDER_NAME)).chain(column_directories(&data_dir))
        {
            if directory.exists() {
                crate::tables::sidecar_file::cleanup_temporary_sidecars(&directory)?;
            }
        }

        Ok(ReamDB {
            db: Arc::new(db),
            votes_db: Arc::default(),
            state_files_checked: Arc::default(),
            data_dir,
            bootstrap_cache: Default::default(),
        })
    }

    pub fn init_beacon_db(&self) -> Result<BeaconDB, StoreError> {
        let write_txn = self.db.begin_write()?;

        write_txn.open_table(crate::db::beacon_canonical::CANONICAL_ROOTS)?;
        write_txn.open_table(crate::tables::beacon::backfill::BOOTSTRAP)?;
        write_txn.open_multimap_table(
            crate::tables::beacon::column_roots_by_slot::COLUMN_ROOTS_BY_SLOT,
        )?;
        write_txn.open_table(crate::tables::beacon::column_roots_by_slot::COLUMN_MAINTENANCE)?;
        write_txn.open_table(BeaconBlockTable::TABLE_DEFINITION)?;
        write_txn.open_table(BeaconStateTable::TABLE_DEFINITION)?;
        write_txn.open_table(BlockTimelinessTable::TABLE_DEFINITION)?;
        write_txn.open_table(CheckpointStatesTable::TABLE_DEFINITION)?;
        write_txn.open_table(EQUIVOCATING_INDICES_FIELD)?;
        write_txn.open_table(FinalizedCheckpointField::FIELD_DEFINITION)?;
        write_txn.open_table(GenesisTimeField::FIELD_DEFINITION)?;
        write_txn.open_table(JustifiedCheckpointField::FIELD_DEFINITION)?;
        write_txn.open_multimap_table(PARENT_ROOT_INDEX_MULTIMAP_TABLE)?;
        write_txn.open_table(ProposerBoostRootField::FIELD_DEFINITION)?;
        write_txn.open_table(BeaconSlotIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(BeaconStateRootIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(BeaconStateSummariesTable::TABLE_DEFINITION)?;
        write_txn.open_table(TimeField::FIELD_DEFINITION)?;
        write_txn.open_table(UnrealizedFinalizedCheckpointField::FIELD_DEFINITION)?;
        write_txn.open_table(UnrealizedJustificationsTable::TABLE_DEFINITION)?;
        write_txn.open_table(UnrealizedJustifiedCheckpointField::FIELD_DEFINITION)?;
        write_txn.commit()?;

        fs::create_dir_all(self.data_dir.join(BLOB_FOLDER_NAME))?;
        for directory in column_directories(&self.data_dir) {
            fs::create_dir_all(directory)?;
        }
        fs::File::open(self.data_dir.join(SHARDED_COLUMN_FOLDER_NAME))?.sync_all()?;
        fs::create_dir_all(self.data_dir.join(STATE_FOLDER_NAME))?;
        fs::File::open(&self.data_dir)?.sync_all()?;
        self.remove_unrecorded_state_files()?;

        let beacon_db = BeaconDB {
            db: self.db.clone(),
            votes_db: self.votes_db()?,
            data_dir: self.data_dir.clone(),
            cache: None,
            bootstrap_cache: self.bootstrap_cache.clone(),
        };
        beacon_db.migrate_column_index()?;
        if let Ok(finalized) = beacon_db.finalized_checkpoint_provider().get() {
            beacon_db.record_finalized_canonical(finalized.root)?;
        }
        Ok(beacon_db)
    }

    /// Deletes the state files that a crash left behind: temporary files and files whose summary
    /// was never committed. This runs once, before any writer of this database has started, so no
    /// file can belong to a running write.
    fn remove_unrecorded_state_files(&self) -> Result<(), StoreError> {
        let mut checked = self
            .state_files_checked
            .lock()
            .expect("state files lock is not poisoned");
        if *checked {
            return Ok(());
        }
        BeaconStateTable {
            db: self.db.clone(),
            data_dir: self.data_dir.clone(),
            cache: None,
        }
        .remove_unrecorded_state_files()?;
        *checked = true;
        Ok(())
    }

    /// The votes database, opened on first use. Latest messages that earlier versions kept in
    /// `REDB_FILE` are moved into it once.
    fn votes_db(&self) -> Result<Arc<Database>, StoreError> {
        self.votes_db_with(|data_dir| fs::File::open(data_dir)?.sync_all())
    }

    /// `votes_db` with the data directory sync passed in, so tests can fail it.
    fn votes_db_with(
        &self,
        sync_data_dir: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<Arc<Database>, StoreError> {
        let mut votes_db = self
            .votes_db
            .lock()
            .expect("votes database lock is not poisoned");
        if let Some(votes_db) = votes_db.as_ref() {
            return Ok(votes_db.clone());
        }
        let opened = Arc::new(
            Builder::new()
                .set_cache_size(VOTES_REDB_CACHE_SIZE)
                .create(self.data_dir.join(VOTES_REDB_FILE))?,
        );
        let write_txn = opened.begin_write()?;
        write_txn.open_table(LatestMessagesTable::TABLE_DEFINITION)?;
        write_txn.commit()?;
        self.move_votes_from_main_database(&opened, sync_data_dir)?;
        *votes_db = Some(opened.clone());
        Ok(opened)
    }

    /// Copies the legacy votes into `votes_db` and then deletes them from `REDB_FILE`. A commit
    /// syncs the file's contents but not its directory entry, so the data directory is synced
    /// before the delete. Otherwise a power loss could keep the delete and lose the new file.
    fn move_votes_from_main_database(
        &self,
        votes_db: &Database,
        sync_data_dir: impl FnOnce(&Path) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let messages = {
            let read_txn = self.db.begin_read()?;
            let table = match read_txn.open_table(LatestMessagesTable::TABLE_DEFINITION) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => {
                    sync_data_dir(&self.data_dir)?;
                    return Ok(());
                }
                Err(err) => return Err(err.into()),
            };
            let mut messages = Vec::new();
            for entry in table.iter()? {
                let (index, message) = entry?;
                messages.push((index.value(), message.value()));
            }
            messages
        };
        let write_txn = votes_db.begin_write()?;
        {
            let mut table = write_txn.open_table(LatestMessagesTable::TABLE_DEFINITION)?;
            for (index, message) in messages {
                table.insert(index, message)?;
            }
        }
        write_txn.commit()?;
        sync_data_dir(&self.data_dir)?;
        let write_txn = self.db.begin_write()?;
        write_txn.delete_table(LatestMessagesTable::TABLE_DEFINITION)?;
        write_txn.commit()?;
        Ok(())
    }

    pub fn init_lean_db(&self) -> Result<LeanDB, StoreError> {
        let write_txn = self.db.begin_write()?;

        write_txn.open_table(LatestFinalizedField::FIELD_DEFINITION)?;
        write_txn.open_table(LatestJustifiedField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanBlockTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanStateTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanSlotIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanStateRootIndexTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanTimeField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanHeadField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanSafeTargetField::FIELD_DEFINITION)?;
        write_txn.open_table(LeanLatestNewAttestationsTable::TABLE_DEFINITION)?;
        write_txn.open_table(LatestKnownAttestationTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanPendingBlocksTable::TABLE_DEFINITION)?;
        write_txn.open_table(AggregatedPayloadsTable::TABLE_DEFINITION)?;
        write_txn.open_table(GossipSignaturesTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanAttestationDataByRootTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanLatestNewAggregatedPayloadsTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanLatestKnownAggregatedPayloadsTable::TABLE_DEFINITION)?;
        write_txn.open_table(LeanValidatorIdField::FIELD_DEFINITION)?;
        write_txn.commit()?;

        Ok(LeanDB {
            db: self.db.clone(),
            cache: None,
        })
    }
}

pub fn reset_db(db_path: &PathBuf) -> anyhow::Result<()> {
    if fs::read_dir(db_path)?.next().is_none() {
        info!("Data directory at {db_path:?} is already empty.");
        return Ok(());
    }

    info!(
        "Are you sure you want to clear the contents of the data directory at {db_path:?}? (y/n):"
    );
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim().eq_ignore_ascii_case("y") {
        for entry in fs::read_dir(db_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
        info!("Database contents cleared successfully.");
    } else {
        info!("Operation canceled by user.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloy_primitives::B256;
    use ream_consensus_beacon::fork_choice::latest_message::LatestMessage;
    use tempdir::TempDir;

    use super::*;
    use crate::test_utils::sepolia_state;

    /// Stores one recorded state file, then adds `leftover`, a file a crash left in the state
    /// directory, and reopens the database. Checks that only the recorded file is left.
    fn reopen_with_leftover_state_file(dir: &Path, leftover: &str) -> (ReamDB, BeaconDB) {
        let recorded_root = B256::repeat_byte(1);
        {
            let db = ReamDB::new(dir.to_path_buf())
                .unwrap()
                .init_beacon_db()
                .unwrap();
            db.state_provider()
                .insert_shared(recorded_root, sepolia_state())
                .unwrap();
        }
        let states = dir.join(STATE_FOLDER_NAME);
        let recorded = states.join(format!("{recorded_root}.ssz_snappy"));
        fs::copy(&recorded, states.join(leftover)).unwrap();

        let ream_db = ReamDB::new(dir.to_path_buf()).unwrap();
        let db = ream_db.init_beacon_db().unwrap();
        assert!(!states.join(leftover).exists());
        assert!(recorded.exists());
        // Reading the state back would also check it against its block, which this test does not
        // store; the summary still marking it whole is what the cleanup must preserve.
        assert!(db.state_provider().is_stored_whole(recorded_root).unwrap());
        (ream_db, db)
    }

    #[test]
    fn reopening_deletes_a_stale_temporary_state_file() {
        let dir = TempDir::new("ream_stale_state_temp").unwrap();
        // A crash while writing a state leaves its temporary file.
        let (ream_db, _db) = reopen_with_leftover_state_file(dir.path(), ".tmpA1b2C3");

        // Only the first `init_beacon_db` scans: a later one can run while writers have a
        // temporary file in flight.
        let in_flight = dir.path().join(STATE_FOLDER_NAME).join(".tmpD4e5F6");
        fs::write(&in_flight, b"in flight").unwrap();
        ream_db.clone().init_beacon_db().unwrap();
        assert!(in_flight.exists());
    }

    #[test]
    fn reopening_deletes_an_unrecorded_state_file() {
        let dir = TempDir::new("ream_unrecorded_state").unwrap();
        // A crash after a state file's rename but before its summary commit leaves a final
        // filename that no summary records.
        let unrecorded_root = B256::repeat_byte(2);
        let (_ream_db, db) =
            reopen_with_leftover_state_file(dir.path(), &format!("{unrecorded_root}.ssz_snappy"));
        assert!(
            !db.state_provider()
                .is_stored_whole(unrecorded_root)
                .unwrap()
        );
    }

    #[test]
    fn votes_in_the_main_database_move_to_their_own() {
        let dir = TempDir::new("ream_votes_db").unwrap();
        let message = LatestMessage {
            epoch: 7,
            root: B256::repeat_byte(3),
        };
        {
            // Earlier versions kept latest messages in the main database.
            let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
            let write_txn = ream_db.db.begin_write().unwrap();
            write_txn
                .open_table(LatestMessagesTable::TABLE_DEFINITION)
                .unwrap()
                .insert(5, message.clone())
                .unwrap();
            write_txn.commit().unwrap();
        }

        let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
        let db = ream_db.init_beacon_db().unwrap();
        assert_eq!(db.latest_messages_provider().get(5).unwrap(), Some(message));
        let read_txn = ream_db.db.begin_read().unwrap();
        assert!(matches!(
            read_txn.open_table(LatestMessagesTable::TABLE_DEFINITION),
            Err(redb::TableError::TableDoesNotExist(_))
        ));
        // A second handle shares the votes database that is already open.
        let again = ream_db.init_beacon_db().unwrap();
        assert!(Arc::ptr_eq(&again.votes_db, &db.votes_db));
    }

    #[test]
    fn interrupted_vote_migration_retries_before_removing_the_source() {
        let dir = TempDir::new("ream_vote_migration_retry").unwrap();
        let message = LatestMessage {
            epoch: 7,
            root: B256::repeat_byte(3),
        };
        {
            let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
            let write_txn = ream_db.db.begin_write().unwrap();
            {
                let mut table = write_txn
                    .open_table(LatestMessagesTable::TABLE_DEFINITION)
                    .unwrap();
                table.insert(5, message.clone()).unwrap();
                table.insert(6, message.clone()).unwrap();
            }
            write_txn.commit().unwrap();
            // Model restart after destination commit, before deleting the legacy table.
            let votes_db = Database::create(dir.path().join(VOTES_REDB_FILE)).unwrap();
            let write_txn = votes_db.begin_write().unwrap();
            {
                let mut table = write_txn
                    .open_table(LatestMessagesTable::TABLE_DEFINITION)
                    .unwrap();
                table.insert(5, message.clone()).unwrap();
                table.insert(6, message.clone()).unwrap();
                table.insert(9, message.clone()).unwrap();
            }
            write_txn.commit().unwrap();
        }
        {
            let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
            let db = ream_db.init_beacon_db().unwrap();
            assert_eq!(
                db.latest_messages_provider().get_all().unwrap(),
                vec![
                    (5, message.clone()),
                    (6, message.clone()),
                    (9, message.clone())
                ]
            );
            assert!(matches!(
                ream_db
                    .db
                    .begin_read()
                    .unwrap()
                    .open_table(LatestMessagesTable::TABLE_DEFINITION),
                Err(redb::TableError::TableDoesNotExist(_))
            ));
        }
        let db = ReamDB::new(dir.path().to_path_buf())
            .unwrap()
            .init_beacon_db()
            .unwrap();
        assert_eq!(db.latest_messages_provider().get_all().unwrap().len(), 3);
    }

    #[test]
    fn failed_directory_sync_keeps_the_legacy_votes_for_a_retry() {
        let dir = TempDir::new("ream_vote_migration_sync").unwrap();
        let message = LatestMessage {
            epoch: 7,
            root: B256::repeat_byte(3),
        };
        {
            let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
            let write_txn = ream_db.db.begin_write().unwrap();
            write_txn
                .open_table(LatestMessagesTable::TABLE_DEFINITION)
                .unwrap()
                .insert(5, message.clone())
                .unwrap();
            write_txn.commit().unwrap();

            let error = ream_db
                .votes_db_with(|_| Err(io::Error::other("injected directory sync failure")))
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("injected directory sync failure")
            );
            assert!(ream_db.votes_db.lock().unwrap().is_none());
            // The legacy table is still the source of truth.
            let read_txn = ream_db.db.begin_read().unwrap();
            assert_eq!(
                read_txn
                    .open_table(LatestMessagesTable::TABLE_DEFINITION)
                    .unwrap()
                    .get(5)
                    .unwrap()
                    .map(|message| message.value()),
                Some(message.clone())
            );
        }

        // Model a power loss that dropped the unsynced directory entry of the votes database.
        fs::remove_file(dir.path().join(VOTES_REDB_FILE)).unwrap();

        let ream_db = ReamDB::new(dir.path().to_path_buf()).unwrap();
        let db = ream_db.init_beacon_db().unwrap();
        assert_eq!(
            db.latest_messages_provider().get_all().unwrap(),
            vec![(5, message)]
        );
        assert!(matches!(
            ream_db
                .db
                .begin_read()
                .unwrap()
                .open_table(LatestMessagesTable::TABLE_DEFINITION),
            Err(redb::TableError::TableDoesNotExist(_))
        ));
    }
}

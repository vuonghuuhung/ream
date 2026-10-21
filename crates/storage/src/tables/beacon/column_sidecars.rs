use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

use ream_consensus_beacon::data_column_sidecar::{ColumnIdentifier, DataColumnSidecar};
use redb::{Database, Durability, ReadableTable};
use snap::raw::{Decoder, Encoder};
use ssz::{Decode, Encode};
use tree_hash::TreeHash;

use super::column_roots_by_slot::{
    COLUMN_MAINTENANCE, COLUMN_ROOTS_BY_SLOT, COLUMN_WRITER, PRUNED_BEFORE,
};
use crate::{errors::StoreError, tables::table::CustomTable};

pub(crate) const COLUMN_FOLDER_NAME: &str = "beacon_columns";
pub(crate) const SHARDED_COLUMN_FOLDER_NAME: &str = "beacon_columns_v2";

pub(crate) fn column_directories(data_dir: &Path) -> impl Iterator<Item = PathBuf> + '_ {
    std::iter::once(data_dir.join(COLUMN_FOLDER_NAME)).chain((0..256).map(|shard| {
        data_dir
            .join(SHARDED_COLUMN_FOLDER_NAME)
            .join(format!("{shard:02x}"))
    }))
}

pub struct ColumnSidecarsTable {
    pub data_dir: PathBuf,
    pub db: Arc<Database>,
}

impl ColumnSidecarsTable {
    pub(crate) fn prepare_insert(
        &self,
        key: ColumnIdentifier,
        value: DataColumnSidecar,
    ) -> Result<crate::tables::sidecar_file::PreparedSidecarFile, StoreError> {
        let bytes = Encoder::new().compress_vec(&value.as_ssz_bytes())?;
        crate::tables::sidecar_file::PreparedSidecarFile::new(self.column_file_path(&key), &bytes)
    }

    pub fn insert_batch(&self, columns: Vec<DataColumnSidecar>) -> Result<(), StoreError> {
        let started = std::time::Instant::now();
        let count = columns.len();
        let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
        let mut write = self.db.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        let floor = write
            .open_table(COLUMN_MAINTENANCE)?
            .get(PRUNED_BEFORE)?
            .map(|value| value.value())
            .unwrap_or_default();
        let columns = columns
            .into_iter()
            .filter(|column| column.signed_block_header.message.slot >= floor)
            .collect::<Vec<_>>();
        {
            let mut index = write.open_multimap_table(COLUMN_ROOTS_BY_SLOT)?;
            for column in &columns {
                index.insert(
                    column.signed_block_header.message.slot,
                    column.signed_block_header.message.tree_hash_root(),
                )?;
            }
        }
        // Index first: a crash may leave an entry without files, never files invisible to prune.
        write.commit()?;
        let prepared = columns
            .into_iter()
            .map(|column| {
                let key = ColumnIdentifier::new(
                    column.signed_block_header.message.tree_hash_root(),
                    column.index,
                );
                self.prepare_insert(key, column)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let written = started.elapsed();
        crate::tables::sidecar_file::PreparedSidecarFile::publish_batch(prepared)?;
        tracing::debug!(
            target: "ream::timing",
            columns = count,
            write_ms = written.as_millis() as u64,
            publish_ms = (started.elapsed() - written).as_millis() as u64,
            "timing: column write"
        );
        Ok(())
    }

    pub(crate) fn file_paths(&self, key: &ColumnIdentifier) -> [PathBuf; 2] {
        let name = format!("{}_{}.ssz_snappy", key.block_root, key.index);
        [
            self.data_dir
                .join(SHARDED_COLUMN_FOLDER_NAME)
                .join(format!("{:02x}", key.block_root[0]))
                .join(&name),
            self.data_dir.join(COLUMN_FOLDER_NAME).join(name),
        ]
    }

    fn column_file_path(&self, key: &ColumnIdentifier) -> PathBuf {
        self.file_paths(key)[0].clone()
    }
}

impl CustomTable for ColumnSidecarsTable {
    type Key = ColumnIdentifier;
    type Value = DataColumnSidecar;

    fn get(&self, key: Self::Key) -> Result<Option<Self::Value>, StoreError> {
        let [current, legacy] = self.file_paths(&key);
        let file = match crate::tables::sidecar_file::open_published(&current)? {
            Some(file) => Some(file),
            None => crate::tables::sidecar_file::open_published(&legacy)?,
        };
        let Some(mut file) = file else {
            return Ok(None);
        };
        let mut bytes = vec![];
        file.read_to_end(&mut bytes)?;
        let snappy_decoding = Decoder::new().decompress_vec(&bytes)?;
        Ok(Some(DataColumnSidecar::from_ssz_bytes(&snappy_decoding)?))
    }

    fn insert(&self, key: Self::Key, value: Self::Value) -> Result<(), StoreError> {
        if key.block_root != value.signed_block_header.message.tree_hash_root()
            || key.index != value.index
        {
            return Err(std::io::Error::other("Column identifier does not match sidecar").into());
        }
        self.insert_batch(vec![value])
    }

    fn remove(&self, key: Self::Key) -> Result<Option<Self::Value>, StoreError> {
        let _writer = COLUMN_WRITER.lock().unwrap_or_else(|err| err.into_inner());
        let [current, legacy] = self.file_paths(&key);
        let value = crate::tables::sidecar_file::remove_published(&current, || self.get(key))?;
        crate::tables::sidecar_file::remove_published(&legacy, || Ok(()))?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use ream_consensus_beacon::data_column_sidecar::ColumnIdentifier;
    use tempdir::TempDir;

    use crate::{
        errors::StoreError,
        tables::{beacon::column_sidecars::COLUMN_FOLDER_NAME, table::CustomTable},
    };

    #[test]
    fn test_column_identifier_default() -> Result<(), StoreError> {
        let tmp_dir = TempDir::new("test_column_sidecar")?;

        let column_dir = tmp_dir.path().to_path_buf().join(COLUMN_FOLDER_NAME);
        fs::create_dir_all(&column_dir)?;

        let db = crate::db::ReamDB::new(tmp_dir.path().to_path_buf())?.init_beacon_db()?;
        let table = db.column_sidecars_provider();

        let key = ColumnIdentifier::default();

        let result = table.get(key)?;

        assert_eq!(result, None);

        Ok(())
    }
    #[test]
    fn sharded_columns_read_legacy_files_and_remove_both_copies() -> Result<(), StoreError> {
        use ream_consensus_beacon::data_column_sidecar::DataColumnSidecar;
        use snap::raw::Encoder;
        use ssz::Encode;
        use tree_hash::TreeHash;

        let dir = TempDir::new("legacy_column_shards")?;
        let db = crate::db::ReamDB::new(dir.path().to_path_buf())?.init_beacon_db()?;
        let table = db.column_sidecars_provider();
        let value = DataColumnSidecar {
            index: 0,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: Default::default(),
            kzg_commitments_inclusion_proof: Default::default(),
        };
        let key = ColumnIdentifier::new(
            value.signed_block_header.message.tree_hash_root(),
            value.index,
        );
        let [current, legacy] = table.file_paths(&key);
        fs::write(&legacy, Encoder::new().compress_vec(&value.as_ssz_bytes())?)?;
        assert_eq!(table.get(key)?, Some(value.clone()));
        table.insert(key, value.clone())?;
        assert!(current.exists());
        assert!(legacy.exists());
        fs::write(&legacy, b"damaged legacy duplicate")?;
        assert_eq!(table.get(key)?, Some(value.clone()));
        assert_eq!(table.remove(key)?, Some(value));
        assert!(!current.exists());
        assert!(!legacy.exists());
        assert_eq!(table.get(key)?, None);
        Ok(())
    }

    #[test]
    fn startup_cleans_staging_in_shards_and_retains_published_columns() -> Result<(), StoreError> {
        use ream_consensus_beacon::data_column_sidecar::DataColumnSidecar;
        use tree_hash::TreeHash;

        let dir = TempDir::new("column_shard_restart")?;
        let value = DataColumnSidecar {
            index: 0,
            column: Default::default(),
            kzg_commitments: Default::default(),
            kzg_proofs: Default::default(),
            signed_block_header: Default::default(),
            kzg_commitments_inclusion_proof: Default::default(),
        };
        let key = ColumnIdentifier::new(
            value.signed_block_header.message.tree_hash_root(),
            value.index,
        );
        let staging;
        {
            let db = crate::db::ReamDB::new(dir.path().to_path_buf())?.init_beacon_db()?;
            let table = db.column_sidecars_provider();
            table.insert(key, value.clone())?;
            let current = table.file_paths(&key)[0].clone();
            staging = current.parent().unwrap().join(".ream-sidecar-orphan");
            fs::write(&staging, b"interrupted")?;
        }
        let db = crate::db::ReamDB::new(dir.path().to_path_buf())?.init_beacon_db()?;
        assert!(!staging.exists());
        assert_eq!(db.column_sidecars_provider().get(key)?, Some(value));
        Ok(())
    }
}

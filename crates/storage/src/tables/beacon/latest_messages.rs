use std::sync::Arc;

use ream_consensus_beacon::fork_choice::latest_message::LatestMessage;
use redb::{Database, Durability, TableDefinition};

use crate::{
    errors::StoreError,
    tables::{ssz_encoder::SSZEncoding, table::REDBTable},
};

pub struct LatestMessagesTable {
    pub db: Arc<Database>,
}

impl LatestMessagesTable {
    pub fn insert_batch(
        &self,
        entries: impl IntoIterator<Item = (u64, LatestMessage)>,
    ) -> Result<(), StoreError> {
        let mut write_txn = self.db.begin_write()?;
        write_txn.set_durability(Durability::Immediate)?;
        {
            let mut table = write_txn.open_table(Self::TABLE_DEFINITION)?;
            for (index, message) in entries {
                table.insert(index, message)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }
}

/// Table definition for the Latest Message table
///
/// Key: latest_messages
/// Value: LatestMessage
impl REDBTable for LatestMessagesTable {
    const TABLE_DEFINITION: TableDefinition<'_, u64, SSZEncoding<LatestMessage>> =
        TableDefinition::new("beacon_latest_messages");

    type Key = u64;

    type KeyTableDefinition = u64;

    type Value = LatestMessage;

    type ValueTableDefinition = SSZEncoding<LatestMessage>;

    fn database(&self) -> Arc<Database> {
        self.db.clone()
    }
}

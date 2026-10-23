//! Gossip that refers to blocks the node has not seen yet: columns that came before their parent
//! block, and blocks that signed messages name before the block itself comes.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Mutex,
};

use alloy_primitives::B256;
use libp2p::PeerId;
use ream_consensus_beacon::data_column_sidecar::{DataColumnSidecar, NUMBER_OF_COLUMNS};
use ream_metrics::{BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL, inc_int_counter_vec};
use ream_storage::cache::BeaconCacheDB;
use tree_hash::TreeHash;

/// Work for the manager loop that gossip handling found.
#[derive(Debug)]
pub enum GossipHint {
    /// A valid-looking column whose parent block is unknown, to check again once it comes.
    UnknownParentColumn {
        column: Box<DataColumnSidecar>,
        peer: PeerId,
    },
    /// A block that a signed message refers to but that has not come.
    UnseenBlock(UnseenBlock),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnseenBlock {
    pub block_root: B256,
    /// The slot of the message that referred to it, which the block is at or before.
    pub slot: u64,
    pub source: UnseenBlockSource,
    pub peer: PeerId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnseenBlockSource {
    /// A column of the block itself.
    Column,
    /// A column whose header names the block as its parent.
    ChildColumn,
    Attestation,
}

impl UnseenBlockSource {
    pub fn as_str(self) -> &'static str {
        match self {
            UnseenBlockSource::Column => "column",
            UnseenBlockSource::ChildColumn => "child_column",
            UnseenBlockSource::Attestation => "attestation",
        }
    }
}

/// Reserves `block_root` for one lookup hint, so the messages of one block report it once.
pub async fn reserve_hint(cached_db: &BeaconCacheDB, block_root: B256) -> bool {
    let mut hinted = cached_db.hinted_block_roots.write().await;
    if hinted.contains(&block_root) {
        return false;
    }
    hinted.put(block_root, ());
    true
}

/// Columns kept for their parent block. About 45 KB each with 21 blobs, so up to about 23 MB.
const MAX_BUFFERED_COLUMNS: usize = 4 * NUMBER_OF_COLUMNS as usize;
/// A column is kept this many slots past its own; parents seen as late as 26 s have come since.
const BUFFERED_COLUMN_SLOTS: u64 = 8;

struct ColumnsOfParent {
    /// The highest column slot, by which the group expires.
    slot: u64,
    columns: Vec<(DataColumnSidecar, PeerId)>,
}

/// Gossip columns whose parent block was not known when they came. Gossip IGNOREs them and does
/// not send them again, so without this the block waits for them by root (consensus-specs Fulu
/// p2p: "a client MAY queue sidecars for processing once the parent block is retrieved").
#[derive(Default)]
pub struct UnknownParentColumns {
    by_parent: HashMap<B256, ColumnsOfParent>,
    keys: HashSet<(B256, u64)>,
}

impl UnknownParentColumns {
    pub fn insert(&mut self, column: DataColumnSidecar, peer: PeerId, current_slot: u64) {
        let header = &column.signed_block_header.message;
        let (slot, parent_root) = (header.slot, header.parent_root);
        let key = (header.tree_hash_root(), column.index);
        if slot + BUFFERED_COLUMN_SLOTS < current_slot || self.keys.contains(&key) {
            inc_int_counter_vec(&BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL, &["skipped"]);
            return;
        }
        while self.keys.len() >= MAX_BUFFERED_COLUMNS {
            // Make room by dropping the oldest group, unless the new column is older still.
            let Some((oldest, oldest_slot)) = self
                .by_parent
                .iter()
                .map(|(root, group)| (*root, group.slot))
                .min_by_key(|(_, slot)| *slot)
            else {
                break;
            };
            if oldest_slot > slot {
                inc_int_counter_vec(&BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL, &["dropped"]);
                return;
            }
            self.remove(oldest, "dropped");
        }
        self.keys.insert(key);
        let group = self
            .by_parent
            .entry(parent_root)
            .or_insert(ColumnsOfParent {
                slot,
                columns: Vec::new(),
            });
        group.slot = group.slot.max(slot);
        group.columns.push((column, peer));
        inc_int_counter_vec(&BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL, &["buffered"]);
    }

    /// The columns waiting for `parent_root`, which has just been imported or become pending.
    pub fn take(&mut self, parent_root: B256) -> Vec<(DataColumnSidecar, PeerId)> {
        let Some(group) = self.by_parent.remove(&parent_root) else {
            return Vec::new();
        };
        for (column, _) in &group.columns {
            self.keys.remove(&(
                column.signed_block_header.message.tree_hash_root(),
                column.index,
            ));
        }
        group.columns
    }

    pub fn prune(&mut self, current_slot: u64) {
        let expired = self
            .by_parent
            .iter()
            .filter(|(_, group)| group.slot + BUFFERED_COLUMN_SLOTS < current_slot)
            .map(|(root, _)| *root)
            .collect::<Vec<_>>();
        for root in expired {
            self.remove(root, "expired");
        }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn remove(&mut self, parent_root: B256, event: &str) {
        let count = self.take(parent_root).len();
        ream_metrics::inc_int_counter_vec_by(
            &BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL,
            count as u64,
            &[event],
        );
    }
}

/// Blocks that passed gossip validation or whose columns were asked of the execution client, so
/// a block is not asked twice and a block still being imported is not looked up.
#[derive(Default)]
pub struct ExecutionFetchReservations {
    recent: Mutex<VecDeque<B256>>,
}

const RECENT_EXECUTION_FETCHES: usize = 256;

impl ExecutionFetchReservations {
    pub fn reserve(&self, block_root: B256) -> bool {
        let mut recent = self.recent.lock().unwrap_or_else(|err| err.into_inner());
        if recent.contains(&block_root) {
            return false;
        }
        if recent.len() == RECENT_EXECUTION_FETCHES {
            recent.pop_front();
        }
        recent.push_back(block_root);
        true
    }

    pub fn contains(&self, block_root: &B256) -> bool {
        self.recent
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .contains(block_root)
    }
}

#[cfg(test)]
mod tests {
    use ream_consensus_misc::beacon_block_header::{BeaconBlockHeader, SignedBeaconBlockHeader};
    use ssz_types::{FixedVector, VariableList};

    use super::*;

    fn column(slot: u64, parent: u8, index: u64) -> DataColumnSidecar {
        DataColumnSidecar {
            index,
            column: VariableList::empty(),
            kzg_commitments: VariableList::empty(),
            kzg_proofs: VariableList::empty(),
            signed_block_header: SignedBeaconBlockHeader {
                message: BeaconBlockHeader {
                    slot,
                    parent_root: B256::repeat_byte(parent),
                    ..Default::default()
                },
                ..Default::default()
            },
            kzg_commitments_inclusion_proof: FixedVector::default(),
        }
    }

    #[test]
    fn columns_are_released_with_their_parent_once() {
        let mut buffer = UnknownParentColumns::default();
        let peer = PeerId::random();
        buffer.insert(column(10, 1, 0), peer, 10);
        buffer.insert(column(10, 1, 0), peer, 10);
        buffer.insert(column(10, 1, 1), peer, 10);
        buffer.insert(column(10, 2, 0), peer, 10);
        assert_eq!(buffer.len(), 3);

        let released = buffer.take(B256::repeat_byte(1));
        assert_eq!(
            released
                .iter()
                .map(|(column, _)| column.index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(buffer.take(B256::repeat_byte(1)).is_empty());
        assert_eq!(buffer.len(), 1);
    }

    #[test]
    fn old_columns_expire_and_make_room() {
        let mut buffer = UnknownParentColumns::default();
        let peer = PeerId::random();
        buffer.insert(column(1, 1, 0), peer, 20);
        assert!(buffer.is_empty());

        buffer.insert(column(10, 1, 0), peer, 10);
        buffer.prune(10 + BUFFERED_COLUMN_SLOTS + 1);
        assert!(buffer.is_empty());

        for index in 0..MAX_BUFFERED_COLUMNS as u64 {
            buffer.insert(column(10, (index / 128) as u8, index % 128), peer, 10);
        }
        buffer.insert(column(5, 9, 0), peer, 10);
        assert_eq!(buffer.len(), MAX_BUFFERED_COLUMNS);
        assert!(buffer.take(B256::repeat_byte(9)).is_empty());

        buffer.insert(column(11, 9, 0), peer, 11);
        assert_eq!(buffer.len(), MAX_BUFFERED_COLUMNS - 127);
        assert_eq!(buffer.take(B256::repeat_byte(9)).len(), 1);
    }

    #[test]
    fn a_block_is_asked_of_the_execution_client_once() {
        let reservations = ExecutionFetchReservations::default();
        assert!(reservations.reserve(B256::repeat_byte(1)));
        assert!(!reservations.reserve(B256::repeat_byte(1)));
        assert!(reservations.contains(&B256::repeat_byte(1)));
        assert!(reservations.reserve(B256::repeat_byte(2)));
    }
}

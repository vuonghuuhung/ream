use std::sync::Arc;

use alloy_primitives::B256;
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    data_column_sidecar::{ColumnIdentifier, DataColumnSidecar},
    electra::beacon_state::BeaconState,
};
use ream_consensus_misc::{
    checkpoint::Checkpoint,
    constants::beacon::GENESIS_SLOT,
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};
#[cfg(not(feature = "disable_ancestor_validation"))]
use ream_fork_choice_beacon::store::get_checkpoint_block_from_db;
use ream_metrics::{
    BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL, BEACON_DATA_COLUMN_SIDECAR_GOSSIP_VERIFICATION_SECONDS,
    BEACON_DATA_COLUMN_SIDECAR_PROCESSING_REQUESTS_TOTAL,
    BEACON_DATA_COLUMN_SIDECAR_PROCESSING_SUCCESSES_TOTAL,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_polynomial_commitments::handlers::verify_data_column_sidecar_kzg_proofs;
use ream_storage::{
    cache::{BeaconCacheDB, ValidatedDataColumnHeader},
    tables::{field::REDBField, table::REDBTable},
};
use tree_hash::TreeHash;

use super::{
    parent::{ParentBlock, find_parent},
    result::DependencyValidationResult,
};

type ValidationResult = DependencyValidationResult<GossipValidatedDataColumn>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipValidatedDataColumn {
    sidecar: Box<DataColumnSidecar>,
}

impl GossipValidatedDataColumn {
    fn new(sidecar: DataColumnSidecar) -> Self {
        Self {
            sidecar: Box::new(sidecar),
        }
    }

    pub(crate) fn sidecar(&self) -> &DataColumnSidecar {
        &self.sidecar
    }

    pub(crate) fn into_inner(self) -> DataColumnSidecar {
        *self.sidecar
    }
}

struct ParentContext {
    block_slot: u64,
    state: Arc<BeaconState>,
    pending_availability: bool,
}

pub async fn validate_data_column_sidecar_full(
    data_column_sidecar: &DataColumnSidecar,
    beacon_chain: &BeaconChain,
    current_time_ms: u64,
    subnet_id: u64,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    BEACON_DATA_COLUMN_SIDECAR_PROCESSING_REQUESTS_TOTAL.inc();
    let timer = BEACON_DATA_COLUMN_SIDECAR_GOSSIP_VERIFICATION_SECONDS.start_timer();

    let result = validate_data_column_sidecar_full_inner(
        data_column_sidecar,
        beacon_chain,
        current_time_ms,
        subnet_id,
        cached_db,
    )
    .await;

    timer.observe_duration();
    if result.is_ok() {
        BEACON_DATA_COLUMN_SIDECAR_PROCESSING_SUCCESSES_TOTAL.inc();
    }

    result
}

async fn validate_data_column_sidecar_full_inner(
    data_column_sidecar: &DataColumnSidecar,
    beacon_chain: &BeaconChain,
    current_time_ms: u64,
    subnet_id: u64,
    cached_db: &BeaconCacheDB,
) -> anyhow::Result<ValidationResult> {
    let header = &data_column_sidecar.signed_block_header.message;
    let tuple = (
        header.slot,
        header.proposer_index,
        data_column_sidecar.index,
    );
    if cached_db
        .seen_data_column_sidecars
        .read()
        .await
        .contains(&tuple)
    {
        return Ok(ValidationResult::Ignore(
            "Already seen sidecar from this proposer for this slot and index".to_string(),
        ));
    }

    if !data_column_sidecar.verify() {
        return Ok(ValidationResult::Reject(
            "Data column sidecar failed basic verification".to_string(),
        ));
    }

    if subnet_id != data_column_sidecar.compute_subnet() {
        return Ok(ValidationResult::Reject(
            "Column sidecar not for correct subnet".to_string(),
        ));
    }

    // Database reads are served without the store lock. The lock is only taken (briefly, by
    // `find_parent`) to consult the pending-availability set.
    let db = beacon_chain.db();
    let genesis_time = db.genesis_time_provider().get()?;
    if !is_not_from_future_slot(genesis_time, header.slot, current_time_ms) {
        return Ok(ValidationResult::Ignore(
            "The sidecar is from a future slot".to_string(),
        ));
    }

    let finalized_checkpoint = db.finalized_checkpoint_provider().get()?;
    if header.slot <= compute_start_slot_at_epoch(finalized_checkpoint.epoch) {
        return Ok(ValidationResult::Ignore(
            "The sidecar is from a slot less than or equal to the latest finalized slot"
                .to_string(),
        ));
    }

    let header_root = header.tree_hash_root();
    // A stored column is not the first for its tuple; ignore it before loading any parent.
    if db
        .column_sidecars_provider()
        .contains(&ColumnIdentifier::new(
            header_root,
            data_column_sidecar.index,
        ))?
    {
        return Ok(ValidationResult::Ignore(
            "Data column sidecar is already stored".to_string(),
        ));
    }

    // One column per block runs the header checks; the others wait and reuse the result.
    let mut header_guard = None;
    let mut header_check = remembered_header_check(
        cached_db,
        header_root,
        data_column_sidecar,
        finalized_checkpoint,
    )
    .await;
    if header_check.is_none() {
        let guard = HeaderLockGuard::lock(cached_db, header_root).await;
        header_check = remembered_header_check(
            cached_db,
            header_root,
            data_column_sidecar,
            finalized_checkpoint,
        )
        .await;
        header_guard = Some(guard);
    }
    let header_already_validated = header_check.is_some();
    // A remembered header skips the parent-state checks, not the ancestry check.
    let remembered_parent_pending = match header_check {
        Some(RememberedHeader::Current) => false,
        Some(RememberedHeader::FinalityMoved | RememberedHeader::ParentWasPending) => {
            if !db.block_provider().contains_key(header.parent_root)? {
                // Still pending: the release re-walks the ancestry once the parent imports.
                true
            } else {
                #[cfg(not(feature = "disable_ancestor_validation"))]
                if get_checkpoint_block_from_db(db, header.parent_root, finalized_checkpoint.epoch)?
                    != finalized_checkpoint.root
                {
                    return Ok(ValidationResult::Reject(
                        "Finalized checkpoint is not an ancestor of the sidecar's block"
                            .to_string(),
                    ));
                }
                false
            }
        }
        None => false,
    };

    let proposer_check = if header_already_validated {
        None
    } else {
        BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL.inc();
        let parent = match find_parent(beacon_chain, header.parent_root).await? {
            Some(ParentBlock::Imported { block, state }) => {
                let Some(parent_state) = state else {
                    return Ok(ValidationResult::Reject(
                        "Sidecar's parent failed validation".to_string(),
                    ));
                };
                Some(ParentContext {
                    block_slot: block.message.slot,
                    state: parent_state,
                    pending_availability: false,
                })
            }
            Some(ParentBlock::PendingAvailability { block, state }) => Some(ParentContext {
                block_slot: block.message.slot,
                state,
                pending_availability: true,
            }),
            None => None,
        };

        // Looking up the parent above does not classify the message. Validation still checks the
        // signature before returning unknown-parent, as required by the gossip specification.
        let head;
        let signature_state: &BeaconState = match &parent {
            Some(parent) => &parent.state,
            None => {
                head = beacon_chain.head()?;
                &head.state
            }
        };
        if usize::try_from(header.proposer_index)
            .ok()
            .and_then(|index| signature_state.validators.get(index))
            .is_none()
        {
            return Ok(ValidationResult::Reject(
                "Sidecar proposer index out of range".to_string(),
            ));
        }
        if !matches!(
            signature_state.verify_block_header_signature(&data_column_sidecar.signed_block_header),
            Ok(true)
        ) {
            return Ok(ValidationResult::Reject(
                "Invalid proposer signature on data column sidecar's block header".to_string(),
            ));
        }

        let Some(ParentContext {
            block_slot,
            state,
            pending_availability,
        }) = parent
        else {
            // Gossip IGNOREs it, but the caller may keep it until the parent comes.
            return Ok(ValidationResult::UnknownParent {
                parent_root: header.parent_root,
            });
        };

        if header.slot <= block_slot {
            return Ok(ValidationResult::Reject(
                "Sidecar slot not higher than parent block's slot".to_string(),
            ));
        }

        #[cfg(not(feature = "disable_ancestor_validation"))]
        if !pending_availability
            && get_checkpoint_block_from_db(db, header.parent_root, finalized_checkpoint.epoch)?
                != finalized_checkpoint.root
        {
            return Ok(ValidationResult::Reject(
                "Finalized checkpoint is not an ancestor of the sidecar's block".to_string(),
            ));
        }

        // A pending parent is absent from the block DB, so ancestry cannot be walked at arrival.
        // Release repeats the normal walk after that parent imports and finality may have advanced.

        Some((state, pending_availability))
    };

    if !data_column_sidecar.verify_inclusion_proof() {
        return Ok(ValidationResult::Reject(
            "Invalid data column sidecar inclusion proof".to_string(),
        ));
    }

    if !matches!(
        verify_data_column_sidecar_kzg_proofs(data_column_sidecar),
        Ok(true)
    ) {
        return Ok(ValidationResult::Reject(
            "Invalid KZG proofs for data column sidecar".to_string(),
        ));
    }

    let pending_availability = match proposer_check {
        Some((state, pending_availability)) => {
            // The parent state's proposer lookahead covers this epoch and the next, so the 128
            // columns of a block need no advanced copy of it. Only a parent more than an epoch
            // older than the sidecar is advanced.
            let expected = if state.determines_proposers_of(compute_epoch_at_slot(header.slot)) {
                state.get_beacon_proposer_index(Some(header.slot))
            } else {
                let mut state = Arc::unwrap_or_clone(state);
                if let Err(err) = state.process_slots(header.slot) {
                    return Ok(ValidationResult::Ignore(format!(
                        "Could not advance parent state to sidecar slot: {err:?}"
                    )));
                }
                state.get_beacon_proposer_index(None)
            };

            match expected {
                Ok(expected_index) if expected_index == header.proposer_index => {}
                Ok(expected_index) => {
                    return Ok(ValidationResult::Reject(format!(
                        "Wrong proposer index: slot {}: expected {expected_index}, got {}",
                        header.slot, header.proposer_index
                    )));
                }
                Err(err) => {
                    return Ok(ValidationResult::Ignore(format!(
                        "Could not get proposer index: {err:?}"
                    )));
                }
            }
            pending_availability
        }
        None => remembered_parent_pending,
    };

    // Re-check under the write lock in case another validation inserted the tuple.
    {
        let mut seen = cached_db.seen_data_column_sidecars.write().await;
        if seen.contains(&tuple) {
            return Ok(ValidationResult::Ignore(
                "Duplicate data column sidecar for (slot, proposer_index, index)".to_string(),
            ));
        }
        seen.put(tuple, ());
    }

    if !matches!(header_check, Some(RememberedHeader::Current)) {
        cached_db.validated_data_column_headers.write().await.put(
            header_root,
            ValidatedDataColumnHeader {
                signature: data_column_sidecar.signed_block_header.signature.clone(),
                finalized_checkpoint,
                parent_pending: pending_availability,
            },
        );
    }
    drop(header_guard);

    if pending_availability {
        return Ok(ValidationResult::ParentPendingAvailability {
            parent_root: header.parent_root,
            validated: GossipValidatedDataColumn::new(data_column_sidecar.clone()),
        });
    }
    Ok(ValidationResult::Accept)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RememberedHeader {
    Current,
    FinalityMoved,
    ParentWasPending,
}

async fn remembered_header_check(
    cached_db: &BeaconCacheDB,
    header_root: B256,
    data_column_sidecar: &DataColumnSidecar,
    finalized_checkpoint: Checkpoint,
) -> Option<RememberedHeader> {
    let headers = cached_db.validated_data_column_headers.read().await;
    let validated = headers.peek(&header_root)?;
    if validated.signature != data_column_sidecar.signed_block_header.signature {
        return None;
    }
    Some(if validated.parent_pending {
        RememberedHeader::ParentWasPending
    } else if validated.finalized_checkpoint != finalized_checkpoint {
        RememberedHeader::FinalityMoved
    } else {
        RememberedHeader::Current
    })
}

/// A block's header lock, removed from the map once no column waits for it.
struct HeaderLockGuard<'a> {
    cached_db: &'a BeaconCacheDB,
    header_root: B256,
    lock: Arc<tokio::sync::Mutex<()>>,
    _guard: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl<'a> HeaderLockGuard<'a> {
    async fn lock(cached_db: &'a BeaconCacheDB, header_root: B256) -> Self {
        let lock = cached_db
            .data_column_header_locks
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .entry(header_root)
            .or_default()
            .clone();
        let guard = lock.clone().lock_owned().await;
        Self {
            cached_db,
            header_root,
            lock,
            _guard: Some(guard),
        }
    }
}

impl Drop for HeaderLockGuard<'_> {
    fn drop(&mut self) {
        self._guard = None;
        let mut locks = self
            .cached_db
            .data_column_header_locks
            .lock()
            .unwrap_or_else(|err| err.into_inner());
        if Arc::strong_count(&self.lock) <= 2 {
            locks.remove(&self.header_root);
        }
    }
}

fn is_not_from_future_slot(genesis_time: u64, slot: u64, current_time_ms: u64) -> bool {
    let network_spec = beacon_network_spec();
    let slots_since_genesis = slot.saturating_sub(GENESIS_SLOT);
    let slot_time_ms = genesis_time
        .saturating_mul(1000)
        .saturating_add(slots_since_genesis.saturating_mul(network_spec.slot_duration_ms));

    current_time_ms.saturating_add(network_spec.maximum_gossip_clock_disparity) >= slot_time_ms
}

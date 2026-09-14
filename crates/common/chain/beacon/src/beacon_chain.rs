use std::sync::Arc;

use alloy_primitives::B256;
use anyhow::bail;
use ream_consensus_beacon::{
    attestation::Attestation,
    attester_slashing::AttesterSlashing,
    data_column_sidecar::{ColumnIdentifier, DataColumnSidecar},
    electra::beacon_block::SignedBeaconBlock,
};
use ream_consensus_misc::{
    constants::beacon::genesis_validators_root, misc::compute_epoch_at_slot,
};
use ream_events_beacon::{BeaconEvent, BeaconEventSender, event::chain::BlockEvent};
use ream_execution_engine::ExecutionEngine;
use ream_execution_rpc_types::forkchoice_update::ForkchoiceStateV1;
use ream_fork_choice_beacon::{
    data_availability::PendingBlock,
    handlers::{
        OnBlockOutcome, on_attestation, on_attester_slashing, on_block, on_tick,
        process_available_block,
    },
    store::Store,
};
use ream_metrics::{
    BEACON_BLOCK_PROCESSING_SECONDS, BEACON_EXECUTION_FORKCHOICE_UPDATE_SECONDS,
    BEACON_STORE_LOCK_WAIT_SECONDS,
};
use ream_network_spec::networks::beacon_network_spec;
use ream_operation_pool::OperationPool;
use ream_req_resp::beacon::messages::status::Status;
use ream_storage::{
    db::beacon::BeaconDB,
    tables::{
        field::REDBField,
        table::{CustomTable, REDBTable},
    },
};
use ream_sync_committee_pool::SyncCommitteePool;
use tokio::sync::{Mutex, broadcast};
use tracing::{debug, warn};
use tree_hash::TreeHash;

pub const BLOCK_IMPORT_EVENT_CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "block processing may be pending data availability rather than imported"]
pub enum BlockProcessingOutcome {
    Imported { block_root: B256 },
    PendingAvailability { block_root: B256 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockImportEvent {
    Imported { block_root: B256 },
    PendingAvailability { block_root: B256 },
}

/// BeaconChain is the main struct which manages the nodes local beacon chain.
pub struct BeaconChain {
    pub store: Mutex<Store>,
    pub execution_engine: Option<ExecutionEngine>,
    pub event_sender: Option<broadcast::Sender<BeaconEvent>>,
    block_import_sender: broadcast::Sender<BlockImportEvent>,
    execution_forkchoice: Mutex<Option<ForkchoiceStateV1>>,
    force_data_availability_checks: bool,
}

impl BeaconChain {
    /// Creates a new instance of `BeaconChain`.
    pub fn new(
        db: BeaconDB,
        operation_pool: Arc<OperationPool>,
        sync_committee_pool: Arc<SyncCommitteePool>,
        execution_engine: Option<ExecutionEngine>,
        event_sender: Option<broadcast::Sender<BeaconEvent>>,
    ) -> Self {
        let (block_import_sender, _) = broadcast::channel(BLOCK_IMPORT_EVENT_CHANNEL_CAPACITY);

        Self {
            store: Mutex::new(Store::new(db, operation_pool, Some(sync_committee_pool))),
            execution_engine,
            event_sender,
            block_import_sender,
            execution_forkchoice: Mutex::new(None),
            force_data_availability_checks: false,
        }
    }

    /// Enables data availability checks independently of the configured Fulu fork epoch.
    /// Intended for test networks that exercise Fulu data flow on an Electra state fixture.
    pub fn force_data_availability_checks(mut self) -> Self {
        self.force_data_availability_checks = true;
        self
    }

    /// Published after the store lock is released, so subscribers can re-enter `process_block`.
    /// Handle `Lagged` by reconciling against the database, or waiting children are stranded.
    pub fn subscribe_block_imports(&self) -> broadcast::Receiver<BlockImportEvent> {
        self.block_import_sender.subscribe()
    }

    pub async fn initialize_execution_forkchoice(&self) {
        self.update_execution_forkchoice(true).await;
    }

    pub async fn process_block(
        &self,
        signed_block: SignedBeaconBlock,
    ) -> anyhow::Result<BlockProcessingOutcome> {
        let block_root = signed_block.message.tree_hash_root();
        let block_processing_timer = BEACON_BLOCK_PROCESSING_SECONDS.start_timer();

        let lock_wait_timer = BEACON_STORE_LOCK_WAIT_SECONDS.start_timer();
        let mut store = self.store.lock().await;
        lock_wait_timer.observe_duration();

        let network_spec = beacon_network_spec();
        let verify_data_availability = self.force_data_availability_checks
            || is_data_availability_check_required(
                compute_epoch_at_slot(signed_block.message.slot),
                store.get_current_store_epoch()?,
                network_spec.fulu_fork_epoch,
                network_spec.min_epochs_for_data_column_sidecars_requests,
            );

        let outcome = on_block(
            &mut store,
            &signed_block,
            &self.execution_engine,
            verify_data_availability,
        )
        .await?;

        if outcome == OnBlockOutcome::PendingAvailability {
            debug!("Block is pending data availability: root={}", block_root);
            drop(store);
            self.notify_block_pending_availability(block_root);
            return Ok(BlockProcessingOutcome::PendingAvailability { block_root });
        }

        self.process_block_attestations(&mut store, &signed_block);
        let block_event = self.build_block_event(&store, &signed_block);
        drop(store);

        self.notify_block_imported(block_root);
        self.publish_block_event(block_event);

        let forkchoice_update_timer = BEACON_EXECUTION_FORKCHOICE_UPDATE_SECONDS.start_timer();
        self.update_execution_forkchoice(true).await;
        forkchoice_update_timer.observe_duration();

        block_processing_timer.observe_duration();
        Ok(BlockProcessingOutcome::Imported { block_root })
    }

    pub async fn process_data_column_sidecar(
        &self,
        block_root: B256,
        column_index: u64,
        slot: u64,
    ) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        let imported_block =
            self.process_data_column_sidecar_locked(&mut store, block_root, column_index, slot)?;
        drop(store);

        if let Some((imported_block_root, block_event)) = imported_block {
            self.notify_block_imported(imported_block_root);
            self.publish_block_event(block_event);
            self.update_execution_forkchoice(true).await;
        }

        Ok(())
    }

    /// Stores and processes a validated column under the same Store guard as a caller-supplied
    /// release check. Coupling these operations prevents mutable finality/ancestry facts from
    /// changing between release validation and completion of a pending block.
    pub async fn import_data_column_sidecar_if<F>(
        &self,
        sidecar: DataColumnSidecar,
        validate_release: F,
    ) -> anyhow::Result<()>
    where
        F: FnOnce(&Store) -> anyhow::Result<()> + Send,
    {
        let block_root = sidecar.signed_block_header.message.tree_hash_root();
        let column_index = sidecar.index;
        let slot = sidecar.signed_block_header.message.slot;
        let mut store = self.store.lock().await;
        validate_release(&store)?;
        store
            .db
            .column_sidecars_provider()
            .insert(ColumnIdentifier::new(block_root, column_index), sidecar)?;
        let imported_block =
            self.process_data_column_sidecar_locked(&mut store, block_root, column_index, slot)?;
        drop(store);

        if let Some((imported_block_root, block_event)) = imported_block {
            self.notify_block_imported(imported_block_root);
            self.publish_block_event(block_event);
            self.update_execution_forkchoice(true).await;
        }

        Ok(())
    }

    fn process_data_column_sidecar_locked(
        &self,
        store: &mut Store,
        block_root: B256,
        column_index: u64,
        slot: u64,
    ) -> anyhow::Result<Option<(B256, Option<BeaconEvent>)>> {
        // Block with available data columns will be stored here, this is
        // a guard check to prevent processing a column for an imported block
        if store.db.block_provider().get(block_root)?.is_some() {
            return Ok(None);
        }

        store
            .data_availability_checker
            .add_column(block_root, column_index, slot);
        if let Some(pending) = store.data_availability_checker.take_if_complete(block_root) {
            Ok(Some(self.import_available_block(store, pending)?))
        } else {
            Ok(None)
        }
    }

    fn import_available_block(
        &self,
        store: &mut Store,
        pending: PendingBlock,
    ) -> anyhow::Result<(B256, Option<BeaconEvent>)> {
        let signed_block = pending.signed_block.clone();
        let block_root = signed_block.message.tree_hash_root();
        process_available_block(store, pending)?;
        self.process_block_attestations(store, &signed_block);
        let block_event = self.build_block_event(store, &signed_block);
        Ok((block_root, block_event))
    }

    /// Returns zero when the beacon block has no known execution payload.
    fn execution_block_hash(store: &Store, block_root: B256) -> B256 {
        store
            .db
            .block_provider()
            .get(block_root)
            .ok()
            .flatten()
            .map(|block| block.message.body.execution_payload.block_hash)
            .unwrap_or_default()
    }

    /// Translates consensus fork choice into Engine API block hashes.
    fn build_forkchoice_state(&self, store: &Store) -> Option<ForkchoiceStateV1> {
        self.execution_engine.as_ref()?;

        let head_root = store
            .get_head()
            .inspect_err(|err| warn!("Failed to read head for forkchoice update: {err}"))
            .ok()?;
        let justified_root = store.db.justified_checkpoint_provider().get().ok()?.root;
        let finalized_root = store.db.finalized_checkpoint_provider().get().ok()?.root;

        Some(ForkchoiceStateV1 {
            head_block_hash: Self::execution_block_hash(store, head_root),
            safe_block_hash: Self::execution_block_hash(store, justified_root),
            finalized_block_hash: Self::execution_block_hash(store, finalized_root),
        })
    }

    /// Updates the execution head without rolling back an accepted consensus import on failure.
    async fn update_execution_forkchoice(&self, allow_initial_update: bool) {
        let Some(execution_engine) = self.execution_engine.as_ref() else {
            return;
        };

        // Recompute after serialization so a delayed import cannot send stale state last.
        let mut last_forkchoice = self.execution_forkchoice.lock().await;
        if last_forkchoice.is_none() && !allow_initial_update {
            return;
        }
        let forkchoice_state = {
            let store = self.store.lock().await;
            self.build_forkchoice_state(&store)
        };
        let Some(forkchoice_state) = forkchoice_state else {
            return;
        };
        if last_forkchoice.as_ref() == Some(&forkchoice_state) {
            return;
        }

        match execution_engine
            .engine_forkchoice_updated_v3(forkchoice_state, None)
            .await
        {
            Ok(result) => {
                *last_forkchoice = Some(forkchoice_state);
                debug!(
                    "Forkchoice updated: execution engine reported {:?}",
                    result.payload_status.status
                );
            }
            Err(err) => warn!("Failed to update execution engine forkchoice: {err}"),
        }
    }

    fn notify_block_imported(&self, block_root: B256) {
        let _ = self
            .block_import_sender
            .send(BlockImportEvent::Imported { block_root });
    }

    fn notify_block_pending_availability(&self, block_root: B256) {
        let _ = self
            .block_import_sender
            .send(BlockImportEvent::PendingAvailability { block_root });
    }

    fn process_block_attestations(&self, store: &mut Store, signed_block: &SignedBeaconBlock) {
        store
            .operation_pool
            .mark_attestations_included(&signed_block.message.body.attestations);

        for attestation in signed_block.message.body.attestations.iter() {
            if let Err(err) = on_attestation(store, attestation.clone(), true) {
                warn!("Failed to process block attestation through fork choice: {err:?}");
            }
        }
    }

    fn build_block_event(
        &self,
        store: &Store,
        signed_block: &SignedBeaconBlock,
    ) -> Option<BeaconEvent> {
        let block_root = signed_block.message.tree_hash_root();
        let finalized_checkpoint = store.db.finalized_checkpoint_provider().get().ok();
        match BlockEvent::from_block(signed_block, finalized_checkpoint, |block_root, epoch| {
            store.get_checkpoint_block(block_root, epoch)
        }) {
            Ok(block_event) => Some(BeaconEvent::Block(block_event)),
            Err(err) => {
                warn!("Failed to build block event after importing {block_root}: {err:?}");
                None
            }
        }
    }

    fn publish_block_event(&self, block_event: Option<BeaconEvent>) {
        if let Some(block_event) = block_event {
            self.event_sender.send_event(block_event);
        }
    }

    pub async fn process_attester_slashing(
        &self,
        attester_slashing: AttesterSlashing,
    ) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        on_attester_slashing(&mut store, attester_slashing)?;
        drop(store);
        self.update_execution_forkchoice(false).await;
        Ok(())
    }

    pub async fn process_attestation(
        &self,
        attestation: Attestation,
        is_from_block: bool,
    ) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        on_attestation(&mut store, attestation, is_from_block)?;
        drop(store);
        self.update_execution_forkchoice(false).await;
        Ok(())
    }

    pub async fn process_tick(&self, time: u64) -> anyhow::Result<()> {
        let mut store = self.store.lock().await;
        on_tick(&mut store, time)?;
        drop(store);
        self.update_execution_forkchoice(false).await;
        Ok(())
    }

    pub async fn build_status_request(&self) -> anyhow::Result<Status> {
        let Ok(finalized_checkpoint) = self
            .store
            .lock()
            .await
            .db
            .finalized_checkpoint_provider()
            .get()
        else {
            bail!("Failed to get finalized checkpoint");
        };

        let head_root = match self.store.lock().await.get_head() {
            Ok(head) => head,
            Err(err) => {
                warn!("Failed to get head root: {err}, falling back to finalized root");
                finalized_checkpoint.root
            }
        };

        let head_slot = match self.store.lock().await.db.block_provider().get(head_root) {
            Ok(Some(block)) => block.message.slot,
            err => {
                bail!("Failed to get block for head root {head_root}: {err:?}");
            }
        };

        Ok(Status {
            fork_digest: beacon_network_spec().fork_digest(
                beacon_network_spec().current_epoch(),
                genesis_validators_root(),
            ),
            finalized_root: finalized_checkpoint.root,
            finalized_epoch: finalized_checkpoint.epoch,
            head_root,
            head_slot,
            earliest_available_slot: 0,
        })
    }
}

/// Check data availability only for blocks within the sidecar retention window.
/// Sidecars for blocks older than roughly 18 days may no longer be available.
pub fn is_data_availability_check_required(
    block_epoch: u64,
    current_epoch: u64,
    fulu_fork_epoch: u64,
    retention_epochs: u64,
) -> bool {
    let boundary_epoch = std::cmp::max(
        fulu_fork_epoch,
        current_epoch.saturating_sub(retention_epochs),
    );

    block_epoch >= boundary_epoch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_availability_boundary_tracks_fulu_and_retention_window() {
        let fulu_epoch = 10;
        let retention_epochs = 100;
        assert!(!is_data_availability_check_required(
            9,
            10,
            fulu_epoch,
            retention_epochs,
        ));
        assert!(is_data_availability_check_required(
            10,
            10,
            fulu_epoch,
            retention_epochs,
        ));

        let current_epoch = fulu_epoch + retention_epochs + 10;
        assert!(!is_data_availability_check_required(
            fulu_epoch + 9,
            current_epoch,
            fulu_epoch,
            retention_epochs,
        ));
        assert!(is_data_availability_check_required(
            fulu_epoch + 10,
            current_epoch,
            fulu_epoch,
            retention_epochs,
        ));
    }
}

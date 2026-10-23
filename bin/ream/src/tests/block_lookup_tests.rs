use std::{
    collections::HashSet,
    net::TcpListener,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy_primitives::B256;
use ream_chain_beacon::beacon_chain::{BeaconChain, BlockImportEvent, BlockProcessingOutcome};
use ream_consensus_beacon::{
    custody_group::PeerCustodyGroups,
    data_column_sidecar::{
        ColumnIdentifier, DataColumnSidecar, get_data_column_sidecars_from_block,
    },
    electra::{
        beacon_block::{BeaconBlock, SignedBeaconBlock},
        beacon_block_body::BeaconBlockBody,
        beacon_state::BeaconState,
    },
    matrix_entry::{compute_cells_and_kzg_proofs, das_context},
};
use ream_consensus_misc::{checkpoint::Checkpoint, constants::beacon::NUM_CUSTODY_GROUPS};
use ream_execution_engine::ExecutionEngine;
use ream_executor::ReamExecutor;
use ream_fork_choice_beacon::data_availability::{
    AvailabilityEntryStatus, DataAvailabilityChecker,
};
use ream_light_client::{
    finality_update::LightClientFinalityUpdate, header::LightClientHeader,
    optimistic_update::LightClientOptimisticUpdate,
};
use ream_mock_execution_engine::block_generator::{
    genesis_execution_payload, sample_blob_and_commitment,
};
use ream_network_manager::{
    block_lookup::{
        BlockLookupConfig, BlockLookupCoordinator, InsertOutcome, apply_block_import_event,
        apply_coordinator_update, execute_coordinator_action, insert_pending_item,
    },
    data_availability_fetch::{ColumnFetchOutcome, fetch_missing_columns},
    gossip_hint::{GossipHint, UnknownParentColumns, UnseenBlockSource},
    gossipsub::{
        handle::{Message, MessageAcceptance, handle_data_column, handle_gossipsub_message},
        validate::{
            data_column_sidecar::{GossipValidatedDataColumn, validate_data_column_sidecar_full},
            result::DependencyValidationResult,
        },
    },
    p2p_sender::P2PSender,
    service::NetworkManagerService,
    timing::ColumnSource,
    unknown_parent_lookup::{
        BlocksByRootRefusals, apply_unknown_parent_update, spawn_unknown_parent_action,
    },
};
use ream_operation_pool::OperationPool;
use ream_p2p::{
    gossipsub::beacon::topics::{GossipTopic, GossipTopicKind},
    network::{
        beacon::{
            channel::{GossipMessage, P2PCallbackResponse, P2PMessage, P2PRequest},
            network_state::NetworkState,
        },
        misc::peer_id_from_enr,
    },
};
use ream_req_resp::beacon::messages::BeaconResponseMessage;
use ream_storage::{
    cache::{AddressSlotIdentifier, BeaconCacheDB},
    tables::{
        field::REDBField,
        table::{CustomTable, REDBTable},
    },
};
use ream_sync_committee_pool::SyncCommitteePool;
use ream_syncer::unknown_parent_lookups::{
    InsertOutcome as UnknownInsertOutcome, MAX_LOOKUPS, UnknownBlockMeta, UnknownParentAction,
    UnknownParentLookupCoordinator,
};
use ream_validator_beacon::{block::sign_beacon_block, randao::sign_randao_reveal};
use serial_test::serial;
use ssz::Encode;
use ssz_types::VariableList;
use tokio::{
    sync::{broadcast, mpsc},
    time::{sleep, timeout},
};
use tree_hash::TreeHash;

use super::{
    beacon_e2e_dev_spec, beacon_e2e_public_keys, beacon_node_config_from_args, beacon_port_offset,
    build_dev_genesis, create_beacon_test_node_db, indexed_private_key,
    initialize_beacon_e2e_genesis_root, initialize_beacon_e2e_network_spec,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

struct BlobBlockFixture {
    signed_block: SignedBeaconBlock,
    post_state: Option<BeaconState>,
    column: DataColumnSidecar,
}

/// A network state without peers: these lookups never fall back to other peers.
fn empty_network_state() -> NetworkState {
    NetworkState {
        local_enr: discv5::Enr::builder()
            .build(&discv5::enr::CombinedKey::generate_secp256k1())
            .expect("valid enr")
            .into(),
        peer_table: Default::default(),
        meta_data: Default::default(),
        status: Default::default(),
        data_dir: std::path::PathBuf::new(),
    }
}

struct GossipLookupHarness {
    beacon_chain: Arc<BeaconChain>,
    cached_db: Arc<BeaconCacheDB>,
    p2p_sender: P2PSender,
    p2p_receiver: mpsc::UnboundedReceiver<P2PMessage>,
    import_receiver: broadcast::Receiver<BlockImportEvent>,
    coordinator: BlockLookupCoordinator,
}

impl GossipLookupHarness {
    async fn new(test_name: &str) -> (Self, BeaconState, SignedBeaconBlock) {
        Self::new_with_forced_data_availability(test_name, true).await
    }

    async fn new_with_forced_data_availability(
        test_name: &str,
        force_data_availability: bool,
    ) -> (Self, BeaconState, SignedBeaconBlock) {
        initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
        let public_keys = beacon_e2e_public_keys();
        let (genesis_state, genesis_block) = build_dev_genesis(&public_keys);
        let ream_db = create_beacon_test_node_db(test_name, 1);
        let genesis_validators_root =
            super::seed_beacon_test_db(&ream_db, genesis_state.clone(), &genesis_block);
        initialize_beacon_e2e_genesis_root(genesis_validators_root);

        let cached_db = Arc::new(BeaconCacheDB::new());
        let beacon_db = ream_db
            .init_beacon_db()
            .expect("beacon DB should reopen")
            .with_cache(cached_db.clone());
        let beacon_chain = BeaconChain::new(
            beacon_db,
            Arc::new(OperationPool::default()),
            Arc::new(SyncCommitteePool::default()),
            None,
            None,
        );
        let beacon_chain = if force_data_availability {
            beacon_chain.force_data_availability_checks()
        } else {
            beacon_chain
        };
        let beacon_chain = Arc::new(beacon_chain);
        {
            let mut store = beacon_chain.store.lock().await;
            store.data_availability_checker = DataAvailabilityChecker::new(HashSet::from([0]));

            // Poison the storage-level "latest state" independently of fork choice. The legacy
            // validation path used this state and would reject every correctly signed fixture
            // below because its validator public keys deliberately do not match.
            let mut unrelated_latest_state = genesis_state.clone();
            unrelated_latest_state.slot = 64;
            let unrelated_public_key =
                super::public_key_from_private_key(indexed_private_key(10_000));
            assert!(
                !public_keys.contains(&unrelated_public_key),
                "the poisoned latest-state key must not belong to any fixture validator"
            );
            for validator in unrelated_latest_state.validators.iter_mut() {
                validator.public_key = unrelated_public_key.clone();
            }
            let unrelated_root = B256::repeat_byte(0xee);
            store
                .db
                .state_provider()
                .insert(unrelated_root, unrelated_latest_state)
                .expect("unrelated latest state should insert");
            store
                .db
                .slot_index_provider()
                .insert(64, unrelated_root)
                .expect("unrelated latest slot should insert");

            let head_root = store.get_head().expect("genesis should remain the head");
            let head_state = store
                .db
                .state_provider()
                .get(head_root)
                .expect("head-state lookup should succeed")
                .expect("head state should exist");
            let latest_state = store
                .db
                .get_latest_state()
                .expect("latest state should exist");
            assert_eq!(head_state.slot, 0);
            assert_eq!(latest_state.slot, 64);
            assert_ne!(
                latest_state.validators[0].public_key, head_state.validators[0].public_key,
                "the fixture must detect accidental get_latest_state validation"
            );
        }

        let import_receiver = beacon_chain.subscribe_block_imports();
        let (p2p_tx, p2p_receiver) = mpsc::unbounded_channel();
        (
            Self {
                beacon_chain,
                cached_db,
                p2p_sender: P2PSender(p2p_tx),
                p2p_receiver,
                import_receiver,
                coordinator: BlockLookupCoordinator::new(
                    BlockLookupConfig::for_data_column_retention(
                        ream_network_spec::networks::beacon_network_spec()
                            .min_epochs_for_data_column_sidecars_requests,
                    ),
                ),
            },
            genesis_state,
            genesis_block,
        )
    }

    async fn wait_for_slot(&self, target_slot: u64) {
        timeout(Duration::from_secs(15), async {
            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system time should follow the Unix epoch")
                    .as_secs();
                self.beacon_chain
                    .process_tick(now)
                    .await
                    .expect("test tick should process");
                let current_slot = self
                    .beacon_chain
                    .store
                    .lock()
                    .await
                    .get_current_slot()
                    .expect("current slot should be available");
                if current_slot >= target_slot {
                    return;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("test genesis should reach the target slot");
    }

    async fn deliver_block(
        &mut self,
        signed_block: &SignedBeaconBlock,
    ) -> (MessageAcceptance, Vec<InsertOutcome>) {
        self.deliver(GossipTopicKind::BeaconBlock, signed_block.as_ssz_bytes())
            .await
    }

    async fn deliver_column(
        &mut self,
        column: &DataColumnSidecar,
    ) -> (MessageAcceptance, Vec<InsertOutcome>) {
        self.deliver(
            GossipTopicKind::DataColumnSidecar(column.compute_subnet()),
            column.as_ssz_bytes(),
        )
        .await
    }

    async fn deliver(
        &mut self,
        kind: GossipTopicKind,
        data: Vec<u8>,
    ) -> (MessageAcceptance, Vec<InsertOutcome>) {
        let topic = GossipTopic {
            fork: ream_network_spec::networks::beacon_network_spec().fork_digest(
                ream_consensus_misc::constants::beacon::FULU_FORK_EPOCH,
                ream_consensus_misc::constants::beacon::genesis_validators_root(),
            ),
            kind,
        };
        let mut pending_item = None;
        let mut unknown_parent_block = None;
        let acceptance = handle_gossipsub_message(
            Message {
                source: None,
                data,
                sequence_number: None,
                topic: topic.into(),
            },
            &self.beacon_chain,
            &self.cached_db,
            &mut pending_item,
            &mut unknown_parent_block,
            &mut Vec::new(),
            libp2p::PeerId::random(),
            |_| {},
        )
        .await;

        let mut outcomes = Vec::new();
        if let Some(item) = pending_item {
            let current_slot = self
                .beacon_chain
                .store
                .lock()
                .await
                .get_current_slot()
                .expect("current slot should be available");
            outcomes.push(insert_pending_item(
                &mut self.coordinator,
                item,
                current_slot,
            ));
        }
        (acceptance, outcomes)
    }

    async fn resume_until_idle(&mut self) {
        for _ in 0..64 {
            let mut made_progress = false;
            loop {
                match self.import_receiver.try_recv() {
                    Ok(event) => {
                        apply_block_import_event(&mut self.coordinator, event);
                        made_progress = true;
                    }
                    Err(broadcast::error::TryRecvError::Empty)
                    | Err(broadcast::error::TryRecvError::Closed) => break,
                    Err(broadcast::error::TryRecvError::Lagged(skipped)) => {
                        panic!("test import receiver lagged by {skipped} events")
                    }
                }
            }

            if let Some(action) = self.coordinator.next_action() {
                made_progress = true;
                let update = execute_coordinator_action(action, &self.beacon_chain).await;
                apply_coordinator_update(&mut self.coordinator, update);
            }

            if !made_progress {
                return;
            }
        }
        panic!("coordinator did not become idle within the bounded test work loop");
    }

    fn assert_no_blocks_by_root_request(&mut self) {
        while let Ok(message) = self.p2p_receiver.try_recv() {
            assert!(
                !matches!(message, P2PMessage::Request(P2PRequest::BlockRoots { .. })),
                "a locally DA-pending parent must not trigger BlocksByRoot"
            );
        }
    }

    async fn respond_to_column_request(
        &mut self,
        expected_peer: libp2p_identity::PeerId,
        expected_root: B256,
        column: DataColumnSidecar,
    ) {
        let request = timeout(TEST_TIMEOUT, self.p2p_receiver.recv())
            .await
            .expect("data-column request should not time out")
            .expect("P2P request channel should remain open");
        let P2PMessage::Request(P2PRequest::DataColumnIdentifiers {
            peer_id,
            column_identifiers,
            callback,
        }) = request
        else {
            panic!("expected a data-columns-by-root request");
        };
        assert_eq!(peer_id, expected_peer);
        assert_eq!(column_identifiers.len(), 1);
        assert_eq!(column_identifiers[0].block_root, expected_root);
        assert_eq!(column_identifiers[0].columns.to_vec(), vec![0]);
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                BeaconResponseMessage::DataColumnSidecarsByRoot(column),
            ))))
            .await
            .expect("data column response should be delivered");
        callback
            .send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .expect("end-of-stream should be delivered");
    }

    async fn assert_imported(&self, block_root: B256) {
        let store = self.beacon_chain.store.lock().await;
        assert!(
            store
                .db
                .block_provider()
                .get(block_root)
                .expect("block lookup should succeed")
                .is_some(),
            "block {block_root} should be imported"
        );
        assert!(
            store
                .db
                .state_provider()
                .get(block_root)
                .expect("state lookup should succeed")
                .is_some(),
            "state {block_root} should be imported"
        );
    }
}

async fn build_blob_block(
    parent_state: &BeaconState,
    parent_block: &SignedBeaconBlock,
    slot: u64,
    proposer_override: Option<u64>,
    blob_seed: u8,
) -> BlobBlockFixture {
    let parent_root = parent_block.message.tree_hash_root();
    let mut state_at_slot = parent_state.clone();
    state_at_slot
        .process_slots(slot)
        .expect("fixture state should advance");
    let expected_proposer = state_at_slot
        .get_beacon_proposer_index(None)
        .expect("fixture should have a proposer");
    let proposer_index = proposer_override.unwrap_or(expected_proposer);
    let private_key = ream_bls::PrivateKey {
        inner: indexed_private_key(proposer_index as usize),
    };
    let (blob, commitment) =
        sample_blob_and_commitment(blob_seed).expect("sample blob should be valid");

    let mut execution_payload = genesis_execution_payload(
        state_at_slot.latest_execution_payload_header.block_hash,
        state_at_slot.compute_timestamp_at_slot(slot),
    );
    execution_payload.prev_randao = state_at_slot.get_randao_mix(state_at_slot.get_current_epoch());
    execution_payload.block_number = state_at_slot.latest_execution_payload_header.block_number + 1;
    execution_payload.block_hash = execution_payload
        .to_execution_header(parent_root, &[])
        .hash_slow();

    let mut body = BeaconBlockBody {
        randao_reveal: sign_randao_reveal(slot, &private_key).expect("RANDAO reveal should sign"),
        eth1_data: state_at_slot.eth1_data.clone(),
        execution_payload,
        blob_kzg_commitments: VariableList::new(vec![commitment])
            .expect("one commitment should fit"),
        ..Default::default()
    };
    body.sync_aggregate.sync_committee_signature = ream_bls::BLSSignature::infinity();
    let mut block = BeaconBlock {
        slot,
        proposer_index,
        parent_root,
        state_root: B256::ZERO,
        body,
    };

    let post_state = if proposer_override.is_none() {
        let mut post_state = state_at_slot;
        post_state
            .process_block(&block, &Option::<ExecutionEngine>::None)
            .await
            .expect("valid fixture block should transition");
        block.state_root = post_state.tree_hash_root();
        Some(post_state)
    } else {
        None
    };
    let signed_block = sign_beacon_block(block, &private_key).expect("fixture block should sign");
    let cells_and_proofs =
        compute_cells_and_kzg_proofs(&blob, das_context()).expect("blob should encode to cells");
    let sidecars = get_data_column_sidecars_from_block(&signed_block, vec![cells_and_proofs])
        .expect("fixture sidecars should build");
    assert_eq!(signed_block.message.body.blob_kzg_commitments.len(), 1);
    assert!(!sidecars[0].column.is_empty());

    BlobBlockFixture {
        signed_block,
        post_state,
        column: sidecars[0].clone(),
    }
}

async fn build_block_without_blobs(
    parent_state: &BeaconState,
    parent_block: &SignedBeaconBlock,
    slot: u64,
) -> (SignedBeaconBlock, BeaconState) {
    let parent_root = parent_block.message.tree_hash_root();
    let mut state_at_slot = parent_state.clone();
    state_at_slot
        .process_slots(slot)
        .expect("fixture state should advance");
    let proposer_index = state_at_slot
        .get_beacon_proposer_index(None)
        .expect("fixture should have a proposer");
    let private_key = ream_bls::PrivateKey {
        inner: indexed_private_key(proposer_index as usize),
    };

    let mut execution_payload = genesis_execution_payload(
        state_at_slot.latest_execution_payload_header.block_hash,
        state_at_slot.compute_timestamp_at_slot(slot),
    );
    execution_payload.prev_randao = state_at_slot.get_randao_mix(state_at_slot.get_current_epoch());
    execution_payload.block_number = state_at_slot.latest_execution_payload_header.block_number + 1;
    execution_payload.block_hash = execution_payload
        .to_execution_header(parent_root, &[])
        .hash_slow();

    let mut body = BeaconBlockBody {
        randao_reveal: sign_randao_reveal(slot, &private_key).expect("RANDAO reveal should sign"),
        eth1_data: state_at_slot.eth1_data.clone(),
        execution_payload,
        ..Default::default()
    };
    body.sync_aggregate.sync_committee_signature = ream_bls::BLSSignature::infinity();
    let mut block = BeaconBlock {
        slot,
        proposer_index,
        parent_root,
        state_root: B256::ZERO,
        body,
    };

    let mut post_state = state_at_slot;
    post_state
        .process_block(&block, &Option::<ExecutionEngine>::None)
        .await
        .expect("valid fixture block should transition");
    block.state_root = post_state.tree_hash_root();
    let signed_block = sign_beacon_block(block, &private_key).expect("fixture block should sign");
    (signed_block, post_state)
}

fn build_network_lookup_chain(
    test_name: &str,
    node_index: usize,
    genesis_state: BeaconState,
    genesis_block: &SignedBeaconBlock,
) -> (
    Arc<BeaconChain>,
    ream_storage::db::beacon::BeaconDB,
    Arc<BeaconCacheDB>,
    Arc<SyncCommitteePool>,
) {
    let ream_db = create_beacon_test_node_db(test_name, node_index);
    super::seed_beacon_test_db(&ream_db, genesis_state, genesis_block);
    let cached_db = Arc::new(BeaconCacheDB::new());
    let beacon_db = ream_db
        .init_beacon_db()
        .expect("beacon DB should reopen")
        .with_cache(cached_db.clone());
    let sync_committee_pool = Arc::new(SyncCommitteePool::default());
    let beacon_chain = Arc::new(BeaconChain::new(
        beacon_db.clone(),
        Arc::new(OperationPool::default()),
        sync_committee_pool.clone(),
        None,
        None,
    ));
    (beacon_chain, beacon_db, cached_db, sync_committee_pool)
}

/// Custody of a peer that serves every column, so a fetch requests all missing columns.
fn full_custody() -> PeerCustodyGroups {
    PeerCustodyGroups::from_advertised(discv5::enr::NodeId::random(), NUM_CUSTODY_GROUPS)
        .expect("full custody is a valid count")
}

fn available_tcp_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("test should reserve an ephemeral TCP port")
        .local_addr()
        .expect("test listener should have a local address")
        .port()
}

fn corrupt_fixture_state_root(fixture: &mut BlobBlockFixture, blob_seed: u8) {
    fixture.signed_block.message.state_root = B256::repeat_byte(0xa5);
    let proposer_index = fixture.signed_block.message.proposer_index;
    let private_key = ream_bls::PrivateKey {
        inner: indexed_private_key(proposer_index as usize),
    };
    fixture.signed_block = sign_beacon_block(fixture.signed_block.message.clone(), &private_key)
        .expect("corrupted fixture should still sign");

    let (blob, commitment) =
        sample_blob_and_commitment(blob_seed).expect("sample blob should be reproducible");
    assert_eq!(
        fixture.signed_block.message.body.blob_kzg_commitments[0],
        commitment
    );
    let cells_and_proofs =
        compute_cells_and_kzg_proofs(&blob, das_context()).expect("blob should encode to cells");
    fixture.column =
        get_data_column_sidecars_from_block(&fixture.signed_block, vec![cells_and_proofs])
            .expect("corrupted fixture sidecar should build")[0]
            .clone();
}

async fn validate_gossip_column(
    harness: &GossipLookupHarness,
    column: &DataColumnSidecar,
) -> DependencyValidationResult<GossipValidatedDataColumn> {
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should follow the Unix epoch")
            .as_millis(),
    )
    .expect("current time should fit in u64 milliseconds");
    validate_data_column_sidecar_full(
        column,
        &harness.beacon_chain,
        now_ms,
        column.compute_subnet(),
        &harness.cached_db,
    )
    .await
    .expect("column validation should not error")
}

#[tokio::test]
#[serial]
async fn test_data_column_header_checks_are_cached_per_signed_header() {
    let (harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("data_column_header_cache").await;
    harness.wait_for_slot(4).await;

    let fixture = build_blob_block(&genesis_state, &genesis_block, 1, None, 1).await;
    let (blob, _) = sample_blob_and_commitment(1).expect("sample blob should be reproducible");
    let cells_and_proofs =
        compute_cells_and_kzg_proofs(&blob, das_context()).expect("blob should encode to cells");
    let columns =
        get_data_column_sidecars_from_block(&fixture.signed_block, vec![cells_and_proofs])
            .expect("fixture sidecars should build");
    let header_root = columns[1].signed_block_header.message.tree_hash_root();

    assert!(matches!(
        validate_gossip_column(&harness, &columns[1]).await,
        DependencyValidationResult::Accept
    ));
    assert!(
        harness
            .cached_db
            .validated_data_column_headers
            .read()
            .await
            .contains(&header_root),
        "a fully validated column must remember its signed header"
    );

    // Break the parent state the header checks read, so only a remembered header can still pass.
    {
        let store = harness.beacon_chain.store.lock().await;
        let parent_root = genesis_block.message.tree_hash_root();
        let mut parent_state = store
            .db
            .state_provider()
            .get(parent_root)
            .expect("parent state lookup should succeed")
            .expect("parent state should exist");
        let proposer_index = fixture.signed_block.message.proposer_index as usize;
        parent_state.validators[proposer_index].public_key =
            super::public_key_from_private_key(indexed_private_key(30_000));
        store
            .db
            .state_provider()
            .insert(parent_root, parent_state)
            .expect("poisoned parent state should insert");
    }

    assert!(
        matches!(
            validate_gossip_column(&harness, &columns[2]).await,
            DependencyValidationResult::Accept
        ),
        "another column of a validated header must not repeat the parent-state checks"
    );

    // The remembered header does not vouch for the column's own cells.
    let mut wrong_proofs = columns[3].clone();
    wrong_proofs.kzg_proofs = columns[4].kzg_proofs.clone();
    assert!(matches!(
        validate_gossip_column(&harness, &wrong_proofs).await,
        DependencyValidationResult::Reject(_)
    ));

    // Nor for a different signature over the same header, which is checked again and fails
    // against the poisoned parent state.
    let mut resigned = columns[5].clone();
    resigned.signed_block_header.signature = ream_bls::BLSSignature::infinity();
    assert!(matches!(
        validate_gossip_column(&harness, &resigned).await,
        DependencyValidationResult::Reject(_)
    ));
}

#[tokio::test]
#[serial]
async fn test_concurrent_columns_of_a_block_check_the_header_once() {
    let (harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("data_column_header_once").await;
    harness.wait_for_slot(4).await;

    let fixture = build_blob_block(&genesis_state, &genesis_block, 1, None, 1).await;
    let (blob, _) = sample_blob_and_commitment(1).expect("sample blob should be reproducible");
    let cells_and_proofs =
        compute_cells_and_kzg_proofs(&blob, das_context()).expect("blob should encode to cells");
    let columns =
        get_data_column_sidecars_from_block(&fixture.signed_block, vec![cells_and_proofs])
            .expect("fixture sidecars should build");

    let checks_before = ream_metrics::BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL.get();
    let (r0, r1, r2, r3, r4, r5, r6, r7) = tokio::join!(
        validate_gossip_column(&harness, &columns[0]),
        validate_gossip_column(&harness, &columns[1]),
        validate_gossip_column(&harness, &columns[2]),
        validate_gossip_column(&harness, &columns[3]),
        validate_gossip_column(&harness, &columns[4]),
        validate_gossip_column(&harness, &columns[5]),
        validate_gossip_column(&harness, &columns[6]),
        validate_gossip_column(&harness, &columns[7]),
    );
    let results = [r0, r1, r2, r3, r4, r5, r6, r7];
    assert!(
        results
            .iter()
            .all(|result| matches!(result, DependencyValidationResult::Accept)),
        "every column of the block is valid"
    );
    assert_eq!(
        ream_metrics::BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL.get() - checks_before,
        1,
        "eight columns arriving together check their shared header once"
    );
    assert!(
        harness
            .cached_db
            .data_column_header_locks
            .lock()
            .unwrap()
            .is_empty(),
        "header locks are dropped once no column waits for them"
    );
}

#[tokio::test]
#[serial]
async fn test_stored_data_column_is_ignored_before_the_parent_checks() {
    let (harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("data_column_already_stored").await;
    harness.wait_for_slot(4).await;

    let fixture = build_blob_block(&genesis_state, &genesis_block, 1, None, 1).await;
    let (blob, _) = sample_blob_and_commitment(1).expect("sample blob should be reproducible");
    let cells_and_proofs =
        compute_cells_and_kzg_proofs(&blob, das_context()).expect("blob should encode to cells");
    let columns =
        get_data_column_sidecars_from_block(&fixture.signed_block, vec![cells_and_proofs])
            .expect("fixture sidecars should build");
    harness
        .beacon_chain
        .db()
        .column_sidecars_provider()
        .insert_batch(vec![columns[6].clone()])
        .expect("column should store");

    let checks_before = ream_metrics::BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL.get();
    assert!(matches!(
        validate_gossip_column(&harness, &columns[6]).await,
        DependencyValidationResult::Ignore(_)
    ));
    assert_eq!(
        ream_metrics::BEACON_DATA_COLUMN_HEADER_CHECKS_TOTAL.get(),
        checks_before,
        "a stored column is ignored without loading its parent"
    );
}

#[tokio::test]
#[serial]
async fn test_pending_parent_block_imports_after_parent_becomes_available() {
    let (mut harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("pending_parent_lookup").await;
    harness.wait_for_slot(4).await;

    let parent = build_blob_block(&genesis_state, &genesis_block, 1, None, 1).await;
    let child = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        2,
        None,
        2,
    )
    .await;
    let expected_sibling_proposer = {
        let mut state = parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state")
            .clone();
        state.process_slots(3).expect("state should advance");
        state
            .get_beacon_proposer_index(None)
            .expect("slot should have proposer")
    };
    let invalid_sibling_proposer = (expected_sibling_proposer + 1)
        % u64::try_from(genesis_state.validators.len()).expect("validator count should fit");
    let invalid_sibling = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        3,
        Some(invalid_sibling_proposer),
        3,
    )
    .await;
    let late_child = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        3,
        None,
        5,
    )
    .await;
    let mut failed_child = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        4,
        None,
        6,
    )
    .await;
    corrupt_fixture_state_root(&mut failed_child, 6);

    let parent_root = parent.signed_block.message.tree_hash_root();
    let child_root = child.signed_block.message.tree_hash_root();
    let sibling_root = invalid_sibling.signed_block.message.tree_hash_root();
    let late_child_root = late_child.signed_block.message.tree_hash_root();
    let failed_child_root = failed_child.signed_block.message.tree_hash_root();

    let (acceptance, insert_outcomes) = harness.deliver_block(&parent.signed_block).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(insert_outcomes.is_empty());
    assert_eq!(
        harness
            .beacon_chain
            .store
            .lock()
            .await
            .data_availability_checker
            .status(&parent_root),
        AvailabilityEntryStatus::PendingBlock
    );

    let (poisoned_head_root, poisoned_proposer_index, original_head_public_key) = {
        // The exact pending-parent registry, not the competing head registry, must authorize both
        // the child block and its column after the mandatory pre-parent signature check.
        let store = harness.beacon_chain.store.lock().await;
        let head_root = store.get_head().expect("head should be available");
        assert_ne!(head_root, parent_root);
        let mut head_state = store
            .db
            .state_provider()
            .get(head_root)
            .expect("head state lookup should succeed")
            .expect("head state should exist");
        let proposer_index = child.signed_block.message.proposer_index as usize;
        let unrelated_public_key = super::public_key_from_private_key(indexed_private_key(20_000));
        let original_head_public_key = head_state.validators[proposer_index].public_key.clone();
        assert_ne!(original_head_public_key, unrelated_public_key);
        head_state.validators[proposer_index].public_key = unrelated_public_key;
        store
            .db
            .state_provider()
            .insert(head_root, head_state)
            .expect("poisoned head state should insert");
        (head_root, proposer_index, original_head_public_key)
    };

    let (acceptance, insert_outcomes) = harness.deliver_block(&child.signed_block).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(matches!(
        insert_outcomes.as_slice(),
        [InsertOutcome::Inserted]
    ));
    let child_proposer = parent
        .post_state
        .as_ref()
        .expect("valid parent should have post-state")
        .validators
        .get(child.signed_block.message.proposer_index as usize)
        .expect("child proposer should exist");
    assert!(
        harness
            .cached_db
            .seen_proposer_signature
            .read()
            .await
            .contains(&AddressSlotIdentifier {
                address: child_proposer.public_key.clone(),
                slot: child.signed_block.message.slot,
            }),
        "a fully validated pending child must enter the seen cache at arrival"
    );
    let pending_count = harness.coordinator.pending_block_count();
    let (duplicate_acceptance, duplicate) = harness.deliver_block(&child.signed_block).await;
    assert!(matches!(duplicate_acceptance, MessageAcceptance::Ignore));
    assert!(duplicate.is_empty());
    assert_eq!(harness.coordinator.pending_block_count(), pending_count);

    let (acceptance, insert_outcomes) = harness.deliver_block(&invalid_sibling.signed_block).await;
    assert!(matches!(acceptance, MessageAcceptance::Reject));
    assert!(insert_outcomes.is_empty());
    assert_eq!(
        harness.coordinator.children(&parent_root),
        vec![child_root],
        "a wrong-proposer child must not enter the coordinator"
    );
    let (acceptance, insert_outcomes) = harness.deliver_column(&invalid_sibling.column).await;
    assert!(matches!(acceptance, MessageAcceptance::Reject));
    assert!(insert_outcomes.is_empty());
    assert!(
        !harness
            .coordinator
            .contains_column(&ColumnIdentifier::new(sibling_root, 0)),
        "a wrong-proposer column must be rejected before pending insertion"
    );

    let (acceptance, insert_outcomes) = harness.deliver_block(&failed_child.signed_block).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(matches!(
        insert_outcomes.as_slice(),
        [InsertOutcome::Inserted]
    ));
    assert_eq!(
        harness.coordinator.children(&parent_root),
        vec![child_root, failed_child_root],
        "multiple valid direct children must coexist under one DA-pending parent"
    );

    for column in [&child.column, &failed_child.column] {
        let (acceptance, insert_outcomes) = harness.deliver_column(column).await;
        assert!(matches!(acceptance, MessageAcceptance::Accept));
        assert!(matches!(
            insert_outcomes.as_slice(),
            [InsertOutcome::Inserted]
        ));
    }
    let (acceptance, insert_outcomes) = harness.deliver_column(&late_child.column).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(matches!(
        insert_outcomes.as_slice(),
        [InsertOutcome::Inserted]
    ));
    assert!(
        harness
            .coordinator
            .contains_column(&ColumnIdentifier::new(late_child_root, 0))
    );

    {
        // Restore the canonical parent state before validating the parent's own column. The
        // temporary mutation above exists only to force the competing-head fallback paths.
        let store = harness.beacon_chain.store.lock().await;
        let mut head_state = store
            .db
            .state_provider()
            .get(poisoned_head_root)
            .expect("head state lookup should succeed")
            .expect("head state should exist");
        head_state.validators[poisoned_proposer_index].public_key = original_head_public_key;
        store
            .db
            .state_provider()
            .insert(poisoned_head_root, head_state)
            .expect("restored head state should insert");
    }

    harness.assert_no_blocks_by_root_request();
    let (acceptance, insert_outcomes) =
        timeout(TEST_TIMEOUT, harness.deliver_column(&parent.column))
            .await
            .expect("parent DA completion deadlocked while children were queued");
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(insert_outcomes.is_empty());

    // This block was never pending: only its column arrived before the parent import. Its typed
    // PendingAvailability outcome must still wake the existing pending column.
    let (acceptance, insert_outcomes) = harness.deliver_block(&late_child.signed_block).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(insert_outcomes.is_empty());

    timeout(TEST_TIMEOUT, harness.resume_until_idle())
        .await
        .expect("pending import deadlocked, likely while holding the Store guard");

    harness.assert_imported(parent_root).await;
    harness.assert_imported(child_root).await;
    harness.assert_imported(late_child_root).await;
    {
        let store = harness.beacon_chain.store.lock().await;
        let child_weight = store
            .get_weight(child_root)
            .expect("child branch weight should be available");
        let late_child_weight = store
            .get_weight(late_child_root)
            .expect("late-child branch weight should be available");
        let expected_head = if (child_weight, child_root) > (late_child_weight, late_child_root) {
            child_root
        } else {
            late_child_root
        };
        assert_eq!(
            store
                .get_head()
                .expect("fork-choice head should be available"),
            expected_head,
            "all imported direct children must participate in fork choice"
        );
        assert!(
            store
                .db
                .block_provider()
                .get(sibling_root)
                .expect("sibling lookup should succeed")
                .is_none(),
            "wrong-proposer sibling must not import"
        );
        assert!(
            store
                .db
                .column_sidecars_provider()
                .get(ColumnIdentifier::new(sibling_root, 0))
                .expect("sibling column lookup should succeed")
                .is_none(),
            "wrong-proposer sibling's column must not enter served storage"
        );
        assert!(
            store
                .db
                .block_provider()
                .get(failed_child_root)
                .expect("failed child lookup should succeed")
                .is_none(),
            "a pending child that fails full import must be dropped"
        );
        assert!(
            store
                .db
                .column_sidecars_provider()
                .get(ColumnIdentifier::new(failed_child_root, 0))
                .expect("failed child column lookup should succeed")
                .is_none(),
            "a failed child's pending column must not enter served storage"
        );
    }
    assert_eq!(harness.coordinator.pending_entry_count(), 0);
    assert_eq!(harness.coordinator.pending_action_count(), 0);
    harness.assert_no_blocks_by_root_request();
}

#[tokio::test]
#[serial]
async fn test_pending_child_is_dropped_if_finality_advances_past_it() {
    let (mut harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("pending_child_finality_advance").await;
    harness.wait_for_slot(2).await;

    let parent = build_blob_block(&genesis_state, &genesis_block, 1, None, 21).await;
    let child = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        2,
        None,
        22,
    )
    .await;
    let parent_root = parent.signed_block.message.tree_hash_root();
    let child_root = child.signed_block.message.tree_hash_root();

    let (acceptance, insert_outcomes) = harness.deliver_block(&parent.signed_block).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(insert_outcomes.is_empty());
    let (acceptance, insert_outcomes) = harness.deliver_block(&child.signed_block).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(matches!(
        insert_outcomes.as_slice(),
        [InsertOutcome::Inserted]
    ));
    let (acceptance, insert_outcomes) = harness.deliver_column(&child.column).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(matches!(
        insert_outcomes.as_slice(),
        [InsertOutcome::Inserted]
    ));

    let (acceptance, insert_outcomes) = harness.deliver_column(&parent.column).await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(insert_outcomes.is_empty());
    harness.assert_imported(parent_root).await;

    {
        let store = harness.beacon_chain.store.lock().await;
        let current = store
            .db
            .finalized_checkpoint_provider()
            .get()
            .expect("finalized checkpoint should exist");
        store
            .db
            .finalized_checkpoint_provider()
            .insert(Checkpoint {
                epoch: 1,
                root: current.root,
            })
            .expect("test finality should advance");
    }

    harness.coordinator.parent_imported(parent_root);
    let action = harness
        .coordinator
        .next_action()
        .expect("parent completion should queue the pending child");
    let update = execute_coordinator_action(action, &harness.beacon_chain).await;
    apply_coordinator_update(&mut harness.coordinator, update);

    assert!(!harness.coordinator.contains_block(&child_root));
    assert!(
        !harness
            .coordinator
            .contains_column(&ColumnIdentifier::new(child_root, 0)),
        "finality rejection must drop the child's pending columns"
    );
    let store = harness.beacon_chain.store.lock().await;
    assert!(
        store
            .db
            .block_provider()
            .get(child_root)
            .expect("child lookup should succeed")
            .is_none(),
        "a child passed by finality while pending must not import"
    );
}

#[tokio::test]
#[serial]
async fn test_finality_advance_before_column_release_does_not_import_pending_child() {
    let (mut harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("pending_child_column_finality_advance").await;
    harness.wait_for_slot(2).await;

    let parent = build_blob_block(&genesis_state, &genesis_block, 1, None, 31).await;
    let child = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        2,
        None,
        32,
    )
    .await;
    let parent_root = parent.signed_block.message.tree_hash_root();
    let child_root = child.signed_block.message.tree_hash_root();
    let child_column = ColumnIdentifier::new(child_root, 0);

    assert!(matches!(
        harness.deliver_block(&parent.signed_block).await.0,
        MessageAcceptance::Accept
    ));
    assert!(matches!(
        harness.deliver_block(&child.signed_block).await.0,
        MessageAcceptance::Accept
    ));
    assert!(matches!(
        harness.deliver_column(&child.column).await.0,
        MessageAcceptance::Accept
    ));
    assert!(matches!(
        harness.deliver_column(&parent.column).await.0,
        MessageAcceptance::Accept
    ));
    harness.assert_imported(parent_root).await;

    harness.coordinator.parent_imported(parent_root);
    let block_action = harness
        .coordinator
        .next_action()
        .expect("parent completion should queue the child block");
    let block_update = execute_coordinator_action(block_action, &harness.beacon_chain).await;
    apply_coordinator_update(&mut harness.coordinator, block_update);
    assert_eq!(
        harness
            .beacon_chain
            .store
            .lock()
            .await
            .data_availability_checker
            .status(&child_root),
        AvailabilityEntryStatus::PendingBlock
    );

    {
        let store = harness.beacon_chain.store.lock().await;
        let current = store
            .db
            .finalized_checkpoint_provider()
            .get()
            .expect("finalized checkpoint should exist");
        store
            .db
            .finalized_checkpoint_provider()
            .insert(Checkpoint {
                epoch: 1,
                root: current.root,
            })
            .expect("test finality should advance");
    }

    let column_action = harness
        .coordinator
        .next_action()
        .expect("pending child should queue its pending column");
    let column_update = execute_coordinator_action(column_action, &harness.beacon_chain).await;
    apply_coordinator_update(&mut harness.coordinator, column_update);

    assert!(!harness.coordinator.contains_column(&child_column));
    let store = harness.beacon_chain.store.lock().await;
    assert!(
        store
            .db
            .column_sidecars_provider()
            .get(child_column)
            .expect("child column lookup should succeed")
            .is_none(),
        "release validation must run before the column enters served storage"
    );
    assert!(
        store
            .db
            .block_provider()
            .get(child_root)
            .expect("child lookup should succeed")
            .is_none(),
        "finality must not race column completion into importing the pending child"
    );
}

#[tokio::test]
#[serial]
async fn test_a_column_that_comes_before_its_parent_is_kept_and_completes_the_child() {
    let (mut harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("column_before_parent").await;
    harness.wait_for_slot(2).await;
    let parent = build_blob_block(&genesis_state, &genesis_block, 1, None, 51).await;
    let child = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        2,
        None,
        52,
    )
    .await;
    let parent_root = parent.signed_block.message.tree_hash_root();
    let child_root = child.signed_block.message.tree_hash_root();
    let peer = libp2p::PeerId::random();

    // The child's column comes first: gossip IGNOREs it, and it is handed back to keep.
    let mut pending_item = None;
    let mut hints = Vec::new();
    let acceptance = handle_data_column(
        Box::new(child.column.clone()),
        child.column.compute_subnet(),
        &harness.beacon_chain,
        &harness.cached_db,
        &mut pending_item,
        &mut hints,
        peer,
        ColumnSource::Gossip,
    )
    .await;
    assert!(matches!(acceptance, MessageAcceptance::Ignore));
    assert!(pending_item.is_none());
    let [
        GossipHint::UnseenBlock(unseen),
        GossipHint::UnknownParentColumn { column, .. },
    ] = hints.as_slice()
    else {
        panic!("expected a parent lookup hint and the column to keep, got {hints:?}");
    };
    assert_eq!(
        (unseen.block_root, unseen.source),
        (parent_root, UnseenBlockSource::ChildColumn)
    );
    let mut kept = UnknownParentColumns::default();
    kept.insert(*column.clone(), peer, 2);

    assert!(matches!(
        harness
            .beacon_chain
            .process_block(parent.signed_block.clone())
            .await,
        Ok(BlockProcessingOutcome::PendingAvailability { .. })
    ));
    harness.deliver_column(&parent.column).await;
    harness.assert_imported(parent_root).await;

    // Released with its parent, the kept column completes the child without a fetch.
    let released = kept.take(parent_root);
    assert_eq!(released.len(), 1);
    let (column, peer) = released.into_iter().next().expect("one column was kept");
    let acceptance = handle_data_column(
        Box::new(column),
        child.column.compute_subnet(),
        &harness.beacon_chain,
        &harness.cached_db,
        &mut pending_item,
        &mut Vec::new(),
        peer,
        ColumnSource::Replayed,
    )
    .await;
    assert!(matches!(acceptance, MessageAcceptance::Accept));
    assert!(matches!(
        harness
            .beacon_chain
            .process_block(child.signed_block.clone())
            .await,
        Ok(BlockProcessingOutcome::Imported { .. })
    ));
    harness.assert_imported(child_root).await;
}

#[tokio::test]
#[serial]
async fn test_unknown_parent_block_imports_after_parent_arrives() {
    let (mut harness, genesis_state, genesis_block) =
        GossipLookupHarness::new_with_forced_data_availability("unknown_parent_lookup", true).await;
    harness.wait_for_slot(2).await;

    let parent = build_blob_block(&genesis_state, &genesis_block, 1, None, 41).await;
    let child = build_blob_block(
        parent
            .post_state
            .as_ref()
            .expect("valid parent should have post-state"),
        &parent.signed_block,
        2,
        None,
        42,
    )
    .await;
    let parent_root = parent.signed_block.message.tree_hash_root();
    let child_root = child.signed_block.message.tree_hash_root();
    let source_peer = libp2p_identity::PeerId::random();

    let topic = GossipTopic {
        fork: ream_network_spec::networks::beacon_network_spec().fork_digest(
            ream_consensus_misc::constants::beacon::FULU_FORK_EPOCH,
            ream_consensus_misc::constants::beacon::genesis_validators_root(),
        ),
        kind: GossipTopicKind::BeaconBlock,
    };
    let mut pending_item = None;
    let mut unknown_parent_block = None;
    let acceptance = handle_gossipsub_message(
        Message {
            source: Some(source_peer),
            data: child.signed_block.as_ssz_bytes(),
            sequence_number: None,
            topic: topic.into(),
        },
        &harness.beacon_chain,
        &harness.cached_db,
        &mut pending_item,
        &mut unknown_parent_block,
        &mut Vec::new(),
        libp2p::PeerId::random(),
        |_| {},
    )
    .await;
    assert!(matches!(acceptance, MessageAcceptance::Ignore));
    assert!(pending_item.is_none());
    let child_proposer = &parent
        .post_state
        .as_ref()
        .expect("valid parent should have post-state")
        .validators[child.signed_block.message.proposer_index as usize];
    let child_proposer_slot = AddressSlotIdentifier {
        address: child_proposer.public_key.clone(),
        slot: child.signed_block.message.slot,
    };
    assert!(
        !harness
            .cached_db
            .seen_proposer_signature
            .read()
            .await
            .contains(&child_proposer_slot),
        "unknown-parent gossip must not be marked seen before exact-state validation"
    );

    let unknown = unknown_parent_block.expect("unknown child should be retained for lookup");
    let mut coordinator = UnknownParentLookupCoordinator::default();
    assert_eq!(
        coordinator.insert_gossip_block(
            UnknownBlockMeta {
                block_root: child_root,
                parent_root: unknown.parent_root,
                slot: unknown.block.message.slot,
            },
            unknown.block,
            source_peer,
        ),
        UnknownInsertOutcome::Inserted
    );

    let (update_sender, mut update_receiver) = mpsc::channel(MAX_LOOKUPS);
    let request_action = coordinator
        .next_action()
        .expect("missing parent should queue a blocks-by-root request");
    assert!(matches!(
        request_action,
        UnknownParentAction::RequestBlock { block_root, .. } if block_root == parent_root
    ));
    spawn_unknown_parent_action(
        request_action,
        harness.beacon_chain.clone(),
        harness.cached_db.clone(),
        harness.p2p_sender.clone(),
        update_sender.clone(),
    );

    let request = timeout(TEST_TIMEOUT, harness.p2p_receiver.recv())
        .await
        .expect("blocks-by-root request should not time out")
        .expect("P2P request channel should remain open");
    let P2PMessage::Request(P2PRequest::BlockRoots {
        peer_id,
        roots,
        callback,
    }) = request
    else {
        panic!("expected a blocks-by-root request");
    };
    assert_eq!(peer_id, source_peer);
    assert_eq!(roots, vec![parent_root]);
    callback
        .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRoot(parent.signed_block.clone()),
        ))))
        .await
        .expect("parent response should be delivered");
    callback
        .send(Ok(P2PCallbackResponse::EndOfStream))
        .await
        .expect("end-of-stream should be delivered");

    let update = timeout(TEST_TIMEOUT, update_receiver.recv())
        .await
        .expect("parent download should finish")
        .expect("lookup update channel should remain open");
    apply_unknown_parent_update(
        &mut coordinator,
        &harness.beacon_chain,
        &empty_network_state(),
        &mut BlocksByRootRefusals::default(),
        update,
    )
    .await;

    for (expected_root, expected_column) in [
        (parent_root, parent.column.clone()),
        (child_root, child.column.clone()),
    ] {
        let action = coordinator
            .next_action()
            .expect("imported ancestry should release the next block");
        assert!(matches!(
            action,
            UnknownParentAction::ProcessBlock { meta, .. } if meta.block_root == expected_root
        ));
        spawn_unknown_parent_action(
            action,
            harness.beacon_chain.clone(),
            harness.cached_db.clone(),
            harness.p2p_sender.clone(),
            update_sender.clone(),
        );
        let update = timeout(TEST_TIMEOUT, update_receiver.recv())
            .await
            .expect("block processing should finish")
            .expect("lookup update channel should remain open");
        apply_unknown_parent_update(
            &mut coordinator,
            &harness.beacon_chain,
            &empty_network_state(),
            &mut BlocksByRootRefusals::default(),
            update,
        )
        .await;

        assert_eq!(
            harness
                .beacon_chain
                .store
                .lock()
                .await
                .data_availability_checker
                .status(&expected_root),
            AvailabilityEntryStatus::PendingBlock
        );
        let beacon_chain = harness.beacon_chain.clone();
        let p2p_sender = harness.p2p_sender.clone();
        let fetch = tokio::spawn(async move {
            fetch_missing_columns(
                &beacon_chain,
                &p2p_sender,
                expected_root,
                source_peer,
                &full_custody(),
            )
            .await
        });
        harness
            .respond_to_column_request(source_peer, expected_root, expected_column)
            .await;
        assert_eq!(
            timeout(TEST_TIMEOUT, fetch)
                .await
                .expect("data-column fetch should finish")
                .expect("data-column fetch task should join"),
            ColumnFetchOutcome::Complete
        );
        harness.assert_imported(expected_root).await;
        coordinator.block_imported(expected_root);
    }

    assert!(coordinator.is_empty());
    assert_eq!(
        harness
            .beacon_chain
            .store
            .lock()
            .await
            .get_head()
            .expect("fork-choice head should be available"),
        child_root
    );
    assert!(
        harness
            .cached_db
            .seen_proposer_signature
            .read()
            .await
            .contains(&child_proposer_slot),
        "the child should enter the seen cache when retried with its imported parent state"
    );
}

#[test]
#[serial]
fn test_unknown_parent_lookup_over_libp2p() {
    initialize_beacon_e2e_network_spec(beacon_e2e_dev_spec());
    let public_keys = beacon_e2e_public_keys();
    let (genesis_state, genesis_block) = build_dev_genesis(&public_keys);
    initialize_beacon_e2e_genesis_root(genesis_state.genesis_validators_root);

    let control_executor = ReamExecutor::new().expect("control executor should start");
    let provider_executor = ReamExecutor::new().expect("provider executor should start");
    let receiver_executor = ReamExecutor::new().expect("receiver executor should start");
    let provider_executor_handle = provider_executor.clone();
    let receiver_executor_handle = receiver_executor.clone();

    control_executor.runtime().block_on(async move {
        let (provider_chain, provider_db, provider_cache, provider_sync_pool) =
            build_network_lookup_chain(
                "unknown_parent_libp2p",
                1,
                genesis_state.clone(),
                &genesis_block,
            );
        let (receiver_chain, receiver_db, receiver_cache, receiver_sync_pool) =
            build_network_lookup_chain(
                "unknown_parent_libp2p",
                2,
                genesis_state.clone(),
                &genesis_block,
            );

        timeout(Duration::from_secs(15), async {
            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system time should follow the Unix epoch")
                    .as_secs();
                provider_chain
                    .process_tick(now)
                    .await
                    .expect("provider tick should process");
                receiver_chain
                    .process_tick(now)
                    .await
                    .expect("receiver tick should process");
                if provider_chain
                    .store
                    .lock()
                    .await
                    .get_current_slot()
                    .expect("provider slot should be available")
                    >= 2
                {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("test genesis should reach slot 2");

        let (parent, parent_state) =
            build_block_without_blobs(&genesis_state, &genesis_block, 1).await;
        let (child, _) = build_block_without_blobs(&parent_state, &parent, 2).await;
        let parent_root = parent.message.tree_hash_root();
        let child_root = child.message.tree_hash_root();
        assert!(matches!(
            provider_chain
                .process_block(parent.clone())
                .await
                .expect("provider should import parent"),
            BlockProcessingOutcome::Imported { block_root } if block_root == parent_root
        ));
        assert!(matches!(
            provider_chain
                .process_block(child.clone())
                .await
                .expect("provider should import child"),
            BlockProcessingOutcome::Imported { block_root } if block_root == child_root
        ));

        let port_offset = beacon_port_offset();
        let mut provider_config = beacon_node_config_from_args(port_offset, None);
        provider_config.disable_discovery = true;
        provider_config.socket_port = available_tcp_port();
        provider_config.discovery_port = 0;
        let provider_manager = provider_executor_handle
            .runtime()
            .spawn(NetworkManagerService::new(
                provider_executor_handle.clone(),
                provider_config.into(),
                provider_db.clone(),
                provider_db.data_dir.clone(),
                provider_chain,
                provider_sync_pool,
                provider_cache,
            ))
            .await
            .expect("provider manager task should join")
            .expect("provider manager should start");
        let provider_enr = provider_manager.network_state.local_enr.read().clone();
        let provider_network_state = provider_manager.network_state.clone();
        let provider_peer =
            peer_id_from_enr(&provider_enr).expect("provider ENR should have peer ID");
        let provider_p2p_sender = provider_manager.p2p_sender.clone();
        let provider_task = provider_executor_handle.spawn(async move {
            provider_manager.start().await;
        });

        // `listen_on` is asynchronous; let the provider swarm poll its listener before the first
        // bootnode dial so the test does not wait for the 20-second redial interval.
        sleep(Duration::from_millis(500)).await;

        let mut receiver_config =
            beacon_node_config_from_args(port_offset + 1, Some(provider_enr.to_base64()));
        receiver_config.disable_discovery = true;
        receiver_config.socket_port = available_tcp_port();
        receiver_config.discovery_port = 0;
        let receiver_manager = receiver_executor_handle
            .runtime()
            .spawn(NetworkManagerService::new(
                receiver_executor_handle.clone(),
                receiver_config.into(),
                receiver_db.clone(),
                receiver_db.data_dir.clone(),
                receiver_chain.clone(),
                receiver_sync_pool,
                receiver_cache,
            ))
            .await
            .expect("receiver manager task should join")
            .expect("receiver manager should start");
        let receiver_network_state = receiver_manager.network_state.clone();
        let receiver_task = receiver_executor_handle.spawn(async move {
            receiver_manager.start().await;
        });

        let connection = timeout(Duration::from_secs(20), async {
            loop {
                if receiver_network_state
                    .connected_peers()
                    .iter()
                    .any(|peer| peer.peer_id == provider_peer)
                {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            connection.is_ok(),
            "receiver should connect to provider {provider_peer}; receiver peers: {:?}; provider peers: {:?}; receiver task finished: {}; provider task finished: {}",
            receiver_network_state.peer_table.read(),
            provider_network_state.peer_table.read(),
            receiver_task.is_finished(),
            provider_task.is_finished(),
        );

        assert!(
            receiver_chain
                .store
                .lock()
                .await
                .db
                .block_provider()
                .get(parent_root)
                .expect("pre-gossip parent lookup should succeed")
                .is_none(),
            "the receiver must learn the parent from the unknown-parent lookup"
        );

        // Let the gossipsub subscription handshake cross at least one heartbeat before publishing.
        sleep(Duration::from_secs(2)).await;
        let topic = GossipTopic {
            fork: ream_network_spec::networks::beacon_network_spec().fork_digest(
                ream_network_spec::networks::beacon_network_spec().current_epoch(),
                ream_consensus_misc::constants::beacon::genesis_validators_root(),
            ),
            kind: GossipTopicKind::BeaconBlock,
        };
        provider_p2p_sender.send_gossip(GossipMessage {
            topic,
            data: child.as_ssz_bytes(),
        });

        timeout(TEST_TIMEOUT, async {
            loop {
                let imported = {
                    let store = receiver_chain.store.lock().await;
                    let has_parent = store
                        .db
                        .block_provider()
                        .get(parent_root)
                        .expect("parent lookup should succeed")
                        .is_some()
                        && store
                            .db
                            .state_provider()
                            .get(parent_root)
                            .expect("parent-state lookup should succeed")
                            .is_some();
                    let has_child = store
                        .db
                        .block_provider()
                        .get(child_root)
                        .expect("child lookup should succeed")
                        .is_some()
                        && store
                            .db
                            .state_provider()
                            .get(child_root)
                            .expect("child-state lookup should succeed")
                            .is_some();
                    has_parent && has_child
                };
                if imported {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("receiver should fetch A over BlocksByRoot, then import A and B");

        assert_eq!(
            receiver_chain
                .store
                .lock()
                .await
                .get_head()
                .expect("receiver head should be available"),
            child_root
        );

        receiver_executor_handle.shutdown_signal();
        provider_executor_handle.shutdown_signal();
        let _ = timeout(Duration::from_secs(5), receiver_task).await;
        let _ = timeout(Duration::from_secs(5), provider_task).await;
    });
}

#[tokio::test]
#[serial]
async fn test_rpc_column_fetch_rechecks_finality_before_import() {
    let (mut harness, genesis_state, genesis_block) =
        GossipLookupHarness::new("rpc_column_finality_advance").await;
    harness.wait_for_slot(1).await;

    let pending = build_blob_block(&genesis_state, &genesis_block, 1, None, 51).await;
    let block_root = pending.signed_block.message.tree_hash_root();
    assert!(matches!(
        harness.deliver_block(&pending.signed_block).await.0,
        MessageAcceptance::Accept
    ));
    // Gossipsub forwards an accepted message itself, so the handler sends nothing.
    assert!(harness.p2p_receiver.try_recv().is_err());
    assert_eq!(
        harness
            .beacon_chain
            .store
            .lock()
            .await
            .data_availability_checker
            .status(&block_root),
        AvailabilityEntryStatus::PendingBlock
    );

    {
        let store = harness.beacon_chain.store.lock().await;
        let current = store
            .db
            .finalized_checkpoint_provider()
            .get()
            .expect("finalized checkpoint should exist");
        store
            .db
            .finalized_checkpoint_provider()
            .insert(Checkpoint {
                epoch: 1,
                root: current.root,
            })
            .expect("test finality should advance");
    }

    let source_peer = libp2p_identity::PeerId::random();
    let beacon_chain = harness.beacon_chain.clone();
    let p2p_sender = harness.p2p_sender.clone();
    let fetch = tokio::spawn(async move {
        fetch_missing_columns(
            &beacon_chain,
            &p2p_sender,
            block_root,
            source_peer,
            &full_custody(),
        )
        .await
    });
    harness
        .respond_to_column_request(source_peer, block_root, pending.column)
        .await;
    assert_eq!(
        timeout(TEST_TIMEOUT, fetch)
            .await
            .expect("data-column fetch should finish")
            .expect("data-column fetch task should join"),
        ColumnFetchOutcome::Incomplete
    );

    let store = harness.beacon_chain.store.lock().await;
    assert!(
        store
            .db
            .block_provider()
            .get(block_root)
            .expect("block lookup should succeed")
            .is_none()
    );
    assert!(
        store
            .db
            .column_sidecars_provider()
            .get(ColumnIdentifier::new(block_root, 0))
            .expect("column lookup should succeed")
            .is_none(),
        "a column rejected at release must not enter served storage"
    );
}

#[tokio::test]
#[serial]
async fn test_a_valid_light_client_update_is_accepted_for_forwarding() {
    let (mut harness, _genesis_state, _genesis_block) =
        GossipLookupHarness::new("light_client_update_acceptance").await;
    let mut attested_header = LightClientHeader::default();
    attested_header.beacon.slot = 1;
    *harness
        .cached_db
        .forwarded_light_client_finality_update
        .write()
        .await = Some(LightClientFinalityUpdate {
        attested_header: attested_header.clone(),
        finalized_header: LightClientHeader::default(),
        finality_branch: Default::default(),
        sync_aggregate: Default::default(),
        signature_slot: 0,
    });
    let update = LightClientOptimisticUpdate {
        attested_header,
        sync_aggregate: Default::default(),
        signature_slot: 0,
    };

    // Gossipsub forwards only what the handler reports as ACCEPT; the handler publishes nothing.
    let (acceptance, _) = harness
        .deliver(
            GossipTopicKind::LightClientOptimisticUpdate,
            update.as_ssz_bytes(),
        )
        .await;
    assert!(
        matches!(acceptance, MessageAcceptance::Accept),
        "expected Accept, got {acceptance:?}"
    );
    assert!(harness.p2p_receiver.try_recv().is_err());

    // A copy for an already forwarded slot is not forwarded again.
    let (acceptance, _) = harness
        .deliver(
            GossipTopicKind::LightClientOptimisticUpdate,
            update.as_ssz_bytes(),
        )
        .await;
    assert!(
        matches!(acceptance, MessageAcceptance::Ignore),
        "expected Ignore, got {acceptance:?}"
    );
}

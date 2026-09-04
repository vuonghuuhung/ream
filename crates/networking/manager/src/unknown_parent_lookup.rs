use std::fmt;

use alloy_primitives::B256;
use libp2p::PeerId;
use ream_chain_beacon::beacon_chain::{BeaconChain, BlockProcessingOutcome};
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use ream_p2p::network::beacon::channel::{P2PCallbackResponse, P2PMessage, P2PRequest};
use ream_req_resp::beacon::messages::BeaconResponseMessage;
use ream_storage::tables::table::REDBTable;
use ream_syncer::unknown_parent_lookups::{
    LookupActionId, ParentStatus, PayloadOrigin, UnknownBlockMeta, UnknownParentAction,
    UnknownParentLookupCoordinator,
};
use tokio::sync::mpsc;
use tracing::warn;
use tree_hash::TreeHash;

use crate::{
    gossipsub::validate::{
        beacon_block::validate_gossip_beacon_block, result::DependencyValidationResult,
    },
    p2p_sender::P2PSender,
};

#[derive(Debug)]
pub enum UnknownParentLookupUpdate {
    Downloaded {
        action_id: LookupActionId,
        requested_root: B256,
        block: Box<SignedBeaconBlock>,
    },
    DownloadFailed {
        action_id: LookupActionId,
        requested_root: B256,
        error: ParentLookupRequestError,
    },
    BlockImported {
        action_id: LookupActionId,
        block_root: B256,
    },
    BlockPendingAvailability {
        action_id: LookupActionId,
        block_root: B256,
    },
    BlockFailed {
        action_id: LookupActionId,
        block_root: B256,
        retry_by_download: bool,
        error: String,
    },
}

pub fn spawn_unknown_parent_action(
    action: UnknownParentAction<SignedBeaconBlock, PeerId>,
    beacon_chain: std::sync::Arc<BeaconChain>,
    cached_db: std::sync::Arc<ream_storage::cache::BeaconCacheDB>,
    p2p_sender: P2PSender,
    update_sender: mpsc::Sender<UnknownParentLookupUpdate>,
) {
    tokio::spawn(async move {
        let update =
            execute_unknown_parent_action(action, &beacon_chain, &cached_db, &p2p_sender).await;
        let _ = update_sender.send(update).await;
    });
}

async fn execute_unknown_parent_action(
    action: UnknownParentAction<SignedBeaconBlock, PeerId>,
    beacon_chain: &BeaconChain,
    cached_db: &ream_storage::cache::BeaconCacheDB,
    p2p_sender: &P2PSender,
) -> UnknownParentLookupUpdate {
    match action {
        UnknownParentAction::RequestBlock {
            action_id,
            block_root,
            peer,
        } => match request_single_block_by_root(p2p_sender, peer, block_root).await {
            Ok(block) => UnknownParentLookupUpdate::Downloaded {
                action_id,
                requested_root: block_root,
                block: Box::new(block),
            },
            Err(err) => UnknownParentLookupUpdate::DownloadFailed {
                action_id,
                requested_root: block_root,
                error: err,
            },
        },
        UnknownParentAction::ProcessBlock {
            action_id,
            meta,
            origin,
            payload,
        } => {
            if let PayloadOrigin::Gossip = origin {
                match validate_gossip_beacon_block(beacon_chain, cached_db, &payload).await {
                    Ok(DependencyValidationResult::Accept) => {}
                    Ok(other) => {
                        return UnknownParentLookupUpdate::BlockFailed {
                            action_id,
                            block_root: meta.block_root,
                            retry_by_download: false,
                            error: format!("gossip validation returned {other:?}"),
                        };
                    }
                    Err(err) => {
                        return UnknownParentLookupUpdate::BlockFailed {
                            action_id,
                            block_root: meta.block_root,
                            retry_by_download: false,
                            error: err.to_string(),
                        };
                    }
                }
            }

            match beacon_chain.process_block(payload).await {
                Ok(BlockProcessingOutcome::Imported { block_root }) => {
                    UnknownParentLookupUpdate::BlockImported {
                        action_id,
                        block_root,
                    }
                }
                Ok(BlockProcessingOutcome::PendingAvailability { block_root }) => {
                    UnknownParentLookupUpdate::BlockPendingAvailability {
                        action_id,
                        block_root,
                    }
                }
                Err(err) => UnknownParentLookupUpdate::BlockFailed {
                    action_id,
                    block_root: meta.block_root,
                    retry_by_download: true,
                    error: err.to_string(),
                },
            }
        }
    }
}

pub async fn parent_status(
    beacon_chain: &BeaconChain,
    parent_root: B256,
) -> anyhow::Result<ParentStatus> {
    let store = beacon_chain.store.lock().await;
    let imported = store.db.block_provider().get(parent_root)?.is_some()
        && store.db.state_provider().get(parent_root)?.is_some();
    if imported {
        return Ok(ParentStatus::Imported);
    }
    if store
        .data_availability_checker
        .pending_block(&parent_root)
        .is_some()
    {
        return Ok(ParentStatus::PendingAvailability);
    }
    Ok(ParentStatus::Unknown)
}

pub async fn apply_unknown_parent_update(
    coordinator: &mut UnknownParentLookupCoordinator<SignedBeaconBlock, PeerId>,
    beacon_chain: &BeaconChain,
    update: UnknownParentLookupUpdate,
) {
    match update {
        UnknownParentLookupUpdate::Downloaded {
            action_id,
            requested_root,
            block,
        } => {
            let meta = UnknownBlockMeta {
                block_root: requested_root,
                parent_root: block.message.parent_root,
                slot: block.message.slot,
            };
            match parent_status(beacon_chain, meta.parent_root).await {
                Ok(status) => {
                    if let Err(err) =
                        coordinator.download_succeeded(action_id, meta, *block, status)
                    {
                        warn!(
                            ?requested_root,
                            ?err,
                            "Dropping invalid parent lookup chain"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        ?requested_root,
                        ?err,
                        "Failed to classify downloaded parent"
                    );
                    coordinator.download_failed(action_id, requested_root);
                }
            }
        }
        UnknownParentLookupUpdate::DownloadFailed {
            action_id,
            requested_root,
            error,
        } => {
            warn!(
                ?requested_root,
                ?error,
                "Blocks-by-root parent lookup failed"
            );
            coordinator.download_failed(action_id, requested_root);
        }
        UnknownParentLookupUpdate::BlockImported {
            action_id,
            block_root,
        } => {
            coordinator.process_imported(action_id, block_root);
        }
        UnknownParentLookupUpdate::BlockPendingAvailability {
            action_id,
            block_root,
        } => {
            coordinator.process_pending_availability(action_id, block_root);
        }
        UnknownParentLookupUpdate::BlockFailed {
            action_id,
            block_root,
            retry_by_download,
            error,
        } => {
            warn!(
                ?block_root,
                ?error,
                "Unknown-parent block processing failed"
            );
            coordinator.process_failed(action_id, block_root, retry_by_download);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentLookupRequestError {
    RequestChannelClosed,
    EmptyResponse,
    ExtraResponse,
    WrongRoot { expected: B256, received: B256 },
    UnexpectedResponseType,
    Disconnected,
    Timeout,
    Callback(String),
    ResponseChannelClosed,
}

impl fmt::Display for ParentLookupRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestChannelClosed => write!(formatter, "P2P request channel closed"),
            Self::EmptyResponse => write!(formatter, "blocks-by-root response was empty"),
            Self::ExtraResponse => write!(formatter, "blocks-by-root returned more than one block"),
            Self::WrongRoot { expected, received } => write!(
                formatter,
                "blocks-by-root returned root {received}, expected {expected}"
            ),
            Self::UnexpectedResponseType => {
                write!(formatter, "received a non-blocks-by-root response")
            }
            Self::Disconnected => write!(formatter, "peer disconnected during blocks-by-root"),
            Self::Timeout => write!(formatter, "blocks-by-root request timed out"),
            Self::Callback(error) => write!(formatter, "blocks-by-root callback failed: {error}"),
            Self::ResponseChannelClosed => {
                write!(
                    formatter,
                    "blocks-by-root response channel closed before end-of-stream"
                )
            }
        }
    }
}

impl std::error::Error for ParentLookupRequestError {}

pub async fn request_single_block_by_root(
    p2p_sender: &P2PSender,
    peer_id: PeerId,
    expected_root: B256,
) -> Result<SignedBeaconBlock, ParentLookupRequestError> {
    let (callback, mut response_receiver) = mpsc::channel(2);
    if p2p_sender
        .0
        .send(P2PMessage::Request(P2PRequest::BlockRoots {
            peer_id,
            roots: vec![expected_root],
            callback,
        }))
        .is_err()
    {
        return Err(ParentLookupRequestError::RequestChannelClosed);
    }

    let mut received_block = None;
    while let Some(response) = response_receiver.recv().await {
        match response {
            Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                let BeaconResponseMessage::BeaconBlocksByRoot(block) = message.as_ref() else {
                    return Err(ParentLookupRequestError::UnexpectedResponseType);
                };
                if received_block.is_some() {
                    return Err(ParentLookupRequestError::ExtraResponse);
                }

                let received_root = block.message.tree_hash_root();
                if received_root != expected_root {
                    return Err(ParentLookupRequestError::WrongRoot {
                        expected: expected_root,
                        received: received_root,
                    });
                }
                received_block = Some(block.clone());
            }
            Ok(P2PCallbackResponse::EndOfStream) => {
                return received_block.ok_or(ParentLookupRequestError::EmptyResponse);
            }
            Ok(P2PCallbackResponse::Disconnected) => {
                return Err(ParentLookupRequestError::Disconnected);
            }
            Ok(P2PCallbackResponse::Timeout) => {
                return Err(ParentLookupRequestError::Timeout);
            }
            Err(err) => return Err(ParentLookupRequestError::Callback(err.to_string())),
        }
    }

    Err(ParentLookupRequestError::ResponseChannelClosed)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::anyhow;
    use ream_p2p::network::beacon::channel::P2PCallbackError;
    use tokio::sync::mpsc::{self, UnboundedReceiver, error::TryRecvError};

    use super::*;

    fn setup() -> (P2PSender, UnboundedReceiver<P2PMessage>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (P2PSender(sender), receiver)
    }

    async fn intercept_request(
        receiver: &mut UnboundedReceiver<P2PMessage>,
        expected_peer: PeerId,
        expected_root: B256,
    ) -> mpsc::Sender<Result<P2PCallbackResponse, P2PCallbackError>> {
        let message = receiver.recv().await.expect("request should be sent");
        let P2PMessage::Request(P2PRequest::BlockRoots {
            peer_id,
            roots,
            callback,
        }) = message
        else {
            panic!("expected a blocks-by-root request");
        };
        assert_eq!(peer_id, expected_peer);
        assert_eq!(roots, vec![expected_root]);
        assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
        callback
    }

    fn block() -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        }
    }

    #[tokio::test]
    async fn returns_one_matching_block_after_end_of_stream() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let block = block();
        let block_root = block.message.tree_hash_root();
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, block_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, block_root).await;
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                BeaconResponseMessage::BeaconBlocksByRoot(block.clone()),
            ))))
            .await
            .expect("block response should be delivered");
        callback
            .send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .expect("end-of-stream should be delivered");

        assert_eq!(request.await.expect("request task should join"), Ok(block));
    }

    #[tokio::test]
    async fn rejects_a_wrong_root() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let block = block();
        let received_root = block.message.tree_hash_root();
        let expected_root = B256::repeat_byte(0x42);
        assert_ne!(received_root, expected_root);
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        callback
            .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                BeaconResponseMessage::BeaconBlocksByRoot(block),
            ))))
            .await
            .expect("wrong-root response should be delivered");

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::WrongRoot {
                expected: expected_root,
                received: received_root,
            })
        );
    }

    #[tokio::test]
    async fn rejects_an_empty_response() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let expected_root = B256::repeat_byte(0x42);
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        callback
            .send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .expect("end-of-stream should be delivered");

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::EmptyResponse)
        );
    }

    #[tokio::test]
    async fn rejects_an_extra_response() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let block = block();
        let expected_root = block.message.tree_hash_root();
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        for _ in 0..2 {
            callback
                .send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
                    BeaconResponseMessage::BeaconBlocksByRoot(block.clone()),
                ))))
                .await
                .expect("block response should be delivered");
        }

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::ExtraResponse)
        );
    }

    #[tokio::test]
    async fn returns_callback_errors() {
        let (sender, mut receiver) = setup();
        let peer_id = PeerId::random();
        let expected_root = B256::repeat_byte(0x42);
        let request_sender = sender.clone();
        let request = tokio::spawn(async move {
            request_single_block_by_root(&request_sender, peer_id, expected_root).await
        });

        let callback = intercept_request(&mut receiver, peer_id, expected_root).await;
        callback
            .send(Err(anyhow!("transport failed").into()))
            .await
            .expect("callback error should be delivered");

        assert_eq!(
            request.await.expect("request task should join"),
            Err(ParentLookupRequestError::Callback(
                "transport failed".to_string()
            ))
        );
    }
}

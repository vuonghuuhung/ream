use alloy_primitives::B256;
use libp2p::PeerId;
use ream_consensus_beacon::{
    blob_sidecar::{BlobIdentifier, BlobSidecar},
    data_column_sidecar::DataColumnSidecar,
    electra::beacon_block::SignedBeaconBlock,
};
use ream_executor::ReamExecutor;
use ream_p2p::network::beacon::channel::{
    P2PCallbackError, P2PCallbackResponse, P2PMessage, P2PRequest,
};
use ream_req_resp::{
    beacon::messages::{BeaconResponseMessage, data_column_sidecars::DataColumnsByRootIdentifier},
    error::ReqRespError,
    inbound_protocol::ResponseCode,
};
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::JoinHandle,
};
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Range {
    pub start_slot: u64,
    pub count: u64,
}

impl Range {
    pub fn new(start_slot: u64, count: u64) -> Self {
        Self { start_slot, count }
    }
}

#[derive(Debug)]
pub enum DownloadFailure {
    Transport(String),
    InvalidData(String),
    RemoteError { code: ResponseCode, message: String },
}

pub enum StreamOutcome<T> {
    Complete(Vec<T>),
    Failed(DownloadFailure),
}

fn classify_req_resp_error(err: ReqRespError) -> DownloadFailure {
    match err {
        ReqRespError::RemoteError { code, message } => {
            DownloadFailure::RemoteError { code, message }
        }
        ReqRespError::InvalidData(message) => DownloadFailure::InvalidData(message),
        other => DownloadFailure::Transport(format!("{other:?}")),
    }
}

async fn drain_responses<T>(
    mut rx: mpsc::Receiver<Result<P2PCallbackResponse, P2PCallbackError>>,
    mut extract: impl FnMut(BeaconResponseMessage) -> Result<T, DownloadFailure>,
) -> StreamOutcome<T> {
    let mut items = vec![];

    while let Some(response) = rx.recv().await {
        match response {
            Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                match extract(message.as_ref().clone()) {
                    Ok(item) => items.push(item),
                    Err(err) => return StreamOutcome::Failed(err),
                }
            }
            Ok(P2PCallbackResponse::EndOfStream) => {
                info!("End of request stream received.");
                return StreamOutcome::Complete(items);
            }
            Ok(P2PCallbackResponse::Disconnected) => {
                return StreamOutcome::Failed(DownloadFailure::Transport(
                    "peer disconnected while receiving response".to_string(),
                ));
            }
            Ok(P2PCallbackResponse::Timeout) => {
                return StreamOutcome::Failed(DownloadFailure::Transport(
                    "request timed out".to_string(),
                ));
            }
            Err(P2PCallbackError::ReqResp(err)) => {
                return StreamOutcome::Failed(classify_req_resp_error(err));
            }
            Err(P2PCallbackError::Other(err)) => {
                return StreamOutcome::Failed(DownloadFailure::Transport(format!("{err:?}")));
            }
        }
    }

    StreamOutcome::Failed(DownloadFailure::Transport(
        "channel closed before EndOfStream".to_string(),
    ))
}

pub struct PeerRangeDownloader;

impl PeerRangeDownloader {
    pub fn start(
        peer_id: PeerId,
        p2p_sender: UnboundedSender<P2PMessage>,
        executor: ReamExecutor,
        range: Range,
    ) -> JoinHandle<anyhow::Result<StreamOutcome<SignedBeaconBlock>>> {
        executor.spawn(async move {
            let (callback, rx) = mpsc::channel(100);
            p2p_sender
                .send(P2PMessage::Request(P2PRequest::BlockRange {
                    peer_id,
                    start: range.start_slot,
                    count: range.count,
                    callback,
                }))
                .expect("Failed to send block range request");

            drain_responses(rx, |message| match message {
                BeaconResponseMessage::BeaconBlocksByRange(block) => Ok(block),
                other => Err(DownloadFailure::InvalidData(format!(
                    "unexpected response variant for a BlockRange request: {other:?}"
                ))),
            })
            .await
        })
    }
}

pub struct PeerRootsDownloader;

impl PeerRootsDownloader {
    pub fn start(
        peer_id: PeerId,
        p2p_sender: UnboundedSender<P2PMessage>,
        executor: ReamExecutor,
        roots: Vec<B256>,
    ) -> JoinHandle<anyhow::Result<StreamOutcome<SignedBeaconBlock>>> {
        executor.spawn(async move {
            let (callback, rx) = mpsc::channel(100);
            p2p_sender
                .send(P2PMessage::Request(P2PRequest::BlockRoots {
                    peer_id,
                    roots,
                    callback,
                }))
                .expect("Failed to send block roots request");

            drain_responses(rx, |message| match message {
                BeaconResponseMessage::BeaconBlocksByRoot(block) => Ok(block),
                other => Err(DownloadFailure::InvalidData(format!(
                    "unexpected response variant for a BlockRoots request: {other:?}"
                ))),
            })
            .await
        })
    }
}

pub struct PeerBlobIdentifierDownloader;

impl PeerBlobIdentifierDownloader {
    pub fn start(
        peer_id: PeerId,
        p2p_sender: UnboundedSender<P2PMessage>,
        executor: ReamExecutor,
        blob_identifiers: Vec<BlobIdentifier>,
    ) -> JoinHandle<anyhow::Result<StreamOutcome<BlobSidecar>>> {
        executor.spawn(async move {
            let (callback, rx) = mpsc::channel(100);
            p2p_sender
                .send(P2PMessage::Request(P2PRequest::BlobIdentifiers {
                    peer_id,
                    blob_identifiers,
                    callback,
                }))
                .expect("Failed to send blob identifiers request");

            drain_responses(rx, |message| match message {
                BeaconResponseMessage::BlobSidecarsByRoot(blob_sidecar) => Ok(blob_sidecar),
                other => Err(DownloadFailure::InvalidData(format!(
                    "unexpected response variant for a BlobIdentifiers request: {other:?}"
                ))),
            })
            .await
        })
    }
}

pub struct PeerDataColumnRangeDownloader;

impl PeerDataColumnRangeDownloader {
    pub fn start(
        peer_id: PeerId,
        p2p_sender: UnboundedSender<P2PMessage>,
        executor: ReamExecutor,
        range: Range,
        columns: Vec<u64>,
    ) -> JoinHandle<anyhow::Result<StreamOutcome<DataColumnSidecar>>> {
        executor.spawn(async move {
            let (callback, rx) = mpsc::channel(100);
            p2p_sender
                .send(P2PMessage::Request(P2PRequest::DataColumnRange {
                    peer_id,
                    start: range.start_slot,
                    count: range.count,
                    columns,
                    callback,
                }))
                .expect("Failed to send data column range request");

            drain_responses(rx, |message| match message {
                BeaconResponseMessage::DataColumnSidecarsByRange(column) => Ok(column),
                other => Err(DownloadFailure::InvalidData(format!(
                    "unexpected response variant for a DataColumnRange request: {other:?}"
                ))),
            })
            .await
        })
    }
}

pub struct PeerDataColumnIdentifierDownloader;

impl PeerDataColumnIdentifierDownloader {
    pub fn start(
        peer_id: PeerId,
        p2p_sender: UnboundedSender<P2PMessage>,
        executor: ReamExecutor,
        identifiers: Vec<DataColumnsByRootIdentifier>,
    ) -> JoinHandle<anyhow::Result<StreamOutcome<DataColumnSidecar>>> {
        executor.spawn(async move {
            let (callback, rx) = mpsc::channel(100);
            p2p_sender
                .send(P2PMessage::Request(P2PRequest::DataColumnIdentifiers {
                    peer_id,
                    column_identifiers: identifiers,
                    callback,
                }))
                .expect("Failed to send data column identifiers request");

            drain_responses(rx, |message| match message {
                BeaconResponseMessage::DataColumnSidecarsByRoot(column) => Ok(column),
                other => Err(DownloadFailure::InvalidData(format!(
                    "unexpected response variant for a DataColumnIdentifiers request: {other:?}"
                ))),
            })
            .await
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    fn test_block() -> SignedBeaconBlock {
        SignedBeaconBlock {
            message: Default::default(),
            signature: Default::default(),
        }
    }

    #[tokio::test]
    async fn drain_responses_rejects_an_unexpected_variant_as_invalid_data() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRange(test_block()),
        ))))
        .await
        .expect("send should succeed");
        tx.send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRoot(test_block()),
        ))))
        .await
        .expect("send should succeed");

        let outcome = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Ok(block),
            other => Err(DownloadFailure::InvalidData(format!(
                "unexpected: {other:?}"
            ))),
        })
        .await;

        assert!(matches!(
            outcome,
            StreamOutcome::Failed(DownloadFailure::InvalidData(_))
        ));
    }

    #[tokio::test]
    async fn drain_responses_completes_on_clean_end_of_stream() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRange(test_block()),
        ))))
        .await
        .expect("send should succeed");
        tx.send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .expect("send should succeed");

        let outcome = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Ok(block),
            other => Err(DownloadFailure::InvalidData(format!(
                "unexpected: {other:?}"
            ))),
        })
        .await;

        let StreamOutcome::Complete(items) = outcome else {
            panic!("expected a complete outcome");
        };
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn drain_responses_treats_channel_close_without_end_of_stream_as_transport_failure() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRange(test_block()),
        ))))
        .await
        .expect("send should succeed");
        drop(tx);

        let outcome = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Ok(block),
            other => Err(DownloadFailure::InvalidData(format!(
                "unexpected: {other:?}"
            ))),
        })
        .await;

        assert!(matches!(
            outcome,
            StreamOutcome::Failed(DownloadFailure::Transport(_))
        ));
    }

    #[tokio::test]
    async fn drain_responses_fails_on_disconnect_without_banning() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::Disconnected))
            .await
            .expect("send should succeed");

        let outcome = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Ok(block),
            other => Err(DownloadFailure::InvalidData(format!(
                "unexpected: {other:?}"
            ))),
        })
        .await;

        assert!(matches!(
            outcome,
            StreamOutcome::Failed(DownloadFailure::Transport(_))
        ));
    }

    #[tokio::test]
    async fn drain_responses_fails_on_timeout_without_banning() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::Timeout))
            .await
            .expect("send should succeed");

        let outcome = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Ok(block),
            other => Err(DownloadFailure::InvalidData(format!(
                "unexpected: {other:?}"
            ))),
        })
        .await;

        assert!(matches!(
            outcome,
            StreamOutcome::Failed(DownloadFailure::Transport(_))
        ));
    }

    #[tokio::test]
    async fn drain_responses_classifies_remote_error_separately_from_invalid_data() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Err(P2PCallbackError::ReqResp(ReqRespError::RemoteError {
            code: ResponseCode::ResourceUnavailable,
            message: "no data for this range".to_string(),
        })))
        .await
        .expect("send should succeed");

        let outcome = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Ok(block),
            other => Err(DownloadFailure::InvalidData(format!(
                "unexpected: {other:?}"
            ))),
        })
        .await;

        assert!(matches!(
            outcome,
            StreamOutcome::Failed(DownloadFailure::RemoteError { .. })
        ));
    }
}

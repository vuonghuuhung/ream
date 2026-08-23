use alloy_primitives::B256;
use anyhow::bail;
use libp2p::PeerId;
use ream_consensus_beacon::{
    blob_sidecar::{BlobIdentifier, BlobSidecar},
    data_column_sidecar::DataColumnSidecar,
    electra::beacon_block::SignedBeaconBlock,
};
use ream_executor::ReamExecutor;
use ream_p2p::network::beacon::channel::{P2PCallbackResponse, P2PMessage, P2PRequest};
use ream_req_resp::beacon::messages::{
    BeaconResponseMessage, data_column_sidecars::DataColumnsByRootIdentifier,
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

async fn drain_responses<T>(
    mut rx: mpsc::Receiver<anyhow::Result<P2PCallbackResponse>>,
    mut extract: impl FnMut(BeaconResponseMessage) -> Option<T>,
) -> anyhow::Result<Vec<T>> {
    let mut items = vec![];

    while let Some(response) = rx.recv().await {
        match response {
            Ok(P2PCallbackResponse::ResponseMessage(message)) => {
                if let Some(item) = extract(message.as_ref().clone()) {
                    items.push(item);
                }
            }
            Ok(P2PCallbackResponse::EndOfStream) => {
                info!("End of request stream received.");
                break;
            }
            Ok(P2PCallbackResponse::Disconnected) => {
                bail!("Peer disconnected while receiving response.");
            }
            Ok(P2PCallbackResponse::Timeout) => {
                bail!("Request timed out.");
            }
            Err(err) => {
                info!("Error receiving response: {err:?}");
            }
        }
    }

    Ok(items)
}

pub struct PeerRangeDownloader;

impl PeerRangeDownloader {
    pub fn start(
        peer_id: PeerId,
        p2p_sender: UnboundedSender<P2PMessage>,
        executor: ReamExecutor,
        range: Range,
    ) -> JoinHandle<anyhow::Result<anyhow::Result<Vec<SignedBeaconBlock>>>> {
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
                BeaconResponseMessage::BeaconBlocksByRange(block) => Some(block),
                _ => None,
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
    ) -> JoinHandle<anyhow::Result<anyhow::Result<Vec<SignedBeaconBlock>>>> {
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
                BeaconResponseMessage::BeaconBlocksByRoot(block) => Some(block),
                _ => None,
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
    ) -> JoinHandle<anyhow::Result<anyhow::Result<Vec<BlobSidecar>>>> {
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
                BeaconResponseMessage::BlobSidecarsByRoot(blob_sidecar) => Some(blob_sidecar),
                _ => None,
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
    ) -> JoinHandle<anyhow::Result<anyhow::Result<Vec<DataColumnSidecar>>>> {
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
                BeaconResponseMessage::DataColumnSidecarsByRange(column) => Some(column),
                _ => None,
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
    ) -> JoinHandle<anyhow::Result<anyhow::Result<Vec<DataColumnSidecar>>>> {
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
                BeaconResponseMessage::DataColumnSidecarsByRoot(column) => Some(column),
                _ => None,
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
    async fn drain_responses_extracts_matching_and_ignores_other_variants() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRange(test_block()),
        ))))
        .await
        .expect("send should succeed");
        // A response for a different request kind must be ignored, not collected or errored on.
        tx.send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRoot(test_block()),
        ))))
        .await
        .expect("send should succeed");
        tx.send(Ok(P2PCallbackResponse::EndOfStream))
            .await
            .expect("send should succeed");

        let items = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Some(block),
            _ => None,
        })
        .await
        .expect("drain should succeed");

        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn drain_responses_returns_collected_items_when_channel_closes() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::ResponseMessage(Arc::new(
            BeaconResponseMessage::BeaconBlocksByRange(test_block()),
        ))))
        .await
        .expect("send should succeed");
        drop(tx);

        let items = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Some(block),
            _ => None,
        })
        .await
        .expect("drain should succeed");

        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn drain_responses_fails_on_disconnect() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::Disconnected))
            .await
            .expect("send should succeed");

        let result = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Some(block),
            _ => None,
        })
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn drain_responses_fails_on_timeout() {
        let (tx, rx) = mpsc::channel(10);
        tx.send(Ok(P2PCallbackResponse::Timeout))
            .await
            .expect("send should succeed");

        let result = drain_responses(rx, |message| match message {
            BeaconResponseMessage::BeaconBlocksByRange(block) => Some(block),
            _ => None,
        })
        .await;

        assert!(result.is_err());
    }
}

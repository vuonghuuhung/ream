use std::io::{self};

use crate::inbound_protocol::ResponseCode;

#[derive(thiserror::Error, Debug)]
pub enum ReqRespError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("Invalid data {0}")]
    InvalidData(String),

    #[error("Remote error [{code:?}]: {message}")]
    RemoteError { code: ResponseCode, message: String },

    #[error("Incomplete stream")]
    IncompleteStream,

    #[error("Stream timed out: {0}")]
    StreamTimedOut(String),

    #[error("Tokio timed out {0}")]
    TokioTimedOut(#[from] tokio::time::error::Elapsed),

    #[error("Disconnected")]
    Disconnected,

    #[error("Raw error message {0}")]
    RawError(String),
}

impl From<ssz::DecodeError> for ReqRespError {
    fn from(err: ssz::DecodeError) -> Self {
        ReqRespError::InvalidData(format!("Failed to decode ssz: {err:?}"))
    }
}

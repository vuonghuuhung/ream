//! `ream::timing` log lines for where each data column came from and who built each block, which
//! the node dashboard reads. One line per received column on a custody node (8 per block) and up
//! to 128 on a supernode; each costs about as much as the `column write` line already logged.

use std::time::{SystemTime, UNIX_EPOCH};

use libp2p::PeerId;
use ream_consensus_beacon::electra::beacon_block::SignedBeaconBlock;
use ream_network_spec::networks::beacon_network_spec;
use tracing::debug;

/// How the node obtained a data column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnSource {
    Gossip,
    ByRoot,
    ExecutionLayer,
    Reconstructed,
    /// Came over gossip before its parent block and was kept until the parent came.
    Replayed,
}

impl ColumnSource {
    fn as_str(self) -> &'static str {
        match self {
            ColumnSource::Gossip => "gossip",
            ColumnSource::ByRoot => "by_root",
            ColumnSource::ExecutionLayer => "el",
            ColumnSource::Reconstructed => "reconstructed",
            ColumnSource::Replayed => "replayed",
        }
    }
}

/// Milliseconds from the start of `slot` until now; negative before the slot starts.
fn into_slot_ms(genesis_time: u64, slot: u64) -> i64 {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as i64);
    let slot_start_ms =
        (genesis_time + slot.saturating_mul(beacon_network_spec().seconds_per_slot())) as i64
            * 1000;
    now_ms - slot_start_ms
}

/// Logs the columns of the block at `slot` the node received from `source`, and the peer that
/// sent them over the network.
pub fn log_columns_received(
    genesis_time: u64,
    slot: u64,
    indices: impl IntoIterator<Item = u64>,
    source: ColumnSource,
    peer: Option<&PeerId>,
) {
    let indices = indices
        .into_iter()
        .map(|index| index.to_string())
        .collect::<Vec<_>>();
    if indices.is_empty() {
        return;
    }
    debug!(
        target: "ream::timing",
        "timing: columns received slot={slot} source={} peer={} indices={} into_slot_ms={}",
        source.as_str(),
        peer.map_or_else(|| "none".to_string(), PeerId::to_string),
        indices.join(","),
        into_slot_ms(genesis_time, slot),
    );
}

/// Logs a lookup of `block_root`, a block of `slot` that gossip from `source` referred to before
/// the block came.
pub fn log_unseen_block_lookup(
    genesis_time: u64,
    slot: u64,
    block_root: alloy_primitives::B256,
    source: &str,
) {
    debug!(
        target: "ream::timing",
        "timing: unseen block lookup slot={slot} root={block_root} source={source} into_slot_ms={}",
        into_slot_ms(genesis_time, slot),
    );
}

/// Logs who built `block`: its proposer, the payload's fee recipient, and the graffiti and payload
/// extra data, where proposers and builders usually name themselves.
pub fn log_block_proposer(genesis_time: u64, block: &SignedBeaconBlock) {
    let message = &block.message;
    let payload = &message.body.execution_payload;
    debug!(
        target: "ream::timing",
        "timing: block proposer slot={} proposer_index={} fee_recipient={} graffiti=\"{}\" extra_data=\"{}\" into_slot_ms={}",
        message.slot,
        message.proposer_index,
        payload.fee_recipient,
        printable(message.body.graffiti.as_slice()),
        printable(&payload.extra_data[..]),
        into_slot_ms(genesis_time, message.slot),
    );
}

/// The printable ASCII of `bytes`, without trailing zero padding. Quotes and backslashes become
/// `_`, so the value stays one quoted field of the log line.
fn printable(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    bytes[..end]
        .iter()
        .map(|byte| match *byte {
            b'"' | b'\\' => '_',
            0x20..=0x7e => *byte as char,
            _ => '.',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graffiti_and_extra_data_print_as_one_field() {
        let mut graffiti = [0u8; 32];
        graffiti[..9].copy_from_slice(b"Lighthous");
        assert_eq!(printable(&graffiti), "Lighthous");
        assert_eq!(printable(b"say \"hi\"\\\x01"), "say _hi__.");
        assert_eq!(printable(&[0u8; 32]), "");
    }
}

use std::{
    collections::{HashMap, hash_map::Entry},
    sync::Arc,
    time::{Duration, Instant},
};

use alloy_primitives::B256;
use libp2p::PeerId;
use ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
use ream_p2p::network::beacon::{network_state::NetworkState, peer::CachedPeer};
use tracing::warn;

/// How long a peer stays banned before it becomes eligible to rejoin the peer set.
const BAN_DURATION: Duration = Duration::from_secs(300);

/// Majority-agreed (slot, root), tagged with root so peer selection can target this chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncTarget {
    pub slot: u64,
    pub root: B256,
}

/// Why a peer was banned. Still just bans outright either way, but structured (instead of a
/// free-text string) so a future scoring system can weigh severities without touching call sites.
#[derive(Debug, Clone)]
pub enum BanReason {
    EmptyResponse,
    /// Disconnect, timeout, decode error, or a response that didn't fit the cache.
    ProtocolError(String),
    /// Failed KZG or inclusion proof verification.
    InvalidProof(String),
}

impl std::fmt::Display for BanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BanReason::EmptyResponse => write!(f, "empty response"),
            BanReason::ProtocolError(detail) => write!(f, "protocol error: {detail}"),
            BanReason::InvalidProof(detail) => write!(f, "invalid proof: {detail}"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PeerStatus {
    Idle,
    Downloading,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer: CachedPeer,
    pub peer_status: PeerStatus,
}

pub struct PeerManager {
    network_state: Arc<NetworkState>,
    peers: HashMap<PeerId, PeerInfo>,
    banned_peers: HashMap<PeerId, Instant>,
    ban_reasons: HashMap<PeerId, BanReason>,
}

impl PeerManager {
    pub fn new(network_state: Arc<NetworkState>) -> Self {
        Self {
            network_state,
            peers: HashMap::new(),
            banned_peers: HashMap::new(),
            ban_reasons: HashMap::new(),
        }
    }

    pub fn update_peer_set(&mut self) {
        let now = Instant::now();
        self.banned_peers
            .retain(|_, banned_at| now.duration_since(*banned_at) < BAN_DURATION);
        self.ban_reasons
            .retain(|peer_id, _| self.banned_peers.contains_key(peer_id));

        let connected_peers = self.network_state.connected_peers();
        for peer in &connected_peers {
            if self.banned_peers.contains_key(&peer.peer_id) {
                continue;
            }

            match self.peers.entry(peer.peer_id) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().peer = peer.clone();
                }
                Entry::Vacant(entry) => {
                    entry.insert(PeerInfo {
                        peer: peer.clone(),
                        peer_status: PeerStatus::Idle,
                    });
                }
            }
        }

        // Remove disconnected peers
        self.peers
            .retain(|peer_id, _| connected_peers.iter().any(|peer| peer.peer_id == *peer_id));
    }

    pub fn ban_peer(&mut self, peer_id: &PeerId, reason: BanReason) {
        self.ban_reasons.insert(*peer_id, reason);
        if let Some(peer_info) = self.peers.remove(peer_id) {
            self.banned_peers
                .insert(peer_info.peer.peer_id, Instant::now());
        } else {
            warn!("Attempted to ban a peer that is not in the peer set: {peer_id}");
        }
    }

    /// Fetches an idle peer from the peer set.
    ///
    /// Will set the peer status to `Downloading` if an idle peer is found.
    pub fn fetch_idle_peer(&mut self) -> Option<CachedPeer> {
        for peer_info in self.peers.values_mut() {
            if let PeerStatus::Idle = peer_info.peer_status {
                peer_info.peer_status = PeerStatus::Downloading;
                return Some(peer_info.peer.clone());
            }
        }
        None
    }

    pub fn fetch_idle_peer_preferring(&mut self, target_root: Option<B256>) -> Option<CachedPeer> {
        if let Some(target_root) = target_root {
            for peer_info in self.peers.values_mut() {
                let matches_target = peer_info.peer.status.as_ref().is_some_and(|status| {
                    status.head_root == target_root || status.finalized_root == target_root
                });
                if matches_target && matches!(peer_info.peer_status, PeerStatus::Idle) {
                    peer_info.peer_status = PeerStatus::Downloading;
                    return Some(peer_info.peer.clone());
                }
            }
        }

        self.fetch_idle_peer()
    }

    pub fn peer_counts(&self) -> String {
        let total_peers = self.peers.len();
        let idle_peers = self
            .peers
            .values()
            .filter(|peer_info| matches!(peer_info.peer_status, PeerStatus::Idle))
            .count();
        let downloading_peers = total_peers - idle_peers;

        format!(
            "Total Peers: {total_peers}, Idle: {idle_peers}, Downloading: {downloading_peers}, Banned: {}",
            self.banned_peers.len()
        )
    }

    /// Marks a peer as idle after a download is complete.
    pub fn mark_peer_as_idle(&mut self, peer_id: &PeerId) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.peer_status = PeerStatus::Idle;
        }
    }

    /// Majority vote on (epoch, root), not just epoch, so two forks can't be merged as "agreed".
    pub fn finalized_target(&self) -> Option<SyncTarget> {
        let mut frequencies: HashMap<(u64, B256), usize> = HashMap::new();

        for peer in self.peers.values() {
            if let Some(status) = &peer.peer.status {
                *frequencies
                    .entry((
                        status.finalized_epoch * SLOTS_PER_EPOCH,
                        status.finalized_root,
                    ))
                    .or_insert(0) += 1;
            }
        }

        frequencies
            .into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|((slot, root), _)| SyncTarget { slot, root })
    }

    /// Majority vote on (slot, root); replaces a bare max() so one outlier can't skew the target.
    pub fn head_target(&self) -> Option<SyncTarget> {
        let mut frequencies: HashMap<(u64, B256), usize> = HashMap::new();

        for peer in self.peers.values() {
            if let Some(status) = &peer.peer.status {
                *frequencies
                    .entry((status.head_slot, status.head_root))
                    .or_insert(0) += 1;
            }
        }

        frequencies
            .into_iter()
            .max_by_key(|&(_, count)| count)
            .map(|((slot, root), _)| SyncTarget { slot, root })
    }

    pub fn sync_target(&self) -> Option<SyncTarget> {
        self.head_target().or_else(|| self.finalized_target())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use discv5::{Enr, enr::CombinedKey};
    use parking_lot::RwLock;
    use ream_peer::{ConnectionState, Direction};
    use ream_req_resp::beacon::messages::{meta_data::GetMetaDataV3, status::Status};

    use super::*;

    fn test_network_state() -> Arc<NetworkState> {
        let enr_key = CombinedKey::generate_secp256k1();
        Arc::new(NetworkState {
            local_enr: RwLock::new(Enr::builder().build(&enr_key).expect("valid enr")),
            peer_table: RwLock::new(HashMap::new()),
            meta_data: RwLock::new(GetMetaDataV3::default()),
            status: RwLock::new(Status::default()),
            data_dir: PathBuf::new(),
        })
    }

    fn test_peer(status: Status) -> CachedPeer {
        let mut peer = CachedPeer::new(
            PeerId::random(),
            None,
            ConnectionState::Connected,
            Direction::Outbound,
            None,
        );
        peer.status = Some(status);
        peer
    }

    fn insert_idle(peer_manager: &mut PeerManager, peer: CachedPeer) {
        peer_manager.peers.insert(
            peer.peer_id,
            PeerInfo {
                peer,
                peer_status: PeerStatus::Idle,
            },
        );
    }

    #[test]
    fn finalized_target_does_not_merge_different_forks_with_same_epoch() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let root_a = B256::repeat_byte(0xAA);
        let root_b = B256::repeat_byte(0xBB);

        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                finalized_epoch: 10,
                finalized_root: root_a,
                ..Default::default()
            }),
        );
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                finalized_epoch: 10,
                finalized_root: root_b,
                ..Default::default()
            }),
        );

        // 1 vote each: must not merge into a false "2 votes" just because the epoch matches.
        let target = peer_manager
            .finalized_target()
            .expect("a target should be picked");
        assert!(target.root == root_a || target.root == root_b);
    }

    #[test]
    fn head_target_ignores_outlier_without_plurality() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let honest_root = B256::repeat_byte(0x11);
        let lying_root = B256::repeat_byte(0x22);

        for _ in 0..3 {
            insert_idle(
                &mut peer_manager,
                test_peer(Status {
                    head_slot: 100,
                    head_root: honest_root,
                    ..Default::default()
                }),
            );
        }
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                head_slot: 999_999,
                head_root: lying_root,
                ..Default::default()
            }),
        );

        let target = peer_manager
            .head_target()
            .expect("a target should be picked");
        assert_eq!(target.slot, 100);
        assert_eq!(target.root, honest_root);
    }

    #[test]
    fn fetch_idle_peer_preferring_prefers_matching_root_then_falls_back() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let target_root = B256::repeat_byte(0x33);
        let other_root = B256::repeat_byte(0x44);

        let matching = test_peer(Status {
            head_root: target_root,
            ..Default::default()
        });
        let matching_id = matching.peer_id;
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                head_root: other_root,
                ..Default::default()
            }),
        );
        insert_idle(&mut peer_manager, matching);

        let peer = peer_manager
            .fetch_idle_peer_preferring(Some(target_root))
            .expect("a peer should be found");
        assert_eq!(peer.peer_id, matching_id);

        // No peer matches this root: falls back to any idle peer instead of returning None.
        let unrelated_root = B256::repeat_byte(0x55);
        assert!(
            peer_manager
                .fetch_idle_peer_preferring(Some(unrelated_root))
                .is_some()
        );
    }

    #[test]
    fn bans_expire_after_ban_duration() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let peer = test_peer(Status::default());
        let peer_id = peer.peer_id;
        insert_idle(&mut peer_manager, peer);

        peer_manager.ban_peer(&peer_id, BanReason::EmptyResponse);
        assert!(peer_manager.banned_peers.contains_key(&peer_id));

        // Simulate the ban having happened BAN_DURATION ago.
        peer_manager.banned_peers.insert(
            peer_id,
            Instant::now() - BAN_DURATION - Duration::from_secs(1),
        );

        peer_manager.update_peer_set();
        assert!(!peer_manager.banned_peers.contains_key(&peer_id));
    }

    #[test]
    fn mark_peer_as_idle_recovers_a_stuck_downloading_peer() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let peer = test_peer(Status::default());
        let peer_id = peer.peer_id;
        peer_manager.peers.insert(
            peer_id,
            PeerInfo {
                peer,
                peer_status: PeerStatus::Downloading,
            },
        );

        peer_manager.mark_peer_as_idle(&peer_id);

        assert!(matches!(
            peer_manager
                .peers
                .get(&peer_id)
                .expect("peer exists")
                .peer_status,
            PeerStatus::Idle
        ));
    }
}

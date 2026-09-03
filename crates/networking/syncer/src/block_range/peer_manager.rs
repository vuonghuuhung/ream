use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    sync::Arc,
    time::{Duration, Instant},
};

use libp2p::PeerId;
use ream_consensus_misc::constants::beacon::SLOTS_PER_EPOCH;
use ream_p2p::network::beacon::{network_state::NetworkState, peer::CachedPeer};
use ream_req_resp::beacon::messages::status::Status;
use tracing::warn;

/// How long a peer stays banned before it becomes eligible to rejoin the peer set.
const BAN_DURATION: Duration = Duration::from_secs(300);

pub const MIN_SYNC_PEERS: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetSelection {
    Ready {
        target_slot: u64,
        eligible_peers: Vec<PeerId>,
    },
    NoQuorum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetQualification {
    FinalizedEpoch(u64),
    HeadEpoch(u64),
}

/// Why a peer was banned. Still just bans outright either way, but structured (instead of a
/// free-text string) so a future scoring system can weigh severities without touching call sites.
#[derive(Debug, Clone)]
pub enum BanReason {
    /// Disconnect, timeout, decode error, or a response that didn't fit the cache.
    ProtocolError(String),
    /// Failed KZG or inclusion proof verification.
    InvalidProof(String),
}

impl std::fmt::Display for BanReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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
    pub processed_blocks: u64,
    pub sync_requests_started: u64,
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
                        processed_blocks: 0,
                        sync_requests_started: 0,
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

    fn reserve(&mut self, peer_id: &PeerId) -> Option<CachedPeer> {
        let peer_info = self.peers.get_mut(peer_id)?;
        if !matches!(peer_info.peer_status, PeerStatus::Idle) {
            return None;
        }
        peer_info.peer_status = PeerStatus::Downloading;
        peer_info.sync_requests_started += 1;
        Some(peer_info.peer.clone())
    }

    /// Fetches an idle peer from the peer set.
    ///
    /// Will set the peer status to `Downloading` if an idle peer is found.
    pub fn fetch_idle_peer(&mut self) -> Option<CachedPeer> {
        let idle_peer_id = self
            .peers
            .iter()
            .find(|(_, peer_info)| matches!(peer_info.peer_status, PeerStatus::Idle))
            .map(|(peer_id, _)| *peer_id)?;
        self.reserve(&idle_peer_id)
    }

    pub fn fetch_idle_peer_from(&mut self, eligible: &[PeerId]) -> Option<CachedPeer> {
        for peer_id in eligible {
            if let Some(peer) = self.reserve(peer_id) {
                return Some(peer);
            }
        }
        None
    }

    pub fn fetch_idle_peer_from_excluding(
        &mut self,
        eligible: &[PeerId],
        excluded: &HashSet<PeerId>,
    ) -> Option<CachedPeer> {
        for peer_id in eligible {
            if excluded.contains(peer_id) {
                continue;
            }
            if let Some(peer) = self.reserve(peer_id) {
                return Some(peer);
            }
        }
        None
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

    pub fn record_processed_blocks(&mut self, peer_id: &PeerId, count: u64) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.processed_blocks += count;
        }
    }

    pub fn best_finalized(&self, our_finalized_epoch: u64) -> TargetSelection {
        let mut votes: HashMap<u64, usize> = HashMap::new();
        let mut candidates: Vec<(PeerId, u64, u64)> = Vec::new();

        for (peer_id, peer_info) in &self.peers {
            let Some(status) = &peer_info.peer.status else {
                continue;
            };
            if status.finalized_epoch < our_finalized_epoch {
                continue;
            }
            *votes.entry(status.finalized_epoch).or_insert(0) += 1;
            candidates.push((*peer_id, status.finalized_epoch, status.head_slot));
        }

        let Some(winner_epoch) = votes
            .iter()
            .max_by(|(epoch_a, votes_a), (epoch_b, votes_b)| {
                votes_a.cmp(votes_b).then(epoch_a.cmp(epoch_b))
            })
            .map(|(&epoch, _)| epoch)
        else {
            return TargetSelection::NoQuorum;
        };

        let mut eligible: Vec<(PeerId, u64, u64)> = candidates
            .into_iter()
            .filter(|(_, epoch, _)| *epoch >= winner_epoch)
            .collect();
        eligible.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)));

        TargetSelection::Ready {
            target_slot: winner_epoch * SLOTS_PER_EPOCH,
            eligible_peers: eligible.into_iter().map(|(id, ..)| id).collect(),
        }
    }

    pub fn best_non_finalized(&self, min_peers: usize, our_head_epoch: u64) -> TargetSelection {
        let our_head_slot = our_head_epoch * SLOTS_PER_EPOCH;
        let mut epoch_votes: HashMap<u64, usize> = HashMap::new();
        let mut candidates: Vec<(PeerId, u64, u64)> = Vec::new();

        for (peer_id, peer_info) in &self.peers {
            let Some(status) = &peer_info.peer.status else {
                continue;
            };
            if status.head_slot <= our_head_slot {
                continue;
            }
            let epoch = status.head_slot / SLOTS_PER_EPOCH;
            *epoch_votes.entry(epoch).or_insert(0) += 1;
            candidates.push((*peer_id, epoch, status.head_slot));
        }

        let Some(target_epoch) = epoch_votes
            .iter()
            .filter(|&(_, &votes)| votes >= min_peers)
            .map(|(&epoch, _)| epoch)
            .max()
        else {
            return TargetSelection::NoQuorum;
        };

        let eligible: Vec<(PeerId, u64)> = candidates
            .into_iter()
            .filter(|(_, epoch, _)| *epoch >= target_epoch)
            .map(|(id, _, head_slot)| (id, head_slot))
            .collect();

        let target_slot = eligible
            .iter()
            .filter(|(_, head_slot)| head_slot / SLOTS_PER_EPOCH == target_epoch)
            .map(|(_, head_slot)| *head_slot)
            .max()
            .unwrap_or(target_epoch * SLOTS_PER_EPOCH);

        let mut eligible = eligible;
        eligible.sort_by_key(|&(_, head_slot)| std::cmp::Reverse(head_slot));

        TargetSelection::Ready {
            target_slot,
            eligible_peers: eligible.into_iter().map(|(id, _)| id).collect(),
        }
    }

    pub fn status_of(&self, peer_id: &PeerId) -> Option<Status> {
        self.peers
            .get(peer_id)
            .and_then(|info| info.peer.status.clone())
    }

    pub fn exact_finalized_epoch_peers(&self, epoch: u64) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                info.peer
                    .status
                    .as_ref()
                    .is_some_and(|status| status.finalized_epoch == epoch)
            })
            .map(|(peer_id, _)| *peer_id)
            .collect()
    }

    pub fn peers_satisfying(&self, qualification: TargetQualification) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                let Some(status) = &info.peer.status else {
                    return false;
                };
                match qualification {
                    TargetQualification::FinalizedEpoch(epoch) => status.finalized_epoch >= epoch,
                    TargetQualification::HeadEpoch(epoch) => {
                        status.head_slot / SLOTS_PER_EPOCH >= epoch
                    }
                }
            })
            .map(|(peer_id, _)| *peer_id)
            .collect()
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
                processed_blocks: 0,
                sync_requests_started: 0,
            },
        );
    }

    #[test]
    fn best_finalized_excludes_peers_behind_our_epoch() {
        let mut peer_manager = PeerManager::new(test_network_state());
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                finalized_epoch: 5,
                ..Default::default()
            }),
        );

        assert_eq!(
            peer_manager.best_finalized(10),
            TargetSelection::NoQuorum,
            "the only peer is behind our own finalized epoch, so there's no target to chase"
        );
    }

    #[test]
    fn best_finalized_is_plurality_not_majority_with_tie_break_by_higher_epoch() {
        let mut peer_manager = PeerManager::new(test_network_state());
        for _ in 0..2 {
            insert_idle(
                &mut peer_manager,
                test_peer(Status {
                    finalized_epoch: 10,
                    ..Default::default()
                }),
            );
        }
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                finalized_epoch: 12,
                ..Default::default()
            }),
        );

        let TargetSelection::Ready {
            target_slot,
            eligible_peers,
        } = peer_manager.best_finalized(0)
        else {
            panic!("expected a target");
        };
        assert_eq!(target_slot, 10 * SLOTS_PER_EPOCH);
        assert_eq!(eligible_peers.len(), 3);
    }

    #[test]
    fn best_non_finalized_uses_a_threshold_not_a_plurality_vote() {
        let mut peer_manager = PeerManager::new(test_network_state());
        for _ in 0..3 {
            insert_idle(
                &mut peer_manager,
                test_peer(Status {
                    head_slot: 20 * SLOTS_PER_EPOCH,
                    ..Default::default()
                }),
            );
        }
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                head_slot: 21 * SLOTS_PER_EPOCH,
                ..Default::default()
            }),
        );

        let TargetSelection::Ready { target_slot, .. } = peer_manager.best_non_finalized(1, 0)
        else {
            panic!("expected a target");
        };
        assert_eq!(target_slot, 21 * SLOTS_PER_EPOCH);
    }

    #[test]
    fn best_non_finalized_returns_no_quorum_below_min_peers_even_with_peers_ahead() {
        let mut peer_manager = PeerManager::new(test_network_state());
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                head_slot: 20 * SLOTS_PER_EPOCH,
                ..Default::default()
            }),
        );

        assert_eq!(
            peer_manager.best_non_finalized(3, 0),
            TargetSelection::NoQuorum,
            "one peer is ahead of us, but not enough to clear min_peers=3"
        );
    }

    #[test]
    fn best_non_finalized_refines_target_to_highest_actual_head_slot_in_winning_epoch() {
        let mut peer_manager = PeerManager::new(test_network_state());
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                head_slot: 20 * SLOTS_PER_EPOCH + 3,
                ..Default::default()
            }),
        );
        insert_idle(
            &mut peer_manager,
            test_peer(Status {
                head_slot: 20 * SLOTS_PER_EPOCH + 9,
                ..Default::default()
            }),
        );

        let TargetSelection::Ready { target_slot, .. } = peer_manager.best_non_finalized(1, 0)
        else {
            panic!("expected a target");
        };
        assert_eq!(target_slot, 20 * SLOTS_PER_EPOCH + 9);
    }

    #[test]
    fn fetch_idle_peer_from_returns_first_idle_in_given_order() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let first = test_peer(Status::default());
        let second = test_peer(Status::default());
        let first_id = first.peer_id;
        let second_id = second.peer_id;
        insert_idle(&mut peer_manager, first);
        insert_idle(&mut peer_manager, second);

        let peer = peer_manager
            .fetch_idle_peer_from(&[second_id, first_id])
            .expect("a peer should be found");
        assert_eq!(peer.peer_id, second_id);

        assert!(
            peer_manager
                .fetch_idle_peer_from(&[PeerId::random()])
                .is_none()
        );
    }

    #[test]
    fn fetch_idle_peer_from_excluding_skips_excluded_peers() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let peer = test_peer(Status::default());
        let peer_id = peer.peer_id;
        insert_idle(&mut peer_manager, peer);

        let mut excluded = HashSet::new();
        excluded.insert(peer_id);
        assert!(
            peer_manager
                .fetch_idle_peer_from_excluding(&[peer_id], &excluded)
                .is_none()
        );
    }

    #[test]
    fn peers_satisfying_distinguishes_finalized_and_head_qualification() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let high_head_low_finalized = test_peer(Status {
            head_slot: 1_000,
            finalized_epoch: 1,
            ..Default::default()
        });
        let id = high_head_low_finalized.peer_id;
        insert_idle(&mut peer_manager, high_head_low_finalized);

        assert!(
            peer_manager
                .peers_satisfying(TargetQualification::FinalizedEpoch(10))
                .is_empty()
        );
        assert_eq!(
            peer_manager.peers_satisfying(TargetQualification::HeadEpoch(0)),
            vec![id]
        );
    }

    #[test]
    fn bans_expire_after_ban_duration() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let peer = test_peer(Status::default());
        let peer_id = peer.peer_id;
        insert_idle(&mut peer_manager, peer);

        peer_manager.ban_peer(&peer_id, BanReason::ProtocolError("test".to_string()));
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
                processed_blocks: 0,
                sync_requests_started: 0,
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

    #[test]
    fn reserving_a_peer_credits_a_started_sync_request_every_time_including_after_reuse() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let peer = test_peer(Status::default());
        let peer_id = peer.peer_id;
        insert_idle(&mut peer_manager, peer);

        peer_manager
            .fetch_idle_peer_from(&[peer_id])
            .expect("peer is idle");
        assert_eq!(
            peer_manager
                .peers
                .get(&peer_id)
                .expect("peer exists")
                .sync_requests_started,
            1
        );

        assert!(peer_manager.fetch_idle_peer_from(&[peer_id]).is_none());
        assert_eq!(
            peer_manager
                .peers
                .get(&peer_id)
                .expect("peer exists")
                .sync_requests_started,
            1
        );

        peer_manager.mark_peer_as_idle(&peer_id);
        peer_manager
            .fetch_idle_peer_from_excluding(&[peer_id], &HashSet::new())
            .expect("peer is idle again");
        assert_eq!(
            peer_manager
                .peers
                .get(&peer_id)
                .expect("peer exists")
                .sync_requests_started,
            2
        );
    }

    #[test]
    fn record_processed_blocks_accumulates_and_ignores_unknown_peers() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let peer = test_peer(Status::default());
        let peer_id = peer.peer_id;
        insert_idle(&mut peer_manager, peer);

        peer_manager.record_processed_blocks(&peer_id, 3);
        peer_manager.record_processed_blocks(&peer_id, 2);
        assert_eq!(
            peer_manager
                .peers
                .get(&peer_id)
                .expect("peer exists")
                .processed_blocks,
            5
        );

        peer_manager.record_processed_blocks(&PeerId::random(), 1);
    }

    #[test]
    fn peers_satisfying_head_epoch_includes_a_peer_below_the_refined_max_slot() {
        let mut peer_manager = PeerManager::new(test_network_state());
        let below_refined_max = test_peer(Status {
            head_slot: 20 * SLOTS_PER_EPOCH + 3,
            ..Default::default()
        });
        let id = below_refined_max.peer_id;
        insert_idle(&mut peer_manager, below_refined_max);

        assert_eq!(
            peer_manager.peers_satisfying(TargetQualification::HeadEpoch(20)),
            vec![id]
        );
    }
}

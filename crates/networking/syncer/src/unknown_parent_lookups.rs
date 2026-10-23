use std::{
    collections::{HashMap, HashSet, VecDeque},
    time::{Duration, Instant},
};

use alloy_primitives::B256;

/// Lookups retain untrusted blocks. At roughly 10 MiB per maximum-size block, 200 lookups bound
/// retained block data at approximately 2 GiB, matching Lighthouse.
pub const MAX_LOOKUPS: usize = 200;

/// Stop walking unknown ancestors after the same 32-block tolerance used by Lighthouse lookup
/// sync. Longer chains belong in range sync rather than single-block lookup sync.
pub const PARENT_DEPTH_TOLERANCE: usize = 32;

/// Lighthouse retries downloading a single lookup component at most four times.
pub const SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS: u8 = 4;

/// An event-driven lookup that lives for 15 seconds per tolerated ancestor is considered stuck.
/// This is an absolute lifetime: duplicate gossip cannot keep untrusted data alive indefinitely.
pub const LOOKUP_MAX_DURATION_STUCK: Duration =
    Duration::from_secs(15 * PARENT_DEPTH_TOLERANCE as u64);

/// Lighthouse caches failed lookup-chain roots for 60 seconds so repeated gossip cannot recreate
/// an exhausted attacker-controlled chain on every message.
pub const FAILED_CHAIN_CACHE_DURATION: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownParentLookupConfig {
    pub max_lookups: usize,
    pub max_parent_depth: usize,
    pub max_attempts: u8,
    pub stuck_timeout: Duration,
    pub failed_chain_cache_duration: Duration,
}

impl Default for UnknownParentLookupConfig {
    fn default() -> Self {
        Self {
            max_lookups: MAX_LOOKUPS,
            max_parent_depth: PARENT_DEPTH_TOLERANCE,
            max_attempts: SINGLE_BLOCK_LOOKUP_MAX_ATTEMPTS,
            stuck_timeout: LOOKUP_MAX_DURATION_STUCK,
            failed_chain_cache_duration: FAILED_CHAIN_CACHE_DURATION,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LookupActionId(u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownBlockMeta {
    pub block_root: B256,
    pub parent_root: B256,
    pub slot: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadOrigin {
    Gossip,
    Rpc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentStatus {
    Imported,
    PendingAvailability,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    Capacity,
    ParentDepthExceeded,
    Cycle,
    RecentlyFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Duplicate,
    Rejected(InsertError),
}

#[derive(Debug)]
pub enum UnknownParentAction<BlockPayload, Peer> {
    RequestBlock {
        action_id: LookupActionId,
        block_root: B256,
        peer: Peer,
    },
    ProcessBlock {
        action_id: LookupActionId,
        meta: UnknownBlockMeta,
        origin: PayloadOrigin,
        payload: BlockPayload,
    },
}

impl<BlockPayload, Peer> UnknownParentAction<BlockPayload, Peer> {
    pub fn action_id(&self) -> LookupActionId {
        match self {
            Self::RequestBlock { action_id, .. } | Self::ProcessBlock { action_id, .. } => {
                *action_id
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LookupState {
    AwaitingDownload,
    Downloading(LookupActionId),
    AwaitingParent,
    ReadyToProcess,
    Processing(LookupActionId),
    PendingAvailability,
}

#[derive(Debug)]
struct StoredPayload<BlockPayload> {
    origin: PayloadOrigin,
    payload: BlockPayload,
}

#[derive(Debug)]
struct LookupEntry<BlockPayload, Peer> {
    meta: Option<UnknownBlockMeta>,
    payload: Option<StoredPayload<BlockPayload>>,
    peers: Vec<Peer>,
    next_peer: usize,
    /// Peers already asked for this block, so a replacement can be one that was not.
    asked_peers: Vec<Peer>,
    awaiting_parent: Option<B256>,
    state: LookupState,
    failed_downloads: u8,
    failed_processing: u8,
    created_at: Instant,
    /// Looked up for itself rather than as a child's parent, so it is kept without children.
    requested: bool,
}

impl<BlockPayload, Peer: Eq> LookupEntry<BlockPayload, Peer> {
    fn add_peer(&mut self, peer: Peer, max_peers: usize) -> bool {
        if self.peers.len() < max_peers && !self.peers.contains(&peer) {
            self.peers.push(peer);
            return true;
        }
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAction {
    RequestBlock(B256),
    ProcessBlock(B256),
}

/// A bounded state machine for raw blocks whose parents are genuinely unknown.
///
/// Payload validation, networking and peer scoring deliberately remain in the caller. In
/// particular, this coordinator never accepts the gossip-validated payload type used by the
/// data-availability-pending coordinator.
pub struct UnknownParentLookupCoordinator<BlockPayload, Peer> {
    config: UnknownParentLookupConfig,
    entries: HashMap<B256, LookupEntry<BlockPayload, Peer>>,
    children_by_parent: HashMap<B256, VecDeque<B256>>,
    pending_actions: VecDeque<PendingAction>,
    failed_roots: HashMap<B256, Instant>,
    next_action_id: u64,
}

impl<BlockPayload, Peer> Default for UnknownParentLookupCoordinator<BlockPayload, Peer>
where
    Peer: Clone + Eq,
{
    fn default() -> Self {
        Self::new(UnknownParentLookupConfig::default())
    }
}

impl<BlockPayload, Peer> UnknownParentLookupCoordinator<BlockPayload, Peer>
where
    Peer: Clone + Eq,
{
    pub fn new(config: UnknownParentLookupConfig) -> Self {
        Self {
            config,
            entries: HashMap::new(),
            children_by_parent: HashMap::new(),
            pending_actions: VecDeque::new(),
            failed_roots: HashMap::new(),
            next_action_id: 0,
        }
    }

    /// Retains an unvalidated gossip block and starts (or joins) its parent lookup.
    pub fn insert_gossip_block(
        &mut self,
        meta: UnknownBlockMeta,
        payload: BlockPayload,
        peer: Peer,
    ) -> InsertOutcome {
        self.prune_failed_roots();
        if self.failed_roots.contains_key(&meta.block_root)
            || self.failed_roots.contains_key(&meta.parent_root)
        {
            return InsertOutcome::Rejected(InsertError::RecentlyFailed);
        }
        if self
            .entries
            .get(&meta.block_root)
            .is_some_and(|entry| entry.meta.is_some())
        {
            self.add_peer_to_chain(meta.block_root, peer);
            return InsertOutcome::Duplicate;
        }

        let new_entries = usize::from(!self.entries.contains_key(&meta.block_root))
            + usize::from(!self.entries.contains_key(&meta.parent_root));
        if self.entries.len().saturating_add(new_entries) > self.config.max_lookups {
            return InsertOutcome::Rejected(InsertError::Capacity);
        }
        if let Err(err) = self.ensure_link_allowed(meta.block_root, meta.parent_root) {
            self.mark_failed_root(meta.block_root, Instant::now());
            return InsertOutcome::Rejected(err);
        }

        let now = Instant::now();
        let max_peers = usize::from(self.config.max_attempts);
        let entry = self
            .entries
            .entry(meta.block_root)
            .or_insert_with(|| LookupEntry {
                meta: None,
                payload: None,
                peers: Vec::new(),
                next_peer: 0,
                asked_peers: Vec::new(),
                awaiting_parent: None,
                state: LookupState::AwaitingParent,
                failed_downloads: 0,
                failed_processing: 0,
                created_at: now,
                requested: false,
            });
        entry.add_peer(peer.clone(), max_peers);
        entry.meta = Some(meta);
        entry.payload = Some(StoredPayload {
            origin: PayloadOrigin::Gossip,
            payload,
        });
        entry.awaiting_parent = Some(meta.parent_root);
        entry.state = LookupState::AwaitingParent;

        self.insert_child(meta.parent_root, meta.block_root);
        self.ensure_parent_lookup(meta.parent_root, peer, now);
        InsertOutcome::Inserted
    }

    /// Downloads `block_root`, a block that signed gossip refers to but that has not arrived.
    pub fn insert_block_root(&mut self, block_root: B256, peer: Peer) -> InsertOutcome {
        self.prune_failed_roots();
        if self.failed_roots.contains_key(&block_root) {
            return InsertOutcome::Rejected(InsertError::RecentlyFailed);
        }
        if self.entries.contains_key(&block_root) {
            self.add_peer_to_chain(block_root, peer);
            return InsertOutcome::Duplicate;
        }
        if self.entries.len() >= self.config.max_lookups {
            return InsertOutcome::Rejected(InsertError::Capacity);
        }
        self.ensure_parent_lookup(block_root, peer, Instant::now());
        if let Some(entry) = self.entries.get_mut(&block_root) {
            entry.requested = true;
        }
        InsertOutcome::Inserted
    }

    /// Applies a verified blocks-by-root response. `parent_status` is determined by the caller
    /// under the chain store lock before this method is called.
    pub fn download_succeeded(
        &mut self,
        action_id: LookupActionId,
        meta: UnknownBlockMeta,
        payload: BlockPayload,
        parent_status: ParentStatus,
    ) -> Result<bool, InsertError> {
        let root = meta.block_root;
        if !self.action_matches(root, LookupState::Downloading(action_id)) {
            return Ok(false);
        }
        self.prune_failed_roots();
        if parent_status == ParentStatus::Unknown
            && self.failed_roots.contains_key(&meta.parent_root)
        {
            // Only the ancestor failed. Marking this chain too would refresh the mark with every
            // new gossip block, so lookups would stay blocked after the ancestor's mark expires.
            self.discard_subtree(root);
            return Err(InsertError::RecentlyFailed);
        }

        if parent_status != ParentStatus::Imported
            && let Err(err) = self.ensure_link_allowed(root, meta.parent_root)
        {
            self.drop_subtree(root);
            return Err(err);
        }

        let needs_parent_entry =
            parent_status == ParentStatus::Unknown && !self.entries.contains_key(&meta.parent_root);
        if needs_parent_entry && self.entries.len() >= self.config.max_lookups {
            self.drop_subtree(root);
            return Err(InsertError::Capacity);
        }

        let inherited_peers = self
            .entries
            .get(&root)
            .map(|entry| entry.peers.clone())
            .unwrap_or_default();
        let entry = self
            .entries
            .get_mut(&root)
            .expect("matched lookup must exist");
        entry.meta = Some(meta);
        entry.payload = Some(StoredPayload {
            origin: PayloadOrigin::Rpc,
            payload,
        });
        match parent_status {
            ParentStatus::Imported => {
                entry.awaiting_parent = None;
                entry.state = LookupState::ReadyToProcess;
                self.pending_actions
                    .push_back(PendingAction::ProcessBlock(root));
            }
            ParentStatus::PendingAvailability | ParentStatus::Unknown => {
                entry.awaiting_parent = Some(meta.parent_root);
                entry.state = LookupState::AwaitingParent;
                self.insert_child(meta.parent_root, root);

                if parent_status == ParentStatus::Unknown {
                    let now = Instant::now();
                    for peer in inherited_peers {
                        self.ensure_parent_lookup(meta.parent_root, peer, now);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Stops asking `peer` for `block_root` and asks `replacement` instead. A block's gossip
    /// sources may be nodes that relay gossip but do not serve blocks by root; without other peers
    /// its lookup would fail on every attempt.
    pub fn replace_peer(&mut self, block_root: B256, peer: &Peer, replacement: Option<Peer>) {
        let max_peers = usize::from(self.config.max_attempts);
        if let Some(entry) = self.entries.get_mut(&block_root) {
            // Keep the only peer rather than leave the lookup with nobody to ask.
            if replacement.is_none() && entry.peers.len() <= 1 {
                return;
            }
            if let Some(position) = entry.peers.iter().position(|known| known == peer) {
                // `next_peer` indexes the peer asked next. Removing a peer before it shifts that
                // peer down one place, so the cursor moves with it and no peer is skipped.
                let cursor = entry.next_peer % entry.peers.len();
                entry.peers.remove(position);
                entry.next_peer = if position < cursor {
                    cursor - 1
                } else {
                    cursor
                };
            }
            if let Some(replacement) = replacement {
                entry.add_peer(replacement, max_peers);
            }
        }
    }

    /// The peers the lookup of `block_root` has asked for it so far.
    pub fn asked_peers(&self, block_root: B256) -> &[Peer] {
        self.entries
            .get(&block_root)
            .map_or(&[], |entry| entry.asked_peers.as_slice())
    }

    pub fn download_failed(&mut self, action_id: LookupActionId, block_root: B256) -> bool {
        if !self.action_matches(block_root, LookupState::Downloading(action_id)) {
            return false;
        }
        let entry = self
            .entries
            .get_mut(&block_root)
            .expect("matched lookup must exist");
        entry.failed_downloads = entry.failed_downloads.saturating_add(1);
        let requested_alone = entry.requested && !self.children_by_parent.contains_key(&block_root);
        if entry.failed_downloads >= self.config.max_attempts && requested_alone {
            // Peers may not have the block yet. Marking it failed would refuse its children's
            // lookups for a minute.
            self.discard_subtree(block_root);
        } else if entry.failed_downloads >= self.config.max_attempts {
            self.drop_subtree(block_root);
        } else {
            entry.state = LookupState::AwaitingDownload;
            self.pending_actions
                .push_back(PendingAction::RequestBlock(block_root));
        }
        true
    }

    pub fn process_failed(
        &mut self,
        action_id: LookupActionId,
        root: B256,
        retry_by_download: bool,
    ) -> bool {
        if !self.action_matches(root, LookupState::Processing(action_id)) {
            return false;
        }
        let entry = self
            .entries
            .get_mut(&root)
            .expect("matched lookup must exist");
        entry.failed_processing = entry.failed_processing.saturating_add(1);
        if !retry_by_download || entry.failed_processing >= self.config.max_attempts {
            self.drop_subtree(root);
        } else {
            // Processing is not transactional. Re-download instead of reusing the consumed block.
            entry.state = LookupState::AwaitingDownload;
            self.pending_actions
                .push_back(PendingAction::RequestBlock(root));
        }
        true
    }

    pub fn process_pending_availability(
        &mut self,
        action_id: LookupActionId,
        block_root: B256,
    ) -> bool {
        if !self.action_matches(block_root, LookupState::Processing(action_id)) {
            return false;
        }
        self.park_pending_availability(block_root);
        true
    }

    pub fn process_imported(&mut self, action_id: LookupActionId, block_root: B256) -> bool {
        if !self.action_matches(block_root, LookupState::Processing(action_id)) {
            return false;
        }
        self.block_imported(block_root);
        true
    }

    /// Records an external DA-pending event without releasing raw children.
    pub fn block_pending_availability(&mut self, block_root: B256) {
        if self.entries.contains_key(&block_root) {
            self.park_pending_availability(block_root);
        }
    }

    /// Drops the raw copy when another coordinator has taken ownership, while keeping this root
    /// as a dependency marker for any unknown descendants until an import event arrives.
    pub fn block_deferred_elsewhere(&mut self, block_root: B256) {
        if self.entries.contains_key(&block_root) {
            self.park_pending_availability(block_root);
        }
    }

    /// Drops a dependency subtree when the coordinator that owns its block reports import failure.
    pub fn block_failed_elsewhere(&mut self, block_root: B256) {
        if self.entries.contains_key(&block_root)
            || self.children_by_parent.contains_key(&block_root)
        {
            self.drop_subtree(block_root);
        }
    }

    /// Records an external import and releases only its immediate children for processing.
    pub fn block_imported(&mut self, block_root: B256) {
        self.remove_entry(block_root);
        let children = self
            .children_by_parent
            .remove(&block_root)
            .unwrap_or_default();
        for child_root in children {
            let Some(child) = self.entries.get_mut(&child_root) else {
                continue;
            };
            if child.awaiting_parent == Some(block_root)
                && child.state == LookupState::AwaitingParent
            {
                child.awaiting_parent = None;
                child.state = LookupState::ReadyToProcess;
                self.pending_actions
                    .push_back(PendingAction::ProcessBlock(child_root));
            }
        }
        self.remove_orphan_placeholders();
    }

    pub fn next_action(&mut self) -> Option<UnknownParentAction<BlockPayload, Peer>> {
        let actions_to_check = self.pending_actions.len();
        for _ in 0..actions_to_check {
            let pending = self.pending_actions.pop_front()?;
            if matches!(pending, PendingAction::ProcessBlock(_)) && self.has_in_flight_process() {
                self.pending_actions.push_back(pending);
                continue;
            }
            let action_id = self.next_action_id();
            match pending {
                PendingAction::RequestBlock(block_root) => {
                    let Some(entry) = self.entries.get_mut(&block_root) else {
                        continue;
                    };
                    if entry.state != LookupState::AwaitingDownload || entry.peers.is_empty() {
                        continue;
                    }
                    let peer = entry.peers[entry.next_peer % entry.peers.len()].clone();
                    entry.next_peer = entry.next_peer.wrapping_add(1);
                    if !entry.asked_peers.contains(&peer) {
                        entry.asked_peers.push(peer.clone());
                    }
                    entry.state = LookupState::Downloading(action_id);
                    return Some(UnknownParentAction::RequestBlock {
                        action_id,
                        block_root,
                        peer,
                    });
                }
                PendingAction::ProcessBlock(block_root) => {
                    let Some(entry) = self.entries.get_mut(&block_root) else {
                        continue;
                    };
                    if entry.state != LookupState::ReadyToProcess {
                        continue;
                    }
                    let meta = entry.meta.expect("process-ready lookup must have metadata");
                    let stored = entry
                        .payload
                        .take()
                        .expect("process-ready lookup must retain its payload");
                    entry.state = LookupState::Processing(action_id);
                    return Some(UnknownParentAction::ProcessBlock {
                        action_id,
                        meta,
                        origin: stored.origin,
                        payload: stored.payload,
                    });
                }
            }
        }
        None
    }

    /// Block downloads may run concurrently, but block replays are serialized so ready siblings
    /// cannot race the seen cache.
    pub fn has_dispatchable_action(&self) -> bool {
        !self.pending_actions.is_empty()
            && (!self.has_in_flight_process()
                || self
                    .pending_actions
                    .iter()
                    .any(|action| matches!(action, PendingAction::RequestBlock(_))))
    }

    /// Drops entries whose absolute lifetime exceeds the stuck-lookup bound. An expired ancestor
    /// drops its dependent descendants, while unrelated trees remain untouched.
    pub fn prune(&mut self) -> usize {
        self.prune_failed_roots();
        let now = Instant::now();
        let expired = self
            .entries
            .iter()
            .filter_map(|(root, entry)| {
                (now.saturating_duration_since(entry.created_at) >= self.config.stuck_timeout)
                    .then_some(*root)
            })
            .collect::<Vec<_>>();
        let before = self.entries.len();
        for root in expired {
            if self.entries.contains_key(&root) {
                self.drop_subtree(root);
            }
        }
        before - self.entries.len()
    }

    /// Drops known blocks at or behind finality together with only their dependent descendants.
    pub fn prune_finalized(&mut self, finalized_slot: u64) -> usize {
        let expired = self
            .entries
            .iter()
            .filter_map(|(root, entry)| {
                entry
                    .meta
                    .is_some_and(|meta| meta.slot <= finalized_slot)
                    .then_some(*root)
            })
            .collect::<Vec<_>>();
        let before = self.entries.len();
        for root in expired {
            if self.entries.contains_key(&root) {
                self.drop_subtree(root);
            }
        }
        before - self.entries.len()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, block_root: &B256) -> bool {
        self.entries.contains_key(block_root)
    }

    pub fn children(&self, parent_root: &B256) -> HashSet<B256> {
        self.children_by_parent
            .get(parent_root)
            .map(|children| children.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn pending_action_count(&self) -> usize {
        self.pending_actions.len()
    }

    /// Roots that may need reconciliation after a lagged import notification.
    pub fn reconciliation_roots(&self) -> Vec<B256> {
        let mut roots = self.entries.keys().copied().collect::<Vec<_>>();
        roots.extend(self.children_by_parent.keys().copied());
        roots.sort_unstable();
        roots.dedup();
        roots
    }

    fn ensure_parent_lookup(&mut self, parent_root: B256, peer: Peer, now: Instant) {
        let max_peers = usize::from(self.config.max_attempts);
        let request_queued = self
            .pending_actions
            .contains(&PendingAction::RequestBlock(parent_root));
        match self.entries.get_mut(&parent_root) {
            Some(parent) => {
                let should_queue = parent.add_peer(peer, max_peers)
                    && parent.state == LookupState::AwaitingDownload
                    && !request_queued;
                if should_queue {
                    self.pending_actions
                        .push_back(PendingAction::RequestBlock(parent_root));
                }
            }
            None => {
                self.entries.insert(
                    parent_root,
                    LookupEntry {
                        meta: None,
                        payload: None,
                        peers: vec![peer],
                        next_peer: 0,
                        asked_peers: Vec::new(),
                        awaiting_parent: None,
                        state: LookupState::AwaitingDownload,
                        failed_downloads: 0,
                        failed_processing: 0,
                        created_at: now,
                        requested: false,
                    },
                );
                self.pending_actions
                    .push_back(PendingAction::RequestBlock(parent_root));
            }
        }
    }

    fn add_peer_to_chain(&mut self, start: B256, peer: Peer) {
        let mut next = Some(start);
        let mut visited = HashSet::new();
        let max_peers = usize::from(self.config.max_attempts);
        while let Some(root) = next
            && visited.insert(root)
        {
            let request_queued = self
                .pending_actions
                .contains(&PendingAction::RequestBlock(root));
            let Some(entry) = self.entries.get_mut(&root) else {
                break;
            };
            let should_queue = entry.add_peer(peer.clone(), max_peers)
                && entry.state == LookupState::AwaitingDownload
                && !request_queued;
            if should_queue {
                self.pending_actions
                    .push_back(PendingAction::RequestBlock(root));
            }
            next = entry.awaiting_parent;
        }
    }

    fn ensure_link_allowed(&self, child_root: B256, parent_root: B256) -> Result<(), InsertError> {
        if child_root == parent_root {
            return Err(InsertError::Cycle);
        }

        let mut ancestors = 0usize;
        let mut cursor = parent_root;
        let mut visited = HashSet::new();
        loop {
            if !visited.insert(cursor) {
                return Err(InsertError::Cycle);
            }
            if cursor == child_root {
                return Err(InsertError::Cycle);
            }
            ancestors = ancestors.saturating_add(1);
            let Some(parent) = self
                .entries
                .get(&cursor)
                .and_then(|entry| entry.awaiting_parent)
            else {
                break;
            };
            cursor = parent;
        }

        let depth = self
            .descendant_height(child_root, &mut HashSet::new())
            .saturating_sub(1)
            .saturating_add(ancestors);
        if depth > self.config.max_parent_depth {
            Err(InsertError::ParentDepthExceeded)
        } else {
            Ok(())
        }
    }

    fn descendant_height(&self, root: B256, visited: &mut HashSet<B256>) -> usize {
        if !visited.insert(root) {
            return self.config.max_parent_depth.saturating_add(1);
        }
        let child_height = self
            .children_by_parent
            .get(&root)
            .map(|children| {
                children
                    .iter()
                    .map(|child| self.descendant_height(*child, visited))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0);
        visited.remove(&root);
        1usize.saturating_add(child_height)
    }

    fn action_matches(&self, root: B256, expected: LookupState) -> bool {
        self.entries
            .get(&root)
            .is_some_and(|entry| entry.state == expected)
    }

    fn has_in_flight_process(&self) -> bool {
        self.entries
            .values()
            .any(|entry| matches!(entry.state, LookupState::Processing(_)))
    }

    fn insert_child(&mut self, parent_root: B256, child_root: B256) {
        let children = self.children_by_parent.entry(parent_root).or_default();
        if !children.contains(&child_root) {
            children.push_back(child_root);
        }
    }

    fn remove_child(&mut self, parent_root: B256, child_root: B256) {
        if let Some(children) = self.children_by_parent.get_mut(&parent_root) {
            children.retain(|child| *child != child_root);
            if children.is_empty() {
                self.children_by_parent.remove(&parent_root);
            }
        }
    }

    fn park_pending_availability(&mut self, root: B256) {
        let parent = self
            .entries
            .get(&root)
            .and_then(|entry| entry.awaiting_parent);
        if let Some(parent) = parent {
            self.remove_child(parent, root);
        }
        if let Some(entry) = self.entries.get_mut(&root) {
            entry.payload = None;
            entry.awaiting_parent = None;
            entry.state = LookupState::PendingAvailability;
        }
        self.remove_queued_actions(root);
        self.remove_orphan_placeholders();
    }

    fn drop_subtree(&mut self, root: B256) {
        let now = Instant::now();
        for root in self.subtree(root) {
            self.mark_failed_root(root, now);
        }
        self.discard_subtree(root);
    }

    /// Removes `root` and its descendants without recording them as failed.
    fn discard_subtree(&mut self, root: B256) {
        for root in self.subtree(root) {
            self.remove_entry(root);
            self.children_by_parent.remove(&root);
        }
        self.remove_orphan_placeholders();
    }

    fn subtree(&self, root: B256) -> HashSet<B256> {
        let mut stack = vec![root];
        let mut roots = HashSet::new();
        while let Some(next) = stack.pop() {
            if !roots.insert(next) {
                continue;
            }
            if let Some(children) = self.children_by_parent.get(&next) {
                stack.extend(children.iter().copied());
            }
        }
        roots
    }

    fn remove_orphan_placeholders(&mut self) {
        loop {
            let orphan = self.entries.iter().find_map(|(root, entry)| {
                (entry.meta.is_none()
                    && !entry.requested
                    && self
                        .children_by_parent
                        .get(root)
                        .is_none_or(|children| children.is_empty()))
                .then_some(*root)
            });
            let Some(root) = orphan else {
                break;
            };
            self.remove_entry(root);
        }
    }

    fn remove_entry(&mut self, root: B256) {
        let Some(entry) = self.entries.remove(&root) else {
            self.remove_queued_actions(root);
            return;
        };
        if let Some(parent) = entry.awaiting_parent {
            self.remove_child(parent, root);
        }
        self.remove_queued_actions(root);
    }

    fn remove_queued_actions(&mut self, root: B256) {
        self.pending_actions.retain(|action| match action {
            PendingAction::RequestBlock(action_root) | PendingAction::ProcessBlock(action_root) => {
                *action_root != root
            }
        });
    }

    fn next_action_id(&mut self) -> LookupActionId {
        let id = LookupActionId(self.next_action_id);
        self.next_action_id = self.next_action_id.wrapping_add(1);
        id
    }

    fn prune_failed_roots(&mut self) {
        let now = Instant::now();
        self.failed_roots.retain(|_, failed_at| {
            now.saturating_duration_since(*failed_at) < self.config.failed_chain_cache_duration
        });
    }

    fn mark_failed_root(&mut self, root: B256, now: Instant) {
        if self.config.max_lookups == 0 {
            return;
        }
        if !self.failed_roots.contains_key(&root)
            && self.failed_roots.len() >= self.config.max_lookups
            && let Some(oldest) = self
                .failed_roots
                .iter()
                .min_by_key(|(_, failed_at)| **failed_at)
                .map(|(root, _)| *root)
        {
            self.failed_roots.remove(&oldest);
        }
        self.failed_roots.insert(root, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(n: u8) -> B256 {
        B256::repeat_byte(n)
    }

    fn meta(block: u8, parent: u8, slot: u64) -> UnknownBlockMeta {
        UnknownBlockMeta {
            block_root: root(block),
            parent_root: root(parent),
            slot,
        }
    }

    fn config() -> UnknownParentLookupConfig {
        UnknownParentLookupConfig {
            max_lookups: 200,
            max_parent_depth: 32,
            max_attempts: 4,
            stuck_timeout: LOOKUP_MAX_DURATION_STUCK,
            failed_chain_cache_duration: FAILED_CHAIN_CACHE_DURATION,
        }
    }

    fn request_action(
        coordinator: &mut UnknownParentLookupCoordinator<u8, u8>,
    ) -> (LookupActionId, B256, u8) {
        match coordinator.next_action().expect("request should be queued") {
            UnknownParentAction::RequestBlock {
                action_id,
                block_root,
                peer,
            } => (action_id, block_root, peer),
            UnknownParentAction::ProcessBlock { .. } => panic!("expected request action"),
        }
    }

    fn process_action(
        coordinator: &mut UnknownParentLookupCoordinator<u8, u8>,
    ) -> (LookupActionId, UnknownBlockMeta, PayloadOrigin, u8) {
        match coordinator.next_action().expect("process should be queued") {
            UnknownParentAction::ProcessBlock {
                action_id,
                meta,
                origin,
                payload,
            } => (action_id, meta, origin, payload),
            UnknownParentAction::RequestBlock { .. } => panic!("expected process action"),
        }
    }

    /// A chain dropped because an ancestor recently failed is not itself recorded as failed;
    /// otherwise every new gossip block refreshes the mark and lookups never resume.
    #[test]
    fn a_failed_ancestor_does_not_mark_its_descendants_as_failed() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.mark_failed_root(root(1), Instant::now());
        assert_eq!(
            coordinator.insert_gossip_block(meta(3, 2, 3), 30, 7),
            InsertOutcome::Inserted
        );
        let (action_id, requested, _) = request_action(&mut coordinator);
        assert_eq!(requested, root(2));

        assert_eq!(
            coordinator.download_succeeded(action_id, meta(2, 1, 2), 20, ParentStatus::Unknown),
            Err(InsertError::RecentlyFailed)
        );
        assert!(coordinator.is_empty());
        assert!(!coordinator.failed_roots.contains_key(&root(2)));
        assert!(!coordinator.failed_roots.contains_key(&root(3)));
        assert_eq!(
            coordinator.insert_gossip_block(meta(4, 3, 4), 40, 8),
            InsertOutcome::Inserted
        );
    }

    #[test]
    fn a_requested_root_is_downloaded_and_processed_without_children() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        assert_eq!(
            coordinator.insert_block_root(root(2), 7),
            InsertOutcome::Inserted
        );
        // Cleanup after another import must not drop it for having no children.
        coordinator.block_imported(root(5));
        assert!(coordinator.contains(&root(2)));

        let (action_id, requested, peer) = request_action(&mut coordinator);
        assert_eq!((requested, peer), (root(2), 7));
        assert_eq!(
            coordinator.download_succeeded(action_id, meta(2, 1, 2), 20, ParentStatus::Imported),
            Ok(true)
        );
        let (action_id, meta, origin, payload) = process_action(&mut coordinator);
        assert_eq!(
            (meta.block_root, origin, payload),
            (root(2), PayloadOrigin::Rpc, 20)
        );
        assert!(coordinator.process_imported(action_id, root(2)));
        assert!(!coordinator.contains(&root(2)));
    }

    #[test]
    fn a_requested_root_that_no_peer_serves_does_not_block_its_children() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_block_root(root(2), 7);
        for _ in 0..config().max_attempts {
            let (action_id, requested, _) = request_action(&mut coordinator);
            assert!(coordinator.download_failed(action_id, requested));
        }
        assert!(coordinator.is_empty());
        assert_eq!(
            coordinator.insert_gossip_block(meta(3, 2, 3), 30, 8),
            InsertOutcome::Inserted
        );
    }

    #[test]
    fn a_requested_root_that_is_already_looked_up_is_a_duplicate() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        assert_eq!(
            coordinator.insert_block_root(root(1), 8),
            InsertOutcome::Duplicate
        );
        assert_eq!(
            coordinator.insert_block_root(root(2), 8),
            InsertOutcome::Duplicate
        );
    }

    #[test]
    fn a_replaced_peer_is_not_asked_again() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        let (action_id, requested, peer) = request_action(&mut coordinator);
        assert_eq!((requested, peer), (root(1), 7));

        coordinator.replace_peer(root(1), &7, Some(9));
        assert!(coordinator.download_failed(action_id, root(1)));
        let (_, requested, peer) = request_action(&mut coordinator);
        assert_eq!((requested, peer), (root(1), 9));
    }

    #[test]
    fn replacing_a_peer_does_not_skip_the_next_one() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        for peer in [7, 8, 9, 10] {
            coordinator.insert_gossip_block(meta(2, 1, 2), 20, peer);
        }
        let (action_id, requested, peer) = request_action(&mut coordinator);
        assert_eq!((requested, peer), (root(1), 7));

        coordinator.replace_peer(root(1), &7, None);
        assert!(coordinator.download_failed(action_id, root(1)));
        let (action_id, _, peer) = request_action(&mut coordinator);
        assert_eq!(peer, 8);

        // Removing a peer after the cursor leaves it in place.
        coordinator.replace_peer(root(1), &10, None);
        assert!(coordinator.download_failed(action_id, root(1)));
        let (_, _, peer) = request_action(&mut coordinator);
        assert_eq!(peer, 9);
    }

    #[test]
    fn gossip_insert_deduplicates_roots_and_source_peers() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        assert_eq!(
            coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7),
            InsertOutcome::Inserted
        );
        assert_eq!(
            coordinator.insert_gossip_block(meta(2, 1, 2), 21, 7),
            InsertOutcome::Duplicate
        );
        for peer in 8..16 {
            assert_eq!(
                coordinator.insert_gossip_block(meta(2, 1, 2), 21, peer),
                InsertOutcome::Duplicate
            );
        }
        assert_eq!(coordinator.len(), 2);
        assert_eq!(coordinator.pending_action_count(), 1);
        assert_eq!(coordinator.entries[&root(1)].peers.len(), 4);
        assert_eq!(coordinator.entries[&root(2)].peers.len(), 4);
        assert_eq!(request_action(&mut coordinator).2, 7);
    }

    #[test]
    fn duplicate_gossip_does_not_replace_an_in_flight_process() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.block_imported(root(1));

        let (action_id, block, _, payload) = process_action(&mut coordinator);
        assert_eq!((block.block_root, payload), (root(2), 20));
        assert_eq!(
            coordinator.insert_gossip_block(meta(2, 1, 2), 21, 8),
            InsertOutcome::Duplicate
        );

        assert!(coordinator.process_imported(action_id, root(2)));
        assert!(coordinator.is_empty());
        assert!(coordinator.next_action().is_none());
    }

    #[test]
    fn imported_parent_releases_only_immediate_children() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(3, 2, 3), 30, 7);
        let (request_id, requested, _) = request_action(&mut coordinator);
        assert_eq!(requested, root(2));
        assert_eq!(
            coordinator.download_succeeded(request_id, meta(2, 1, 2), 20, ParentStatus::Unknown,),
            Ok(true)
        );
        let (ancestor_request, requested, _) = request_action(&mut coordinator);
        assert_eq!(requested, root(1));
        assert_eq!(
            coordinator.download_succeeded(
                ancestor_request,
                meta(1, 9, 1),
                10,
                ParentStatus::Imported,
            ),
            Ok(true)
        );

        let (process_1, block_1, _, payload_1) = process_action(&mut coordinator);
        assert_eq!((block_1.block_root, payload_1), (root(1), 10));
        assert!(coordinator.process_imported(process_1, root(1)));
        let (process_2, block_2, _, payload_2) = process_action(&mut coordinator);
        assert_eq!((block_2.block_root, payload_2), (root(2), 20));
        assert!(coordinator.process_imported(process_2, root(2)));
        let (_, block_3, origin_3, payload_3) = process_action(&mut coordinator);
        assert_eq!((block_3.block_root, payload_3), (root(3), 30));
        assert_eq!(origin_3, PayloadOrigin::Gossip);
    }

    #[test]
    fn pending_availability_parks_until_imported() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.block_pending_availability(root(1));
        assert!(coordinator.next_action().is_none());
        assert!(coordinator.contains(&root(2)));

        coordinator.block_imported(root(1));
        assert_eq!(process_action(&mut coordinator).1.block_root, root(2));
    }

    #[test]
    fn ready_gossip_siblings_are_processed_in_arrival_order() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.insert_gossip_block(meta(3, 1, 2), 30, 8);

        coordinator.block_imported(root(1));
        let (first_action, first_meta, _, _) = process_action(&mut coordinator);
        assert_eq!(first_meta.block_root, root(2));
        assert!(
            coordinator.next_action().is_none(),
            "the later sibling must wait until the first arrival finishes validation"
        );
        assert!(!coordinator.has_dispatchable_action());

        assert!(coordinator.process_imported(first_action, root(2)));
        assert_eq!(process_action(&mut coordinator).1.block_root, root(3));
    }

    #[test]
    fn another_coordinator_can_take_ownership_without_releasing_descendants() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.insert_gossip_block(meta(3, 2, 3), 30, 8);

        coordinator.block_deferred_elsewhere(root(2));
        assert!(!coordinator.contains(&root(1)));
        assert!(coordinator.contains(&root(2)));
        assert!(coordinator.contains(&root(3)));
        assert!(coordinator.next_action().is_none());

        coordinator.block_imported(root(2));
        assert_eq!(process_action(&mut coordinator).1.block_root, root(3));
    }

    #[test]
    fn failure_from_the_owning_coordinator_drops_only_dependants() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.insert_gossip_block(meta(3, 2, 3), 30, 8);
        coordinator.insert_gossip_block(meta(5, 4, 5), 50, 9);
        coordinator.block_deferred_elsewhere(root(2));

        coordinator.block_failed_elsewhere(root(2));
        assert!(!coordinator.contains(&root(2)));
        assert!(!coordinator.contains(&root(3)));
        assert!(coordinator.contains(&root(4)));
        assert!(coordinator.contains(&root(5)));
    }

    #[test]
    fn stale_download_and_process_results_are_ignored() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        let (old_request, _, _) = request_action(&mut coordinator);
        assert!(coordinator.download_failed(old_request, root(1)));
        assert_eq!(
            coordinator.insert_gossip_block(meta(2, 1, 2), 20, 8),
            InsertOutcome::Duplicate
        );
        let (new_request, _, _) = request_action(&mut coordinator);
        assert_ne!(old_request, new_request);
        assert_eq!(
            coordinator.download_succeeded(old_request, meta(1, 9, 1), 10, ParentStatus::Imported,),
            Ok(false)
        );
        assert_eq!(
            coordinator.download_succeeded(new_request, meta(1, 9, 1), 10, ParentStatus::Imported,),
            Ok(true)
        );
        let (process_id, process_meta, origin, payload) = process_action(&mut coordinator);
        assert!(!coordinator.process_failed(old_request, process_meta.block_root, true));
        let _ = (origin, payload);
        assert!(coordinator.process_imported(process_id, root(1)));
    }

    #[test]
    fn four_download_failures_drop_only_the_dependent_subtree() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.insert_gossip_block(meta(4, 3, 2), 40, 8);

        let (first_failure, requested, _) = request_action(&mut coordinator);
        assert_eq!(requested, root(1));
        let (_, unrelated_root, _) = request_action(&mut coordinator);
        assert_eq!(unrelated_root, root(3));
        assert!(coordinator.download_failed(first_failure, root(1)));
        for _ in 1..4 {
            let (action_id, requested, _) = request_action(&mut coordinator);
            assert_eq!(requested, root(1));
            assert!(coordinator.download_failed(action_id, requested));
        }

        assert!(!coordinator.contains(&root(1)));
        assert!(!coordinator.contains(&root(2)));
        assert!(coordinator.contains(&root(3)));
        assert!(coordinator.contains(&root(4)));
    }

    #[test]
    fn exhausted_chain_cannot_be_recreated_immediately() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        for attempt in 0..4 {
            let (action_id, requested, _) = request_action(&mut coordinator);
            assert!(coordinator.download_failed(action_id, requested));
            assert_eq!(coordinator.contains(&root(1)), attempt < 3);
        }

        assert_eq!(
            coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7),
            InsertOutcome::Rejected(InsertError::RecentlyFailed)
        );
        assert_eq!(
            coordinator.insert_gossip_block(meta(3, 1, 3), 30, 8),
            InsertOutcome::Rejected(InsertError::RecentlyFailed)
        );
    }

    #[test]
    fn process_failure_drops_child_but_keeps_sibling() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.insert_gossip_block(meta(3, 1, 3), 30, 8);
        coordinator.block_imported(root(1));

        let failed = process_action(&mut coordinator);
        let sibling_root = if failed.1.block_root == root(2) {
            root(3)
        } else {
            root(2)
        };
        assert!(coordinator.process_failed(failed.0, failed.1.block_root, false));
        assert!(!coordinator.contains(&failed.1.block_root));
        assert!(coordinator.contains(&sibling_root));
        assert_eq!(process_action(&mut coordinator).1.block_root, sibling_root);
    }

    #[test]
    fn transient_processing_failures_redownload_up_to_the_attempt_limit() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.block_imported(root(1));

        for attempt in 0..4 {
            let (process_id, process_meta, _, _) = process_action(&mut coordinator);
            assert!(coordinator.process_failed(process_id, process_meta.block_root, true));
            if attempt == 3 {
                break;
            }

            let (download_id, requested_root, peer) = request_action(&mut coordinator);
            assert_eq!((requested_root, peer), (root(2), 7));
            assert_eq!(
                coordinator.download_succeeded(
                    download_id,
                    meta(2, 1, 2),
                    20,
                    ParentStatus::Imported,
                ),
                Ok(true)
            );
        }

        assert!(!coordinator.contains(&root(2)));
    }

    #[test]
    fn capacity_rejects_without_evicting_existing_entries() {
        let mut cfg = config();
        cfg.max_lookups = 2;
        let mut coordinator = UnknownParentLookupCoordinator::new(cfg);
        assert_eq!(
            coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7),
            InsertOutcome::Inserted
        );
        assert_eq!(
            coordinator.insert_gossip_block(meta(4, 3, 4), 40, 8),
            InsertOutcome::Rejected(InsertError::Capacity)
        );
        assert!(coordinator.contains(&root(1)));
        assert!(coordinator.contains(&root(2)));
        assert!(!coordinator.contains(&root(3)));
        assert!(!coordinator.contains(&root(4)));
    }

    #[test]
    fn depth_limit_counts_parent_edges_and_rejects_cycles() {
        let mut cfg = config();
        cfg.max_parent_depth = 2;
        let mut coordinator = UnknownParentLookupCoordinator::new(cfg);
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        let (request_id, _, _) = request_action(&mut coordinator);
        assert_eq!(
            coordinator.download_succeeded(request_id, meta(1, 9, 1), 10, ParentStatus::Unknown,),
            Ok(true)
        );
        let (request_id, _, _) = request_action(&mut coordinator);
        assert_eq!(
            coordinator.download_succeeded(request_id, meta(9, 8, 0), 90, ParentStatus::Unknown,),
            Err(InsertError::ParentDepthExceeded)
        );
        assert!(coordinator.is_empty());

        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        assert_eq!(
            coordinator.insert_gossip_block(meta(1, 1, 1), 10, 7),
            InsertOutcome::Rejected(InsertError::Cycle)
        );
    }

    #[test]
    fn prune_uses_absolute_entry_lifetime_and_isolates_trees() {
        let mut cfg = config();
        cfg.stuck_timeout = Duration::ZERO;
        let mut coordinator = UnknownParentLookupCoordinator::new(cfg);
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.insert_gossip_block(meta(4, 3, 4), 40, 8);
        assert_eq!(coordinator.prune(), 4);
        assert!(coordinator.is_empty());
    }

    #[test]
    fn finalized_payload_and_its_orphan_parent_lookup_are_pruned() {
        let mut coordinator = UnknownParentLookupCoordinator::new(config());
        coordinator.insert_gossip_block(meta(2, 1, 2), 20, 7);
        coordinator.insert_gossip_block(meta(4, 3, 4), 40, 8);

        assert_eq!(coordinator.prune_finalized(2), 2);
        assert!(!coordinator.contains(&root(1)));
        assert!(!coordinator.contains(&root(2)));
        assert!(coordinator.contains(&root(3)));
        assert!(coordinator.contains(&root(4)));
    }
}

use std::sync::Arc;

use libp2p::{
    PeerId,
    gossipsub::{Message, MessageAcceptance, MessageId, TopicHash},
};
use ream_chain_beacon::beacon_chain::BeaconChain;
use ream_consensus_beacon::{
    data_column_sidecar::{DataColumnSidecar, NUMBER_OF_COLUMNS},
    electra::beacon_block::SignedBeaconBlock,
};
use ream_metrics::{
    BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL, BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL,
    inc_int_counter_vec,
};
use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
use ream_storage::cache::BeaconCacheDB;
use tokio::{
    sync::{Mutex, Semaphore, mpsc},
    task::{JoinError, JoinSet},
};
use tracing::{debug, error};

use super::handle::{UnknownParentGossipBlock, handle_data_column, handle_gossipsub_message};
use crate::{
    block_lookup::PendingGossipItem, gossip_hint::GossipHint, p2p_sender::P2PSender,
    timing::ColumnSource,
};

/// Messages waiting for a worker. A full queue sheds new messages as IGNORE, which does not
/// penalize their senders; mainnet sends thousands of attestations per slot.
const GOSSIP_QUEUE_CAPACITY: usize = 16_384;

/// Columns the workers validated whose block waits on its parent's availability, queued for the
/// manager loop, which owns the lookups. A block yields at most one item per column, so the
/// queue holds two blocks' worth: the next block's columns can arrive while the loop drains the
/// last one's. A column with 21 blobs is about 45 KB, so a full queue holds about 12 MB. Items
/// that do not fit are dropped: once the block is pending availability, its missing columns are
/// fetched by root.
pub const PENDING_ITEM_QUEUE_CAPACITY: usize = 2 * NUMBER_OF_COLUMNS as usize;

/// Gossip blocks waiting for a block worker. About two epochs of blocks; a full queue sheds new
/// blocks as IGNORE, and a missed block is found again by its children's parent lookup.
const BLOCK_QUEUE_CAPACITY: usize = 64;

/// Tasks validating and importing gossip blocks. Import takes the store lock, so blocks still
/// import one at a time, but a second worker lets a new block be validated while an old one loads
/// a parent state from disk: one such block once held the manager loop 29 s, and the blocks of
/// the next four slots behind it.
pub const BLOCK_WORKERS: usize = 2;

/// A gossip block whose parent is unknown, with the peer that sent it, for the manager loop to
/// look up.
pub struct UnknownParentWork {
    pub block: UnknownParentGossipBlock,
    pub propagation_source: PeerId,
}

/// Called with each gossip block that passed validation, before its import starts.
pub type OnValidBlock = Arc<dyn Fn(&SignedBeaconBlock) + Send + Sync>;

/// How many gossip messages all [`GossipWorkers`] pools may handle at once. Validation runs BLS
/// and KZG checks synchronously, so each handler at work can hold a runtime thread; the budget is
/// one per runtime worker thread but two, which stay free for the network loops.
#[derive(Clone)]
pub struct GossipWorkerBudget {
    workers: usize,
    permits: Arc<Semaphore>,
}

impl GossipWorkerBudget {
    pub fn for_current_runtime() -> Self {
        Self::new(
            tokio::runtime::Handle::current()
                .metrics()
                .num_workers()
                .saturating_sub(2)
                .max(1),
        )
    }

    fn new(workers: usize) -> Self {
        Self {
            workers,
            permits: Arc::new(Semaphore::new(workers)),
        }
    }
}

/// Whether `topic` carries data column sidecars. They go to their own [`GossipWorkers`]: on
/// mainnet a supernode gets 128 per block, and importing each one waits for the store lock, so
/// handling them on the manager loop kept it busy for most of every slot.
pub fn is_data_column(topic: &TopicHash) -> bool {
    matches!(
        GossipTopic::from_topic_hash(topic).map(|topic| topic.kind),
        Ok(GossipTopicKind::DataColumnSidecar(_))
    )
}

/// Whether `topic` carries beacon blocks or blob sidecars, which go to the block workers.
pub fn is_gossip_block(topic: &TopicHash) -> bool {
    matches!(
        GossipTopic::from_topic_hash(topic).map(|topic| topic.kind),
        Ok(GossipTopicKind::BeaconBlock | GossipTopicKind::BlobSidecar(_))
    )
}

/// Whether a message on `topic` is handled by the shared [`GossipWorkers`] pools. Blocks and their
/// sidecars have their own workers, which hand lookups and availability back to the manager loop;
/// every other topic is validated against shared state only, so its messages can be handled
/// concurrently.
pub fn is_handled_concurrently(topic: &TopicHash) -> bool {
    match GossipTopic::from_topic_hash(topic) {
        Ok(topic) => !matches!(
            topic.kind,
            GossipTopicKind::BeaconBlock
                | GossipTopicKind::BlobSidecar(_)
                | GossipTopicKind::DataColumnSidecar(_)
        ),
        Err(_) => false,
    }
}

enum GossipWork {
    Message {
        message: Message,
        message_id: MessageId,
        propagation_source: PeerId,
    },
    /// A column kept since before its parent block came, checked again now that it has.
    ReplayColumn {
        column: Box<DataColumnSidecar>,
        propagation_source: PeerId,
    },
}

/// Lookup hints waiting for the manager loop. Hints are best effort, so a full queue drops them.
pub const HINT_QUEUE_CAPACITY: usize = 4 * NUMBER_OF_COLUMNS as usize;

/// Tasks that validate and import gossip messages off the manager loop. Handled one at a time,
/// attestation BLS checks alone fell minutes behind the network on mainnet.
pub struct GossipWorkers {
    sender: mpsc::Sender<GossipWork>,
    p2p_sender: P2PSender,
    tasks: JoinSet<()>,
}

impl GossipWorkers {
    /// Starts as many tasks as `budget` allows handlers, so one pool can use the whole budget
    /// while the others are idle; a task takes a permit once it has a message. A column whose
    /// block waits on its parent's availability yields lookup work, which goes to
    /// `pending_items` because the manager loop owns the lookups.
    pub fn start(
        beacon_chain: Arc<BeaconChain>,
        cached_db: Arc<BeaconCacheDB>,
        p2p_sender: P2PSender,
        pending_items: mpsc::Sender<PendingGossipItem>,
        hints: mpsc::Sender<GossipHint>,
        budget: &GossipWorkerBudget,
    ) -> Self {
        let (sender, receiver) = mpsc::channel::<GossipWork>(GOSSIP_QUEUE_CAPACITY);
        let worker_p2p_sender = p2p_sender.clone();
        let permits = budget.permits.clone();
        let tasks = spawn_workers(budget.workers, receiver, move |work: GossipWork| {
            let beacon_chain = beacon_chain.clone();
            let cached_db = cached_db.clone();
            let p2p_sender = worker_p2p_sender.clone();
            let pending_items = pending_items.clone();
            let hints = hints.clone();
            let permits = permits.clone();
            async move {
                let _permit = permits
                    .acquire()
                    .await
                    .expect("the gossip worker budget is never closed");
                let mut pending_item = None;
                let mut found_hints = Vec::new();
                match work {
                    GossipWork::Message {
                        message,
                        message_id,
                        propagation_source,
                    } => {
                        let mut unknown_parent_block = None;
                        let acceptance = handle_gossipsub_message(
                            message,
                            &beacon_chain,
                            &cached_db,
                            &mut pending_item,
                            &mut unknown_parent_block,
                            &mut found_hints,
                            propagation_source,
                            |_| {},
                        )
                        .await;
                        // Only blocks produce unknown-parent work, and they never come here.
                        debug_assert!(unknown_parent_block.is_none());
                        p2p_sender.report_gossip_validation(
                            message_id,
                            propagation_source,
                            acceptance,
                        );
                    }
                    GossipWork::ReplayColumn {
                        column,
                        propagation_source,
                    } => {
                        let subnet_id = column.compute_subnet();
                        handle_data_column(
                            column,
                            subnet_id,
                            &beacon_chain,
                            &cached_db,
                            &mut pending_item,
                            &mut found_hints,
                            propagation_source,
                            ColumnSource::Replayed,
                        )
                        .await;
                    }
                }
                if let Some(item) = pending_item
                    && !try_forward(&pending_items, item)
                {
                    debug!("Pending gossip item queue is full, dropping a column");
                    BEACON_GOSSIP_PENDING_ITEMS_DROPPED_TOTAL.inc();
                }
                for hint in found_hints {
                    if !try_forward(&hints, hint) {
                        debug!("Gossip hint queue is full, dropping a hint");
                    }
                }
            }
        });
        Self {
            sender,
            p2p_sender,
            tasks,
        }
    }

    /// Starts [`BLOCK_WORKERS`] tasks for gossip blocks and blob sidecars, outside the shared
    /// budget so that blocks never wait behind attestations. Work only the manager loop can do
    /// goes back to it: blocks with an unknown parent to `unknown_parents`, and blocks whose
    /// parent waits on availability to `pending_items`. Both are sent with backpressure rather
    /// than dropped.
    pub fn start_blocks(
        beacon_chain: Arc<BeaconChain>,
        cached_db: Arc<BeaconCacheDB>,
        p2p_sender: P2PSender,
        pending_items: mpsc::Sender<PendingGossipItem>,
        unknown_parents: mpsc::Sender<UnknownParentWork>,
        on_valid_block: OnValidBlock,
    ) -> Self {
        let (sender, receiver) = mpsc::channel::<GossipWork>(BLOCK_QUEUE_CAPACITY);
        let worker_p2p_sender = p2p_sender.clone();
        let tasks = spawn_workers(BLOCK_WORKERS, receiver, move |work: GossipWork| {
            let beacon_chain = beacon_chain.clone();
            let cached_db = cached_db.clone();
            let p2p_sender = worker_p2p_sender.clone();
            let pending_items = pending_items.clone();
            let unknown_parents = unknown_parents.clone();
            let on_valid_block = on_valid_block.clone();
            async move {
                let GossipWork::Message {
                    message,
                    message_id,
                    propagation_source,
                } = work
                else {
                    debug_assert!(false, "columns are never replayed on the block workers");
                    return;
                };
                let mut pending_item = None;
                let mut unknown_parent_block = None;
                let mut found_hints = Vec::new();
                let acceptance = handle_gossipsub_message(
                    message,
                    &beacon_chain,
                    &cached_db,
                    &mut pending_item,
                    &mut unknown_parent_block,
                    &mut found_hints,
                    propagation_source,
                    |block| on_valid_block(block),
                )
                .await;
                // Blocks and blob sidecars give no hints.
                debug_assert!(found_hints.is_empty());
                p2p_sender.report_gossip_validation(message_id, propagation_source, acceptance);
                if let Some(block) = unknown_parent_block
                    && unknown_parents
                        .send(UnknownParentWork {
                            block,
                            propagation_source,
                        })
                        .await
                        .is_err()
                {
                    debug!("Manager loop stopped, dropping an unknown-parent block");
                }
                if let Some(item) = pending_item
                    && pending_items.send(item).await.is_err()
                {
                    debug!("Manager loop stopped, dropping a pending block");
                }
            }
        });
        Self {
            sender,
            p2p_sender,
            tasks,
        }
    }

    /// Waits until a worker task ends. Workers run until the queue closes, which only happens when
    /// `self` is dropped, so this returns the error of a worker that panicked.
    pub async fn stopped(&mut self) -> Option<JoinError> {
        self.tasks.join_next().await?.err()
    }

    /// Queues `message` for a worker, or reports it as IGNORE when the queue is full.
    pub fn submit(&self, message: Message, message_id: MessageId, propagation_source: PeerId) {
        let work = GossipWork::Message {
            message,
            message_id: message_id.clone(),
            propagation_source,
        };
        if let Err(err) = self.sender.try_send(work) {
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    debug!("Gossip queue is full, ignoring message {message_id}");
                }
                mpsc::error::TrySendError::Closed(_) => {
                    error!("No gossip worker is running, ignoring message {message_id}");
                }
            }
            self.p2p_sender.report_gossip_validation(
                message_id,
                propagation_source,
                MessageAcceptance::Ignore,
            );
        }
    }

    /// Queues `column`, kept since before its parent block came, to be checked again.
    pub fn replay_column(&self, column: DataColumnSidecar, propagation_source: PeerId) {
        let work = GossipWork::ReplayColumn {
            column: Box::new(column),
            propagation_source,
        };
        if self.sender.try_send(work).is_err() {
            inc_int_counter_vec(&BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL, &["dropped"]);
        } else {
            inc_int_counter_vec(&BEACON_UNKNOWN_PARENT_COLUMNS_TOTAL, &["replayed"]);
        }
    }
}

/// Starts `count` tasks that take items from `receiver` one at a time and pass them to `handle`.
/// The tasks end once `receiver`'s senders are dropped and the queue is empty. A panic in `handle`
/// ends its task, and the returned set reports it.
fn spawn_workers<Work, Handle, HandleFuture>(
    count: usize,
    receiver: mpsc::Receiver<Work>,
    handle: Handle,
) -> JoinSet<()>
where
    Work: Send + 'static,
    Handle: Fn(Work) -> HandleFuture + Clone + Send + 'static,
    HandleFuture: Future<Output = ()> + Send,
{
    let receiver = Arc::new(Mutex::new(receiver));
    let mut tasks = JoinSet::new();
    for _ in 0..count {
        let receiver = receiver.clone();
        let handle = handle.clone();
        tasks.spawn(async move {
            loop {
                let Some(work) = receiver.lock().await.recv().await else {
                    return;
                };
                // The next worker was just woken into this thread's LIFO slot, which other threads
                // cannot steal; without a yield the pool runs one handler at a time.
                tokio::task::yield_now().await;
                handle(work).await;
            }
        });
    }
    tasks
}

/// Sends `item` unless the queue is full, and returns whether it was not dropped for that. A
/// closed queue means the manager loop is shutting down, so its items are not counted as dropped.
fn try_forward<T>(sender: &mpsc::Sender<T>, item: T) -> bool {
    !matches!(
        sender.try_send(item),
        Err(mpsc::error::TrySendError::Full(_))
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use alloy_primitives::aliases::B32;
    use libp2p::gossipsub::IdentTopic;
    use ream_p2p::gossipsub::beacon::topics::{GossipTopic, GossipTopicKind};
    use tokio::sync::mpsc;

    use super::{
        BLOCK_WORKERS, GossipWorkerBudget, is_data_column, is_gossip_block,
        is_handled_concurrently, spawn_workers, try_forward,
    };

    #[tokio::test]
    async fn a_slow_block_does_not_hold_the_next_one() {
        let (sender, receiver) = mpsc::channel::<Option<tokio::sync::oneshot::Receiver<()>>>(4);
        let (done_sender, mut done) = mpsc::channel::<&'static str>(4);
        let _tasks = spawn_workers(BLOCK_WORKERS, receiver, move |work| {
            let done_sender = done_sender.clone();
            async move {
                match work {
                    Some(release) => {
                        let _ = release.await;
                        let _ = done_sender.send("slow").await;
                    }
                    None => {
                        let _ = done_sender.send("fast").await;
                    }
                }
            }
        });
        let (release, slow) = tokio::sync::oneshot::channel();
        sender.send(Some(slow)).await.unwrap();
        sender.send(None).await.unwrap();

        // The second item finishes while the first is still held.
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), done.recv())
            .await
            .expect("the next item is handled while the slow one waits");
        assert_eq!(first, Some("fast"));
        release.send(()).unwrap();
        assert_eq!(done.recv().await, Some("slow"));
    }

    #[tokio::test]
    async fn a_panicking_worker_is_reported() {
        let (sender, receiver) = mpsc::channel::<bool>(4);
        let handled = Arc::new(AtomicUsize::new(0));
        let counter = handled.clone();
        let mut tasks = spawn_workers(2, receiver, move |panics: bool| {
            let counter = counter.clone();
            async move {
                assert!(!panics, "test worker panics");
                counter.fetch_add(1, Ordering::SeqCst);
            }
        });

        sender.send(false).await.expect("workers are running");
        sender.send(true).await.expect("workers are running");
        let err = tasks
            .join_next()
            .await
            .expect("a worker ends")
            .expect_err("the worker panicked");
        assert!(err.is_panic());

        // The other worker keeps taking work until the queue closes.
        sender
            .send(false)
            .await
            .expect("one worker is still running");
        drop(sender);
        assert!(tasks.join_next().await.expect("a worker ends").is_ok());
        assert_eq!(handled.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn workers_handle_queued_messages_in_parallel() {
        let (sender, receiver) = mpsc::channel::<()>(64);
        let running = Arc::new(AtomicUsize::new(0));
        let most_running = Arc::new(AtomicUsize::new(0));
        let (now, max) = (running.clone(), most_running.clone());
        let mut tasks = spawn_workers(4, receiver, move |()| {
            let (now, max) = (now.clone(), max.clone());
            async move {
                max.fetch_max(now.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                // Validation is synchronous work that holds the thread.
                std::thread::sleep(std::time::Duration::from_millis(20));
                now.fetch_sub(1, Ordering::SeqCst);
            }
        });
        // Messages arrive one by one, faster than one handler keeps up with.
        for _ in 0..40 {
            sender.send(()).await.expect("workers are running");
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        drop(sender);
        while tasks.join_next().await.is_some() {}
        assert!(
            most_running.load(Ordering::SeqCst) >= 3,
            "at most {} handlers ran at once",
            most_running.load(Ordering::SeqCst)
        );
    }

    fn topic_hash(kind: GossipTopicKind) -> libp2p::gossipsub::TopicHash {
        IdentTopic::new(
            GossipTopic {
                fork: B32::ZERO,
                kind,
            }
            .to_string(),
        )
        .hash()
    }

    #[test]
    fn blocks_and_sidecars_have_their_own_workers() {
        assert!(is_gossip_block(&topic_hash(GossipTopicKind::BeaconBlock)));
        assert!(is_gossip_block(&topic_hash(GossipTopicKind::BlobSidecar(
            0
        ))));
        assert!(!is_gossip_block(&topic_hash(
            GossipTopicKind::DataColumnSidecar(3)
        )));
        assert!(!is_gossip_block(&topic_hash(
            GossipTopicKind::BeaconAttestation(5)
        )));
        assert!(!is_gossip_block(&IdentTopic::new("unknown").hash()));

        assert!(!is_handled_concurrently(&topic_hash(
            GossipTopicKind::BeaconBlock
        )));
        assert!(!is_handled_concurrently(&topic_hash(
            GossipTopicKind::BlobSidecar(0)
        )));
        assert!(!is_handled_concurrently(&topic_hash(
            GossipTopicKind::DataColumnSidecar(3)
        )));
        assert!(is_handled_concurrently(&topic_hash(
            GossipTopicKind::BeaconAttestation(5)
        )));
        assert!(is_handled_concurrently(&topic_hash(
            GossipTopicKind::AggregateAndProof
        )));
        assert!(is_handled_concurrently(&topic_hash(
            GossipTopicKind::SyncCommittee(1)
        )));
        assert!(!is_handled_concurrently(&IdentTopic::new("unknown").hash()));
    }

    #[test]
    fn only_data_columns_go_to_the_column_workers() {
        assert!(is_data_column(&topic_hash(
            GossipTopicKind::DataColumnSidecar(3)
        )));
        assert!(!is_data_column(&topic_hash(GossipTopicKind::BeaconBlock)));
        assert!(!is_data_column(&topic_hash(GossipTopicKind::BlobSidecar(
            0
        ))));
        assert!(!is_data_column(&topic_hash(
            GossipTopicKind::BeaconAttestation(5)
        )));
        assert!(!is_data_column(&IdentTopic::new("unknown").hash()));
    }

    #[test]
    fn a_full_pending_queue_drops_the_item() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(try_forward(&sender, 1));
        assert!(!try_forward(&sender, 2));
        assert_eq!(receiver.try_recv(), Ok(1));
        assert!(receiver.try_recv().is_err());

        drop(receiver);
        assert!(
            try_forward(&sender, 3),
            "a closed queue is not counted as full"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn pools_share_a_budget_that_leaves_two_threads_free() {
        let budget = GossipWorkerBudget::for_current_runtime();
        assert_eq!(budget.workers, 4);
        let shared = budget.clone();
        let _held = budget
            .permits
            .acquire_many(4)
            .await
            .expect("budget is open");
        assert_eq!(shared.permits.available_permits(), 0);
    }
}

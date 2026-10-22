//! Publishes the assembler's events to NATS on the node, the sink behind --nats.
//!
//! The capture thread never waits for NATS. NatsSink turns each event into its subject and
//! the same JSON the files hold, and puts it on a bounded queue. One publisher thread takes
//! up to BATCH messages off the queue at a time, sends them all, then collects the server's
//! acks together, so a slow ack holds up one batch instead of every message behind it.
//! When the queue fills up, transactions are dropped first: above TX_ROOM a transaction
//! is turned away, while slots, summaries and rollups still get in until QUEUE is reached.
//! Every message dropped or lost is counted, and the longest wait is measured, so the next
//! rollup can show when the publisher falls behind.
//!
//! shred.slot and shred.stats are stored in JetStream streams, each message with a Nats-Msg-Id
//! so a resend inside the duplicate window is not stored twice. The streams are made on connect
//! if they are missing. shred.tx and shred.public are plain publishes, not stored, live only.
//!
//! So a page opens full instead of empty, NatsSink also keeps the last HISTORY_SLOTS summaries,
//! HISTORY_STATS rollups and HISTORY_SAMPLES sampled transactions, and every HISTORY_EVERY
//! it stores them as one snapshot on shred.history, so a page loses at most a few slots. That stream keeps only the latest message,
//! on disk so a NATS restart keeps it, and a page reads it once with a JetStream direct get.
//! The async client runs on its own small tokio runtime, so the rest of shredtap stays sync.

use std::collections::VecDeque;

use serde::Serialize;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use async_nats::jetstream::{self, stream};
use async_nats::{Client, HeaderMap, header};
use tokio::runtime::Runtime;

use crate::assembler::Event;
use crate::error::{Error, Result};
use crate::feed::{Public, Summary};
use crate::record::{EventSink, Published, untagged_json};
use crate::rollup::Rollup;

/// Messages the queue holds before it drops. A slot's transactions all arrive at once when it
/// closes, and a busy slot can hold tens of thousands, so the queue has room for the biggest.
/// About 400 bytes a transaction, so a full queue is about 26 MB.
const QUEUE: usize = 65_536;
/// Above this many queued, transactions are dropped, so the rest still have room.
const TX_ROOM: usize = QUEUE * 3 / 4;
/// Messages sent before waiting for their acks.
const BATCH: usize = 256;

/// The stored subjects, each in its own stream so each keeps what it is worth.
const STREAMS: [(&str, &str, Duration, i64); 2] = [
    (
        "SHRED_SLOT",
        "shred.slot",
        Duration::from_secs(3 * 86_400),
        2 << 30,
    ),
    (
        "SHRED_STATS",
        "shred.stats",
        Duration::from_secs(3 * 86_400),
        64 << 20,
    ),
];

/// The snapshot stream: only the latest message, readable with a direct get.
const HISTORY_STREAM: &str = "SHRED_HISTORY";
/// Slots in the snapshot, more than the page's 120 slot window so it opens full.
const HISTORY_SLOTS: usize = 150;
/// Rollups in the snapshot, ten minutes of them.
const HISTORY_STATS: usize = 120;
/// Sampled transactions in the snapshot, the page's list.
const HISTORY_SAMPLES: usize = 8;
/// How often the snapshot is stored, so its newest slot is at most about 5 slots old.
const HISTORY_EVERY: Duration = Duration::from_secs(1);

/// What a page needs to open full.
#[derive(Default)]
struct History {
    /// Summaries without their samples, which are kept apart.
    slots: VecDeque<Summary>,
    stats: VecDeque<Rollup>,
    /// Newest first.
    samples: VecDeque<HistorySample>,
}

#[derive(Serialize)]
struct HistorySample {
    sig: String,
    rebuilt: bool,
    slot: u64,
}

/// The JSON of one snapshot, tagged like the messages on shred.public.
#[derive(Serialize)]
struct Snapshot<'a> {
    kind: &'static str,
    slots: &'a VecDeque<Summary>,
    stats: &'a VecDeque<Rollup>,
    samples: &'a VecDeque<HistorySample>,
}

impl History {
    fn add(&mut self, message: &Public) {
        match message {
            Public::Summary(summary) => {
                for t in summary.sample.iter().rev() {
                    self.samples.push_front(HistorySample {
                        sig: t.sig.clone(),
                        rebuilt: t.rebuilt,
                        slot: summary.slot,
                    });
                }
                self.samples.truncate(HISTORY_SAMPLES);
                self.slots.push_back(Summary {
                    sample: Vec::new(),
                    ..summary.clone()
                });
                if self.slots.len() > HISTORY_SLOTS {
                    self.slots.pop_front();
                }
            }
            Public::Stats(rollup) => {
                self.stats.push_back(rollup.clone());
                if self.stats.len() > HISTORY_STATS {
                    self.stats.pop_front();
                }
            }
        }
    }

    fn json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&Snapshot {
            kind: "history",
            slots: &self.slots,
            stats: &self.stats,
            samples: &self.samples,
        })?)
    }
}

/// One message waiting to go out.
struct Message {
    subject: &'static str,
    /// The Nats-Msg-Id, set on stored messages only.
    id: Option<String>,
    payload: Vec<u8>,
    queued: Instant,
}

impl Message {
    fn new(subject: &'static str, id: Option<String>, payload: Vec<u8>) -> Self {
        Self {
            subject,
            id,
            payload,
            queued: Instant::now(),
        }
    }
}

/// The messages for one event: a transaction, live only, or a closed slot, stored.
/// Nothing for sets and markers.
fn event_messages(event: &Event) -> Result<Option<Message>> {
    let (subject, id) = match event {
        Event::Tx { .. } => ("shred.tx", None),
        Event::Slot { slot, .. } => ("shred.slot", Some(slot.to_string())),
        _ => return Ok(None),
    };
    Ok(Some(Message::new(subject, id, untagged_json(event)?)))
}

/// The messages for one public message: a summary goes on shred.public,
/// a rollup is stored on shred.stats and also goes on shred.public.
fn public_messages(message: &Public) -> Result<Vec<Message>> {
    let public = Message::new("shred.public", None, serde_json::to_vec(message)?);
    Ok(match message {
        Public::Summary(_) => vec![public],
        Public::Stats(rollup) => vec![
            Message::new(
                "shred.stats",
                Some(rollup.at_ns.to_string()),
                serde_json::to_vec(rollup)?,
            ),
            public,
        ],
    })
}

/// What the queue holds, behind one lock.
#[derive(Default)]
struct State {
    messages: VecDeque<Message>,
    /// Messages the publisher has taken and not finished with.
    in_flight: usize,
    closed: bool,
    /// The publisher thread has stopped, so nothing will be sent any more.
    stopped: bool,
    dropped: u64,
    lag_ns: Option<u64>,
}

/// A bounded queue between the capture thread and the publisher thread.
struct Queue {
    state: Mutex<State>,
    /// Woken when a message is added, one is finished, or the queue closes.
    changed: Condvar,
}

impl Queue {
    fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // a panic while holding the lock leaves plain counters behind, still fine to read
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds a message without waiting, or counts it as dropped when there is no room.
    fn push(&self, message: Message) {
        let mut state = self.lock();
        let limit = if message.subject == "shred.tx" {
            TX_ROOM
        } else {
            QUEUE
        };
        if state.stopped || state.messages.len() >= limit {
            state.dropped += 1;
            return;
        }
        state.messages.push_back(message);
        self.changed.notify_all();
    }

    /// Waits for messages and takes up to max of them, None once the queue is closed and empty.
    fn pop_batch(&self, max: usize) -> Option<Vec<Message>> {
        let mut state = self.lock();
        loop {
            if !state.messages.is_empty() {
                let n = state.messages.len().min(max);
                state.in_flight += n;
                return Some(state.messages.drain(..n).collect());
            }
            if state.closed {
                return None;
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    /// The publisher is done with its message, sent after waiting `lag` or lost.
    fn done(&self, sent: bool, lag: Duration) {
        let mut state = self.lock();
        state.in_flight = state.in_flight.saturating_sub(1);
        if sent {
            let lag_ns = u64::try_from(lag.as_nanos()).unwrap_or(u64::MAX);
            state.lag_ns = Some(state.lag_ns.map_or(lag_ns, |l| l.max(lag_ns)));
        } else {
            state.dropped += 1;
        }
        self.changed.notify_all();
    }

    /// Waits until every queued message has been handled.
    fn wait_empty(&self) {
        let mut state = self.lock();
        while (!state.messages.is_empty() || state.in_flight > 0) && !state.stopped {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn close(&self) {
        self.lock().closed = true;
        self.changed.notify_all();
    }

    /// The publisher thread is gone. What is left counts as dropped, and nobody waits for it.
    fn stop(&self) {
        let mut state = self.lock();
        state.stopped = true;
        state.in_flight = 0;
        state.dropped += state.messages.len() as u64;
        state.messages.clear();
        self.changed.notify_all();
    }

    /// The drop count, and the longest wait since the last read.
    fn published(&self) -> Published {
        let mut state = self.lock();
        Published {
            dropped: state.dropped,
            lag_ns: state.lag_ns.take(),
        }
    }
}

/// Publishes events to a NATS server.
pub struct NatsSink {
    queue: Arc<Queue>,
    runtime: Arc<Runtime>,
    client: Client,
    publisher: Option<JoinHandle<()>>,
    history: History,
    /// When the snapshot was last stored.
    history_at: Option<Instant>,
}

impl NatsSink {
    /// Connects, makes the streams if they are missing, and starts the publisher thread.
    /// Fails at once if the server can't be reached, so a service manager can retry.
    pub fn connect(addr: &str) -> Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("nats-client")
            .enable_all()
            .build()?;
        let client = runtime.block_on(async {
            let client = async_nats::connect(addr).await.map_err(nats_error)?;
            let js = jetstream::new(client.clone());
            for (name, subject, max_age, max_bytes) in STREAMS {
                js.get_or_create_stream(stream::Config {
                    name: name.to_string(),
                    subjects: vec![subject.to_string()],
                    max_age,
                    max_bytes,
                    ..Default::default()
                })
                .await
                .map_err(nats_error)?;
            }
            js.get_or_create_stream(stream::Config {
                name: HISTORY_STREAM.to_string(),
                subjects: vec!["shred.history".to_string()],
                max_messages_per_subject: 1,
                max_bytes: 4 << 20,
                allow_direct: true,
                ..Default::default()
            })
            .await
            .map_err(nats_error)?;
            Ok::<_, Error>(client)
        })?;

        let runtime = Arc::new(runtime);
        let queue = Arc::new(Queue::new());
        let publisher = std::thread::Builder::new()
            .name("nats-publisher".to_string())
            .spawn({
                let (queue, runtime, client) = (queue.clone(), runtime.clone(), client.clone());
                move || publish_all(&queue, &runtime, client)
            })?;
        Ok(Self {
            queue,
            runtime,
            client,
            publisher: Some(publisher),
            history: History::default(),
            history_at: None,
        })
    }
}

/// Stops the queue when the publisher thread ends, even by a panic, so flush never waits forever.
struct StopOnExit<'a>(&'a Queue);

impl Drop for StopOnExit<'_> {
    fn drop(&mut self) {
        self.0.stop();
    }
}

/// The publisher thread: sends a batch, then waits for the acks of its stored messages.
fn publish_all(queue: &Queue, runtime: &Runtime, client: Client) {
    let _stop = StopOnExit(queue);
    // the JetStream context starts a task of its own, so it has to be made inside the runtime
    let js = {
        let _inside = runtime.enter();
        jetstream::new(client.clone())
    };
    while let Some(batch) = queue.pop_batch(BATCH) {
        runtime.block_on(async {
            let mut acks = Vec::with_capacity(batch.len());
            for message in batch {
                match message.id {
                    Some(id) => {
                        let mut headers = HeaderMap::new();
                        headers.insert(header::NATS_MESSAGE_ID, id);
                        match js
                            .publish_with_headers(message.subject, headers, message.payload.into())
                            .await
                        {
                            Ok(ack) => acks.push((ack, message.queued)),
                            Err(_) => queue.done(false, message.queued.elapsed()),
                        }
                    }
                    None => {
                        let sent = client
                            .publish(message.subject, message.payload.into())
                            .await
                            .is_ok();
                        queue.done(sent, message.queued.elapsed());
                    }
                }
            }
            // the whole batch is on its way, so the acks come back together
            for (ack, queued) in acks {
                queue.done(ack.await.is_ok(), queued.elapsed());
            }
        });
    }
}

fn nats_error(e: impl std::fmt::Display) -> Error {
    Error::Nats(e.to_string())
}

impl EventSink for NatsSink {
    fn write(&mut self, event: &Event) -> Result<()> {
        if let Some(message) = event_messages(event)? {
            self.queue.push(message);
        }
        Ok(())
    }

    fn public(&mut self, message: &Public) -> Result<()> {
        self.history.add(message);
        for m in public_messages(message)? {
            self.queue.push(m);
        }
        // a fresh snapshot every HISTORY_EVERY, stored so a page can read it on connect
        if self
            .history_at
            .is_none_or(|at| at.elapsed() >= HISTORY_EVERY)
        {
            let now = Instant::now();
            self.history_at = Some(now);
            let id = format!("history:{now:?}");
            self.queue.push(Message::new(
                "shred.history",
                Some(id),
                self.history.json()?,
            ));
        }
        Ok(())
    }

    /// Waits until everything queued is sent and the client has written it out.
    fn flush(&mut self) -> Result<()> {
        self.queue.wait_empty();
        self.runtime
            .block_on(self.client.flush())
            .map_err(nats_error)
    }

    fn published(&mut self) -> Option<Published> {
        Some(self.queue.published())
    }
}

impl Drop for NatsSink {
    fn drop(&mut self) {
        self.queue.close();
        if let Some(publisher) = self.publisher.take() {
            // the thread only returns once the queue is closed and empty, a panic there is already lost
            let _ = publisher.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::{SlotEnd, Timing};
    use crate::feed::Summary;
    use solana_transaction::Signature;

    fn tx(slot: u64) -> Event {
        Event::Tx {
            slot,
            signature: Signature::default(),
            timing: Timing {
                fec_set_index: 0,
                first_shred_ns: 1,
                decodable_ns: 2,
                decoded_ns: 3,
            },
            rebuilt: true,
        }
    }

    fn slot(slot: u64) -> Event {
        Event::Slot {
            slot,
            leader: None,
            first_shred_ns: 1,
            done_ns: None,
            sets_decoded: 0,
            sets_lost: 0,
            txs: 0,
            late_data: 0,
            footer: None,
            end: SlotEnd::GivenUp,
        }
    }

    fn message(subject: &'static str) -> Message {
        Message::new(subject, None, Vec::new())
    }

    #[test]
    fn test_subjects_and_ids() {
        let m = event_messages(&tx(7)).unwrap().unwrap();
        // live only, so no message id
        assert_eq!((m.subject, m.id.is_none()), ("shred.tx", true));
        // the same JSON as the line in tx.jsonl, no kind tag
        let json: serde_json::Value = serde_json::from_slice(&m.payload).unwrap();
        assert_eq!(json["slot"], 7);
        assert_eq!(json["rebuilt"], true);
        assert!(json.get("kind").is_none());

        let m = event_messages(&slot(8)).unwrap().unwrap();
        assert_eq!((m.subject, m.id.as_deref()), ("shred.slot", Some("8")));

        let set = Event::Set {
            slot: 8,
            fec_set_index: 0,
            first_shred_ns: 0,
            decodable_ns: None,
            data_at_decode: 0,
            rebuilt: Vec::new(),
            decoded: false,
        };
        assert!(event_messages(&set).unwrap().is_none());
    }

    #[test]
    fn test_public_messages() {
        let summary = Public::Summary(Summary {
            slot: 8,
            leader: None,
            first_shred_ns: 1,
            done_ns: None,
            txs: 0,
            data_missing: 0,
            data_shreds: None,
            first_tx_ms: None,
            end: "given_up",
            fast_final: None,
            sample: Vec::new(),
        });
        let m = public_messages(&summary).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!((m[0].subject, m[0].id.is_none()), ("shred.public", true));
        assert!(m[0].payload.starts_with(br#"{"kind":"summary""#));
    }

    #[test]
    fn test_history_keeps_the_latest() {
        use crate::feed::SampleTx;
        use crate::rollup::{Fill, FillN};
        let mut h = History::default();
        // worst case sizes: real length leaders and signatures, every field set
        for slot in 452_000_000..452_000_160u64 {
            h.add(&Public::Summary(Summary {
                slot,
                leader: Some("5D1fNXzvv5NjV1ysLjirC4WY92RNsVH18vjmcszZd8on".to_string()),
                first_shred_ns: 1_792_001_554_921_075_667,
                done_ns: Some(1_792_001_555_183_199_732),
                txs: 1_435,
                data_missing: 12,
                data_shreds: Some(2_240),
                first_tx_ms: Some(42.17),
                end: "complete",
                fast_final: Some(true),
                sample: vec![
                    SampleTx {
                        sig: format!("{slot}a{}", "x".repeat(78)),
                        rebuilt: false,
                    },
                    SampleTx {
                        sig: format!("{slot}b{}", "x".repeat(78)),
                        rebuilt: true,
                    },
                ],
            }));
        }
        for i in 0..130u64 {
            h.add(&Public::Stats(Rollup {
                at_ns: 1_792_001_554_921_075_667 + i,
                window_s: 60,
                packets_per_s: 4_040,
                kernel_drops: Some(0),
                slots_closed: 300,
                slots_given_up: 2,
                slots_never_came: 4,
                data_shreds_missing_pct: 12.34,
                set_fill_ms: Some(Fill {
                    p50: 65.43,
                    p99: 161.07,
                }),
                set_fill_ms_5s: FillN {
                    p50: Some(65.43),
                    p99: Some(161.07),
                    n: 812,
                },
                stale_shreds: 1_234,
                first_tx_ms: Some(Fill {
                    p50: 42.17,
                    p99: 118.4,
                }),
                txs_rebuilt_pct: 42.81,
                bad_proof: 0,
                bad_signature: 0,
                events_dropped: Some(0),
                publish_lag_ms: Some(0.36),
            }));
        }
        assert_eq!(
            (h.slots.len(), h.stats.len()),
            (HISTORY_SLOTS, HISTORY_STATS)
        );
        assert_eq!(h.slots.front().unwrap().slot, 452_000_010);
        assert_eq!(h.slots.back().unwrap().slot, 452_000_159);
        assert!(h.slots.iter().all(|s| s.sample.is_empty()));
        // the newest samples first, in their slot's order
        assert_eq!(h.samples.len(), HISTORY_SAMPLES);
        assert!(
            h.samples[0].sig.starts_with("452000159a")
                && h.samples[1].sig.starts_with("452000159b")
        );

        let json = h.json().unwrap();
        // max_payload on the node is 128 KB, keep a margin
        assert!(json.len() < 112 * 1024, "{} bytes", json.len());
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["kind"], "history");
        assert_eq!(v["slots"].as_array().unwrap().len(), HISTORY_SLOTS);
        assert_eq!(v["samples"][0]["slot"], 452_000_159);
    }

    #[test]
    fn test_full_queue_drops_transactions_first() {
        let queue = Queue::new();
        for _ in 0..TX_ROOM {
            queue.push(message("shred.tx"));
        }
        // no room left for a transaction, but a slot still gets in
        queue.push(message("shred.tx"));
        queue.push(message("shred.slot"));
        assert_eq!(queue.published().dropped, 1);
        for _ in TX_ROOM + 1..QUEUE {
            queue.push(message("shred.public"));
        }
        queue.push(message("shred.slot"));
        assert_eq!(queue.published().dropped, 2);
        assert_eq!(queue.lock().messages.len(), QUEUE);
    }

    #[test]
    fn test_queue_order_and_counters() {
        let queue = Queue::new();
        queue.push(message("shred.tx"));
        queue.push(message("shred.slot"));
        queue.push(message("shred.public"));
        // a batch takes the oldest first, and no more than asked
        let batch = queue.pop_batch(2).unwrap();
        let subjects: Vec<_> = batch.iter().map(|m| m.subject).collect();
        assert_eq!(subjects, ["shred.tx", "shred.slot"]);
        queue.done(true, Duration::from_millis(3));
        queue.done(false, Duration::ZERO);
        assert_eq!(queue.pop_batch(BATCH).unwrap().len(), 1);
        queue.done(true, Duration::ZERO);
        let published = queue.published();
        assert_eq!(published.dropped, 1);
        assert_eq!(published.lag_ns, Some(3_000_000));
        // the longest wait is reset once it is read
        assert_eq!(queue.published().lag_ns, None);
        queue.close();
        assert!(queue.pop_batch(BATCH).is_none());
    }

    #[test]
    fn test_a_stopped_publisher_never_blocks() {
        let queue = Queue::new();
        queue.push(message("shred.slot"));
        queue.stop();
        // what was waiting is counted, flush returns, and new messages are turned away
        queue.wait_empty();
        queue.push(message("shred.slot"));
        assert_eq!(queue.published().dropped, 2);
    }

    /// A nats-server with JetStream on a free port, stopped and cleaned up when dropped.
    struct Server {
        child: std::process::Child,
        dir: std::path::PathBuf,
        addr: String,
    }

    impl Server {
        /// None when nats-server is not installed, so the test is skipped.
        fn start() -> Option<Self> {
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .ok()?
                .local_addr()
                .ok()?
                .port();
            let dir = std::env::temp_dir().join(format!("shredtap-nats-{port}"));
            let child = std::process::Command::new("nats-server")
                .args(["-js", "-a", "127.0.0.1", "-p", &port.to_string(), "-sd"])
                .arg(&dir)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok()?;
            let addr = format!("127.0.0.1:{port}");
            // wait until it accepts connections
            for _ in 0..50 {
                if std::net::TcpStream::connect(&addr).is_ok() {
                    return Some(Self { child, dir, addr });
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            None
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn test_publish_a_real_capture() {
        use crate::assembler::Assembler;
        use crate::feed::Feed;
        use shred_core::pcap::{PacketSource, PcapReader, udp_payload};
        use crate::rollup::Rollups;
        use futures_util::StreamExt;

        let Ok(file) = std::fs::File::open("tests/fixtures/real-10s.pcap") else {
            return;
        };
        let Some(server) = Server::start() else {
            return;
        };
        let mut sink = NatsSink::connect(&server.addr).unwrap();
        // a reader of shred.public, like the page, subscribed before anything is sent
        let reader = sink
            .runtime
            .block_on(async_nats::connect(&server.addr))
            .unwrap();
        let mut sub = sink
            .runtime
            .block_on(reader.subscribe("shred.public"))
            .unwrap();
        let mut tx_sub = sink.runtime.block_on(reader.subscribe("shred.tx")).unwrap();
        sink.runtime.block_on(reader.flush()).unwrap();

        let mut reader_pcap = PcapReader::new(std::io::BufReader::new(file)).unwrap();
        let (mut asm, mut feed, mut rollups) =
            (Assembler::new(), Feed::default(), Rollups::default());
        let (mut txs, mut slots, mut public) = (0, 0, 0);
        let count = |event: &Event, txs: &mut u64, slots: &mut u64| match event {
            Event::Tx { .. } => *txs += 1,
            Event::Slot { .. } => *slots += 1,
            _ => {}
        };
        while let Some(rec) = reader_pcap.next_record().unwrap() {
            if let Some(payload) = udp_payload(&rec.frame) {
                for event in asm.push(payload, rec.recv_ns) {
                    count(&event, &mut txs, &mut slots);
                    rollups.add(&event);
                    if let Some(s) = feed.add(&event) {
                        sink.public(&Public::Summary(s)).unwrap();
                        public += 1;
                    }
                    sink.write(&event).unwrap();
                }
            }
            if let Some(r) = rollups.tick(rec.recv_ns, asm.stats(), || None, || None) {
                sink.public(&Public::Stats(r)).unwrap();
                public += 1;
            }
        }
        for event in asm.finish() {
            count(&event, &mut txs, &mut slots);
            if let Some(s) = feed.add(&event) {
                sink.public(&Public::Summary(s)).unwrap();
                public += 1;
            }
            sink.write(&event).unwrap();
        }
        sink.flush().unwrap();
        assert_eq!(sink.published().unwrap().dropped, 0);

        // every slot is stored, transactions are not, and the readers got every live message
        let (slots_stored, tx_stream) = sink.runtime.block_on(async {
            let js = jetstream::new(reader.clone());
            let mut stream = js.get_stream("SHRED_SLOT").await.unwrap();
            let slots_stored = stream.info().await.unwrap().state.messages;
            (slots_stored, js.get_stream("SHRED_TX").await.is_ok())
        });
        assert_eq!(slots_stored, slots);
        assert!(!tx_stream);

        // the snapshot a page opens with, read the way the page reads it, a direct get
        let snapshot = sink.runtime.block_on(async {
            let js = jetstream::new(reader.clone());
            let stream = js.get_stream(HISTORY_STREAM).await.unwrap();
            stream
                .direct_get_last_for_subject("shred.history")
                .await
                .unwrap()
                .payload
        });
        let v: serde_json::Value = serde_json::from_slice(&snapshot).unwrap();
        assert_eq!(v["kind"], "history");
        // taken at the last rollup, so it holds the slots closed by then
        assert!(!v["slots"].as_array().unwrap().is_empty());
        assert!(!v["stats"].as_array().unwrap().is_empty());
        assert!(txs > 2_000 && slots > 40, "{txs} txs, {slots} slots");
        let received = |sub: &mut async_nats::Subscriber, want: u64| {
            sink.runtime.block_on(async {
                let mut got = 0;
                while got < want {
                    match tokio::time::timeout(Duration::from_secs(5), sub.next()).await {
                        Ok(Some(_)) => got += 1,
                        _ => break,
                    }
                }
                got
            })
        };
        assert_eq!(received(&mut sub, public), public);
        assert_eq!(received(&mut tx_sub, txs), txs);
        // a subscriber unsubscribes with a task of its own when dropped
        let _inside = sink.runtime.enter();
        drop((sub, tx_sub));
    }
}

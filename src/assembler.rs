//! Turns a stream of shred packets into decoded transactions and block markers, with timing.
//!
//! push takes one packet, parses it and puts the shred into its FEC set.
//! A set decodes as soon as it has 32 shreds, the earliest moment the data can be known.
//! Sets go to the slot's Batcher strictly in order, because a batch can start in one set and end in the next.
//! Each finished batch is decoded and handed out as events, one per transaction or marker.
//! A slot closes when its last shred is decoded, or when its Alpenglow skip deadline has passed
//! on the capture clock, 1.45 s after its first shred with 200 ms slots.
//! Every event carries t0 (first shred of the set), t1 (32nd shred) and t2 (the batch could decode).

use crate::block::{Batcher, Component, decode_component, is_last_in_slot};
use crate::fec::{DATA_SHREDS, FecSet};
use crate::shred::{Kind, Shred};
use crate::wire;
use solana_transaction::Signature;
use std::collections::{BTreeMap, BTreeSet, HashMap};

// Alpenglow timing, from Agave votor/src/common.rs and timer_manager/timers.rs.
// A validator votes skip on slot i of a leader window at
// ParentReady + DELTA_TIMEOUT + (i + 1) * slot duration, so by
// first shred + DELTA_TIMEOUT + LEADER_WINDOW_SLOTS * slot + DELTA every honest
// validator has passed the slot's skip deadline and its shreds are no longer coming.

/// Network delay bound, Agave DELTA.
pub const DELTA_NS: u64 = 250_000_000;
/// Base leader handover timeout, Agave DELTA_TIMEOUT.
pub const DELTA_TIMEOUT_NS: u64 = 400_000_000;
/// Slots per leader window, Agave NUM_CONSECUTIVE_LEADER_SLOTS.
pub const LEADER_WINDOW_SLOTS: u64 = 4;
/// Slot duration on mainnet and testnet. Agave reads it from the bank per epoch.
pub const DEFAULT_SLOT_NS: u64 = 200_000_000;

/// Closed slots remembered so shreds arriving after them are counted, not reopened. About 14 minutes of slots.
const CLOSED_SLOTS_KEPT: usize = 4096;

/// When each part of a transaction's journey happened, all in capture nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// FEC set the batch finished in.
    pub fec_set_index: u32,
    /// First shred of that set arrived (t0).
    pub first_shred_ns: u64,
    /// That set had 32 unique shreds, so it could be rebuilt (t1).
    pub decodable_ns: u64,
    /// The packet that let the batch decode arrived (t2).
    pub decoded_ns: u64,
}

/// What the assembler hands out.
#[derive(Debug)]
pub enum Event {
    /// One transaction, keyed by its first signature.
    Tx {
        slot: u64,
        signature: Signature,
        timing: Timing,
    },
    /// A block marker, variant 0 footer, 1 header, 2 update parent, 3 genesis certificate.
    Marker {
        slot: u64,
        variant: u8,
        data: Vec<u8>,
        timing: Timing,
    },
    /// One FEC set, either decoded or given up on. Comes before anything decoded from it.
    Set {
        slot: u64,
        fec_set_index: u32,
        /// First shred of the set arrived (t0).
        first_shred_ns: u64,
        /// The set reached 32 shreds (t1), None if it never did.
        decodable_ns: Option<u64>,
        /// Data shreds the set held when it was decoded or given up on.
        data_at_decode: u64,
        /// Reed-Solomon rebuilt missing data shards.
        recovered: bool,
        /// False when the set was given up on.
        decoded: bool,
    },
}

/// Shred health counters for the report.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    pub packets: u64,
    /// Packets that are not a shred we can read, like the wrong size or an unknown variant.
    pub not_shreds: u64,
    pub duplicates: u64,
    /// Shreds that arrived after their slot was finished or given up on, mostly leftover coding shreds.
    pub after_slot_done: u64,
    /// Shreds whose set was already decoded from the first 32 that arrived.
    pub after_decode: u64,
    /// Shreds a FEC set refused, like an out of range index or a config other than 32 and 32.
    pub rejected: u64,
    /// Sets whose data shards went to the decoder.
    pub sets_decoded: u64,
    /// Of those, sets decoded with Reed-Solomon because some data shreds weren't in yet at t1.
    pub sets_recovered: u64,
    /// Sets that never reached 32 shreds, or waited behind one that didn't.
    pub sets_lost: u64,
    pub batches: u64,
    /// Batches that didn't decode as entries or a marker.
    pub decode_errors: u64,
    pub slots_complete: u64,
    /// Transactions handed out, one per first signature.
    pub txs: u64,
    /// Block markers handed out.
    pub markers: u64,
}

/// Everything in flight for one slot.
struct SlotState {
    /// Earliest arrival of any shred of this slot, the start of its give up clock.
    first_seen_ns: u64,
    sets: BTreeMap<u32, FecSet>,
    /// fec_set_index of the next set to hand to the batcher, sets must go in order
    /// because a batch can start in one set and end in the next.
    next_set: u32,
    batcher: Batcher,
}

pub struct Assembler {
    slots: HashMap<u64, SlotState>,
    /// Slots finished or given up on, so shreds arriving after them are counted and not reopened.
    closed: BTreeSet<u64>,
    /// Capture clock, the newest recv_ns seen, so a reordered packet can't move time backwards.
    now_ns: u64,
    /// How long after its first shred a slot is given up on.
    give_up_ns: u64,
    stats: Stats,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    /// An assembler for 200 ms slots.
    pub fn new() -> Self {
        Self::with_slot_duration_ns(DEFAULT_SLOT_NS)
    }

    /// An assembler for another slot duration, which moves the give up deadline with it.
    pub fn with_slot_duration_ns(slot_ns: u64) -> Self {
        Self {
            slots: HashMap::new(),
            closed: BTreeSet::new(),
            now_ns: 0,
            give_up_ns: DELTA_TIMEOUT_NS + LEADER_WINDOW_SLOTS * slot_ns + DELTA_NS,
            stats: Stats::default(),
        }
    }

    /// How long after its first shred a slot is given up on.
    pub fn give_up_ns(&self) -> u64 {
        self.give_up_ns
    }

    /// Feeds one UDP payload. Returns whatever this packet made decodable.
    pub fn push(&mut self, payload: &[u8], recv_ns: u64) -> Vec<Event> {
        self.stats.packets += 1;

        let Some(shred) = parse_full_shred(payload, recv_ns) else {
            self.stats.not_shreds += 1;
            return Vec::new();
        };
        let slot = shred.slot;

        // time moves on even for a shred we end up dropping
        self.now_ns = self.now_ns.max(recv_ns);
        let mut events = self.give_up_expired_slots();

        if self.closed.contains(&slot) {
            self.stats.after_slot_done += 1;
            return events;
        }

        let state = self.slots.entry(slot).or_insert_with(|| SlotState {
            first_seen_ns: recv_ns,
            sets: BTreeMap::new(),
            next_set: 0,
            batcher: Batcher::new(),
        });
        state.first_seen_ns = state.first_seen_ns.min(recv_ns);
        if shred.fec_set_index < state.next_set {
            // its set was already decoded, the shred is no longer needed
            self.stats.after_decode += 1;
            return events;
        }

        let set = state
            .sets
            .entry(shred.fec_set_index)
            .or_insert_with(|| FecSet::new(slot, shred.fec_set_index));
        match set.push(shred) {
            Ok(true) => {}
            Ok(false) => {
                self.stats.duplicates += 1;
                return events;
            }
            Err(_) => {
                self.stats.rejected += 1;
                return events;
            }
        }

        events.extend(self.drain(slot, recv_ns));
        events
    }

    /// Hands every rebuildable set, in order, to the slot's batcher and decodes finished batches.
    fn drain(&mut self, slot: u64, now_ns: u64) -> Vec<Event> {
        let mut events = Vec::new();
        let mut slot_done = false;

        let Some(state) = self.slots.get_mut(&slot) else {
            return events;
        };

        while let Some(set) = state.sets.get_mut(&state.next_set) {
            if !set.can_recover() {
                break;
            }
            let Some(mut set) = state.sets.remove(&state.next_set) else {
                break;
            };
            state.next_set += DATA_SHREDS as u32;

            // counted before recover, which fills the missing data places
            let data_at_decode = set.data_received() as u64;
            if set.recover().is_err() {
                self.stats.sets_lost += 1;
                events.push(set_event(&set, data_at_decode, false));
                // later sets can't be decoded without this one's bytes
                slot_done = true;
                break;
            }
            self.stats.sets_decoded += 1;
            if set.recovered {
                self.stats.sets_recovered += 1;
            }
            events.push(set_event(&set, data_at_decode, true));

            let timing = Timing {
                fec_set_index: set.fec_set_index,
                first_shred_ns: set.first_seen_ns.unwrap_or(now_ns),
                decodable_ns: set.decodable_ns.unwrap_or(now_ns),
                decoded_ns: now_ns,
            };

            let Ok(shards) = set.data_shards() else {
                self.stats.sets_lost += 1;
                slot_done = true;
                break;
            };
            for shard in shards {
                let batch = match state.batcher.push(shard) {
                    Ok(Some(batch)) => batch,
                    Ok(None) => continue,
                    Err(_) => {
                        self.stats.decode_errors += 1;
                        continue;
                    }
                };
                self.stats.batches += 1;
                match decode_component(&batch) {
                    Ok(component) => {
                        push_events(&mut events, &mut self.stats, slot, component, timing)
                    }
                    Err(_) => self.stats.decode_errors += 1,
                }
                if is_last_in_slot(shard).unwrap_or(false) {
                    self.stats.slots_complete += 1;
                    slot_done = true;
                }
            }
            if slot_done {
                break;
            }
        }

        if slot_done {
            events.extend(self.close(slot));
        }
        events
    }

    /// Gives up on every slot whose deadline has passed on the capture clock.
    fn give_up_expired_slots(&mut self) -> Vec<Event> {
        let mut expired: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, state)| self.now_ns > state.first_seen_ns.saturating_add(self.give_up_ns))
            .map(|(slot, _)| *slot)
            .collect();
        // HashMap order changes from run to run, sorting keeps the output the same every time
        expired.sort_unstable();
        let mut events = Vec::new();
        for slot in expired {
            events.extend(self.close(slot));
        }
        events
    }

    /// Drops a slot's state. Every set it never decoded is counted and handed out as lost.
    fn close(&mut self, slot: u64) -> Vec<Event> {
        self.closed.insert(slot);
        // forget the oldest slots first, a junk slot number only takes one place
        while self.closed.len() > CLOSED_SLOTS_KEPT {
            self.closed.pop_first();
        }
        let Some(state) = self.slots.remove(&slot) else {
            return Vec::new();
        };
        self.stats.sets_lost += state.sets.len() as u64;
        state
            .sets
            .values()
            .map(|set| set_event(set, set.data_received() as u64, false))
            .collect()
    }

    /// End of input. Every set still waiting is given up on, and handed out as lost.
    pub fn finish(&mut self) -> Vec<Event> {
        let mut slots: Vec<u64> = self.slots.keys().copied().collect();
        slots.sort_unstable();
        let mut events = Vec::new();
        for slot in slots {
            events.extend(self.close(slot));
        }
        events
    }

    /// Counters so far.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

/// Parses a payload only if it is a whole shred of the right size for its kind.
fn parse_full_shred(payload: &[u8], recv_ns: u64) -> Option<Shred> {
    let shred = Shred::parse(payload, recv_ns).ok()?;
    let expected = match shred.variant.kind {
        Kind::Data => wire::DATA_PAYLOAD_SIZE,
        Kind::Code => wire::CODING_PAYLOAD_SIZE,
    };
    (payload.len() == expected).then_some(shred)
}

/// The Set event for a set, decoded or not.
fn set_event(set: &FecSet, data_at_decode: u64, decoded: bool) -> Event {
    Event::Set {
        slot: set.slot,
        fec_set_index: set.fec_set_index,
        first_shred_ns: set.first_seen_ns.unwrap_or(0),
        decodable_ns: set.decodable_ns,
        data_at_decode,
        recovered: set.recovered,
        decoded,
    }
}

/// One event per transaction (by first signature), or one for a marker.
fn push_events(
    events: &mut Vec<Event>,
    stats: &mut Stats,
    slot: u64,
    component: Component,
    timing: Timing,
) {
    match component {
        Component::Entries(entries) => {
            for entry in entries {
                for tx in entry.transactions {
                    if let Some(signature) = tx.signatures.first() {
                        stats.txs += 1;
                        events.push(Event::Tx {
                            slot,
                            signature: *signature,
                            timing,
                        });
                    }
                }
            }
        }
        Component::Marker { variant, data, .. } => {
            stats.markers += 1;
            events.push(Event::Marker {
                slot,
                variant,
                data,
                timing,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every shred of slot 449661788 in the order and at the times they reached the node,
    // taken from real-10s.pcap. Each record is recv_ns (u64), length (u16), then the shred.
    // 255 shreds, 128 data and 127 coding. getBlock reports 26 transactions.
    const ARRIVALS: &[u8] = include_bytes!("../tests/fixtures/real-slot-arrivals.bin");
    const SLOT: u64 = 449_661_788;

    // From getBlock 449661788 on the public testnet RPC.
    const FIRST_SIG: &str =
        "4AbpiMLynSZh6xhuKRvFVYWv56nAdgtiJ17kHMeTeHbjgAP4SQXxn6CBRzkF2TukHjAhaDappzuDgkZ9gXfmuNBu";
    const LAST_SIG: &str =
        "2Q6fhMTitpBvyP5WzzowF6EWCoQgRqh1tZxSi6rgBeaVxT3nGYHbMGgenT3tjXRw8ummmLmwkSdiT6JntDeJfL8Z";

    fn arrivals() -> Vec<(u64, &'static [u8])> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < ARRIVALS.len() {
            let recv_ns = u64::from_le_bytes(ARRIVALS[at..at + 8].try_into().unwrap());
            let len = usize::from(u16::from_le_bytes([ARRIVALS[at + 8], ARRIVALS[at + 9]]));
            out.push((recv_ns, &ARRIVALS[at + 10..at + 10 + len]));
            at += 10 + len;
        }
        out
    }

    fn is_data(shred: &[u8]) -> bool {
        matches!(shred[64] >> 4, 0x9 | 0xB)
    }

    fn run(packets: &[(u64, &[u8])]) -> (Assembler, Vec<Event>) {
        let mut asm = Assembler::new();
        let mut events = Vec::new();
        for (recv_ns, payload) in packets {
            events.extend(asm.push(payload, *recv_ns));
        }
        (asm, events)
    }

    fn signatures(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Tx { signature, .. } => Some(signature.to_string()),
                _ => None,
            })
            .collect()
    }

    fn marker_variants(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Marker { variant, .. } => Some(*variant),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_real_arrival_order() {
        let (asm, events) = run(&arrivals());
        let sigs = signatures(&events);
        assert_eq!(sigs.len(), 26);
        assert_eq!(sigs.first().unwrap(), FIRST_SIG);
        assert_eq!(sigs.last().unwrap(), LAST_SIG);
        // header first, footer near the end
        assert_eq!(marker_variants(&events), [1, 0]);

        let s = asm.stats();
        assert_eq!(s.packets, 255);
        assert_eq!(s.not_shreds, 0);
        assert_eq!(s.sets_decoded, 4);
        assert_eq!(s.slots_complete, 1);
        assert_eq!(s.batches, 4);
        assert_eq!(s.decode_errors, 0);
    }

    #[test]
    fn test_reverse_order() {
        // the last set completes first, nothing may decode until set 0 is in
        let mut packets = arrivals();
        packets.reverse();
        let (_, events) = run(&packets);
        let sigs = signatures(&events);
        assert_eq!(sigs.len(), 26);
        assert_eq!(sigs.first().unwrap(), FIRST_SIG);
        assert_eq!(sigs.last().unwrap(), LAST_SIG);
    }

    #[test]
    fn test_sets_wait_for_earlier_set() {
        // every shred except those of set 0, then set 0
        let packets = arrivals();
        let set0 = |p: &[u8]| wire::fec_set_index(p).unwrap() == 0;
        let (mut asm, events) = run(&packets
            .iter()
            .copied()
            .filter(|(_, p)| !set0(p))
            .collect::<Vec<_>>());
        assert!(events.is_empty());
        let mut late = Vec::new();
        for (t, p) in packets.iter().filter(|(_, p)| set0(p)) {
            late.extend(asm.push(p, *t));
        }
        assert_eq!(signatures(&late).len(), 26);
    }

    #[test]
    fn test_recovers_lost_data_shreds() {
        // drop 10 data shreds of set 32, the coding shreds rebuild them
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| {
                let index = wire::index(p).unwrap();
                !(is_data(p) && (40..50).contains(&index))
            })
            .collect();
        let (asm, events) = run(&packets);
        assert_eq!(signatures(&events).len(), 26);
        assert_eq!(asm.stats().sets_decoded, 4);
        assert_eq!(asm.stats().sets_lost, 0);
    }

    #[test]
    fn test_duplicates_and_junk() {
        let mut packets = Vec::new();
        for (t, p) in arrivals() {
            packets.push((t, p));
            packets.push((t + 1, p)); // every shred twice
        }
        let mut stray = vec![0u8; 1203];
        stray[64] = 0x19; // not a shred variant
        let cut = &arrivals()[0].1[..500]; // right variant, wrong size
        packets.insert(3, (0, &stray[..]));
        packets.insert(7, (0, cut));
        packets.insert(9, (0, &[][..]));

        let (asm, events) = run(&packets);
        assert_eq!(signatures(&events).len(), 26);
        let s = asm.stats();
        assert_eq!(s.not_shreds, 3);
        assert!(s.duplicates > 0);
        assert_eq!(s.rejected, 0);
    }

    #[test]
    fn test_timing() {
        let (_, events) = run(&arrivals());
        for e in &events {
            if let Event::Tx { timing, .. } | Event::Marker { timing, .. } = e {
                assert!(timing.first_shred_ns <= timing.decodable_ns);
                assert!(timing.decodable_ns <= timing.decoded_ns);
            }
        }
        // the header marker decodes from set 0 alone
        let Some(Event::Marker { timing, slot, .. }) =
            events.iter().find(|e| matches!(e, Event::Marker { .. }))
        else {
            panic!("expected a header marker");
        };
        assert_eq!(*slot, SLOT);
        assert_eq!(timing.fec_set_index, 0);
    }

    #[test]
    fn test_late_shreds_after_slot_done() {
        let packets = arrivals();
        let (mut asm, _) = run(&packets);
        assert!(asm.push(packets[0].1, 0).is_empty());
        assert!(asm.stats().after_slot_done > 0);
    }

    // a valid shred of some other slot arriving at `at_ns`, which moves the capture clock
    fn tick(asm: &mut Assembler, at_ns: u64) -> Vec<Event> {
        let mut other = arrivals()[0].1.to_vec();
        other[65..73].copy_from_slice(&(SLOT + 1_000).to_le_bytes());
        asm.push(&other, at_ns)
    }

    // half of set 0's data shreds, arriving at their real times
    fn half_set_0() -> Vec<(u64, &'static [u8])> {
        arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() == 0 && is_data(p))
            .take(16)
            .collect()
    }

    #[test]
    fn test_give_up_deadline_is_alpenglow_skip_timeout() {
        // 400 ms DELTA_TIMEOUT + 4 slots of 200 ms + 250 ms DELTA
        assert_eq!(Assembler::new().give_up_ns(), 1_450_000_000);
        // the deadline moves with the slot duration, 400 ms slots give 2.25 s
        assert_eq!(
            Assembler::with_slot_duration_ns(400_000_000).give_up_ns(),
            2_250_000_000
        );
    }

    #[test]
    fn test_old_slot_given_up() {
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let (mut asm, events) = run(&packets);
        assert!(events.is_empty());

        // just before the deadline the slot is still open
        tick(&mut asm, first + 1_440_000_000);
        assert_eq!(asm.stats().sets_lost, 0);

        // just after it, the slot is given up on
        tick(&mut asm, first + 1_460_000_000);
        assert_eq!(asm.stats().sets_lost, 1);

        // the old slot is closed now, more of its shreds only count as after_slot_done
        let before = asm.stats().after_slot_done;
        asm.push(packets[1].1, first + 1_470_000_000);
        assert_eq!(asm.stats().after_slot_done, before + 1);
    }

    #[test]
    fn test_longer_slots_wait_longer() {
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let mut asm = Assembler::with_slot_duration_ns(400_000_000);
        for (t, p) in &packets {
            asm.push(p, *t);
        }
        tick(&mut asm, first + 2_000_000_000);
        assert_eq!(asm.stats().sets_lost, 0);
        tick(&mut asm, first + 2_300_000_000);
        assert_eq!(asm.stats().sets_lost, 1);
    }

    #[test]
    fn test_junk_slot_does_not_block() {
        // a shred with an absurd slot number arrives first, the real slot must still decode
        let mut junk = arrivals()[0].1.to_vec();
        junk[65..73].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut packets = vec![(arrivals()[0].0, &junk[..])];
        packets.extend(arrivals());
        let (mut asm, events) = run(&packets);
        assert_eq!(signatures(&events).len(), 26);
        // the real slot is handled exactly as without the junk shred
        let (clean, _) = run(&arrivals());
        assert_eq!(asm.stats().after_slot_done, clean.stats().after_slot_done);
        assert_eq!(asm.stats().sets_decoded, clean.stats().sets_decoded);

        // the junk slot itself is given up on once its deadline passes
        let last = arrivals().iter().map(|(t, _)| *t).max().unwrap();
        let lost = tick(&mut asm, last + 1_500_000_000);
        assert!(lost.iter().any(|e| matches!(e, Event::Set { slot: u64::MAX, .. })));
    }

    #[test]
    fn test_reordered_packet_does_not_rewind_the_clock() {
        // a packet stamped earlier than the newest one must not reopen the deadline
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let (mut asm, _) = run(&packets);
        tick(&mut asm, first + 1_460_000_000);
        assert_eq!(asm.stats().sets_lost, 1);
        tick(&mut asm, first);
        assert_eq!(asm.stats().sets_lost, 1);
    }

    #[test]
    fn test_finish_counts_unfinished_sets() {
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() != 0)
            .collect();
        let (mut asm, events) = run(&packets);
        assert!(events.is_empty());
        asm.finish();
        assert_eq!(asm.stats().sets_lost, 3);
    }

    // Set events, one per FEC set, decoded or lost

    fn set_events(events: &[Event]) -> Vec<&Event> {
        events
            .iter()
            .filter(|e| matches!(e, Event::Set { .. }))
            .collect()
    }

    #[test]
    fn test_set_event_per_decoded_set() {
        let (asm, events) = run(&arrivals());
        let sets = set_events(&events);
        assert_eq!(sets.len(), 4);
        let mut indexes = Vec::new();
        for e in sets {
            let Event::Set {
                slot,
                fec_set_index,
                first_shred_ns,
                decodable_ns,
                data_at_decode,
                recovered,
                decoded,
            } = e
            else {
                unreachable!()
            };
            assert_eq!(*slot, SLOT);
            assert!(*decoded);
            assert!(decodable_ns.unwrap() >= *first_shred_ns);
            // Reed-Solomon runs exactly when some data shreds were missing at decode time
            assert_eq!(*recovered, *data_at_decode < 32);
            indexes.push(*fec_set_index);
        }
        assert_eq!(indexes, [0, 32, 64, 96]);
        assert_eq!(asm.stats().txs, 26);
        assert_eq!(asm.stats().markers, 2);
    }

    #[test]
    fn test_set_event_comes_before_its_transactions() {
        // a reader of the event stream learns about the set before what was decoded from it
        let (_, events) = run(&arrivals());
        let first_set = events.iter().position(|e| matches!(e, Event::Set { .. }));
        let first_other = events.iter().position(|e| !matches!(e, Event::Set { .. }));
        assert!(first_set.unwrap() < first_other.unwrap());
    }

    #[test]
    fn test_finish_emits_lost_sets() {
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() != 0)
            .collect();
        let (mut asm, _) = run(&packets);
        let lost = asm.finish();
        assert_eq!(lost.len(), 3);
        for e in lost {
            let Event::Set {
                decoded,
                decodable_ns,
                ..
            } = e
            else {
                panic!("finish should only hand out set events");
            };
            assert!(!decoded);
            // these sets had 32 shreds but waited behind set 0, which never came
            assert!(decodable_ns.is_some());
        }
    }

    #[test]
    fn test_finish_order_is_stable() {
        // lost sets from several slots come out by slot, then by set, on every run
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() != 0)
            .collect();
        let mut asm = Assembler::new();
        for offset in [5u64, 1, 9, 3] {
            for (t, p) in &packets {
                let mut shred = p.to_vec();
                shred[65..73].copy_from_slice(&(SLOT + offset).to_le_bytes());
                asm.push(&shred, *t);
            }
        }
        let order: Vec<(u64, u32)> = asm
            .finish()
            .iter()
            .filter_map(|e| match e {
                Event::Set {
                    slot,
                    fec_set_index,
                    ..
                } => Some((*slot, *fec_set_index)),
                _ => None,
            })
            .collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order.len(), 12);
        assert_eq!(order, sorted);
    }

    #[test]
    fn test_eviction_emits_lost_set() {
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let (mut asm, _) = run(&packets);
        let events = tick(&mut asm, first + 1_460_000_000);
        let lost = set_events(&events);
        assert_eq!(lost.len(), 1);
        let Event::Set {
            slot,
            decodable_ns,
            data_at_decode,
            decoded,
            ..
        } = lost[0]
        else {
            unreachable!()
        };
        assert_eq!(*slot, SLOT);
        assert!(!decoded);
        assert_eq!(*decodable_ns, None); // never reached 32 shreds
        assert_eq!(*data_at_decode, 16); // data shreds it held when given up on
    }

    // Real capture, runs only where the raw pcap is present (it is never committed)

    #[test]
    fn test_real_capture() {
        use crate::pcap::{PcapReader, udp_payload};
        let Ok(file) = std::fs::File::open("tests/fixtures/real-10s.pcap") else {
            return;
        };
        let mut reader = PcapReader::new(std::io::BufReader::new(file)).unwrap();
        let mut asm = Assembler::new();
        let mut txs = 0;
        while let Some(rec) = reader.next_record().unwrap() {
            if let Some(payload) = udp_payload(&rec.frame) {
                txs += signatures(&asm.push(payload, rec.recv_ns)).len();
            }
        }
        asm.finish();
        let s = asm.stats().clone();
        assert_eq!(s.packets, 15_907);
        assert_eq!(s.not_shreds, 1);
        assert_eq!(s.slots_complete, 45);
        assert_eq!(s.sets_decoded, 246);
        assert_eq!(s.decode_errors, 0);
        assert_eq!(txs, 2_394);
        assert_eq!(s.txs, 2_394);
    }
}

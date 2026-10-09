//! Turns a stream of shred packets into decoded transactions and block markers, with timing.
//!
//! push takes one packet, parses it and puts the shred into its FEC set.
//! A set decodes as soon as it has 32 shreds, the earliest moment the data can be known.
//! Sets go to the slot's Batcher strictly in order, because a batch can start in one set and end in the next.
//! Each finished batch is decoded and handed out as events, one per transaction or marker.
//! A slot closes when its last shred is decoded, or when it falls too far behind the newest slot.
//! Every event carries t0 (first shred of the set), t1 (32nd shred) and t2 (the batch could decode).

use crate::block::{Batcher, Component, decode_component, is_last_in_slot};
use crate::fec::{DATA_SHREDS, FecSet};
use crate::shred::{Kind, Shred};
use crate::wire;
use solana_transaction::Signature;
use std::collections::{BTreeMap, HashMap};

/// Slots this far behind the newest slot seen are given up on, and their unfinished sets counted as lost.
pub const MAX_SLOTS_IN_FLIGHT: u64 = 32;

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
}

/// Shred health counters for the report.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub packets: u64,
    /// Packets that are not a shred we can read, like the wrong size or an unknown variant.
    pub not_shreds: u64,
    pub duplicates: u64,
    /// Shreds for a slot already finished, given up on, or too far behind the newest slot.
    pub late: u64,
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
}

/// Everything in flight for one slot.
#[derive(Default)]
struct SlotState {
    sets: BTreeMap<u32, FecSet>,
    /// fec_set_index of the next set to hand to the batcher, sets must go in order
    /// because a batch can start in one set and end in the next.
    next_set: u32,
    batcher: Batcher,
}

#[derive(Default)]
pub struct Assembler {
    slots: HashMap<u64, SlotState>,
    /// Slots finished or given up on, so their late shreds are counted and not reopened.
    closed: BTreeMap<u64, ()>,
    newest_slot: u64,
    stats: Stats,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds one UDP payload. Returns whatever this packet made decodable.
    pub fn push(&mut self, payload: &[u8], recv_ns: u64) -> Vec<Event> {
        self.stats.packets += 1;

        let Some(shred) = parse_full_shred(payload, recv_ns) else {
            self.stats.not_shreds += 1;
            return Vec::new();
        };
        let slot = shred.slot;

        let too_old = slot < self.newest_slot.saturating_sub(MAX_SLOTS_IN_FLIGHT);
        if too_old || self.closed.contains_key(&slot) {
            self.stats.late += 1;
            return Vec::new();
        }

        if slot > self.newest_slot {
            self.newest_slot = slot;
            self.evict_old_slots();
        }

        let state = self.slots.entry(slot).or_default();
        if shred.fec_set_index < state.next_set {
            // its set was already decoded, the shred is no longer needed
            self.stats.after_decode += 1;
            return Vec::new();
        }

        let set = state
            .sets
            .entry(shred.fec_set_index)
            .or_insert_with(|| FecSet::new(slot, shred.fec_set_index));
        match set.push(shred) {
            Ok(true) => {}
            Ok(false) => {
                self.stats.duplicates += 1;
                return Vec::new();
            }
            Err(_) => {
                self.stats.rejected += 1;
                return Vec::new();
            }
        }

        self.drain(slot, recv_ns)
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

            if set.recover().is_err() {
                self.stats.sets_lost += 1;
                // later sets can't be decoded without this one's bytes
                slot_done = true;
                break;
            }
            self.stats.sets_decoded += 1;
            if set.recovered {
                self.stats.sets_recovered += 1;
            }

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
                    Ok(component) => push_events(&mut events, slot, component, timing),
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
            self.close(slot);
        }
        events
    }

    /// Gives up on slots too far behind the newest one.
    fn evict_old_slots(&mut self) {
        let cutoff = self.newest_slot.saturating_sub(MAX_SLOTS_IN_FLIGHT);
        let old: Vec<u64> = self.slots.keys().copied().filter(|s| *s < cutoff).collect();
        for slot in old {
            self.close(slot);
        }
        // slots below the cutoff are refused as too old anyway, so the list stays short
        self.closed = self.closed.split_off(&cutoff);
    }

    /// Drops a slot's state, counting any set it never decoded as lost.
    fn close(&mut self, slot: u64) {
        if let Some(state) = self.slots.remove(&slot) {
            self.stats.sets_lost += state.sets.len() as u64;
        }
        self.closed.insert(slot, ());
    }

    /// End of input. Every set still waiting is counted as lost.
    pub fn finish(&mut self) -> &Stats {
        let slots: Vec<u64> = self.slots.keys().copied().collect();
        for slot in slots {
            self.close(slot);
        }
        &self.stats
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

/// One event per transaction (by first signature), or one for a marker.
fn push_events(events: &mut Vec<Event>, slot: u64, component: Component, timing: Timing) {
    match component {
        Component::Entries(entries) => {
            for entry in entries {
                for tx in entry.transactions {
                    if let Some(signature) = tx.signatures.first() {
                        events.push(Event::Tx {
                            slot,
                            signature: *signature,
                            timing,
                        });
                    }
                }
            }
        }
        Component::Marker { variant, data, .. } => events.push(Event::Marker {
            slot,
            variant,
            data,
            timing,
        }),
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
                Event::Marker { .. } => None,
            })
            .collect()
    }

    fn marker_variants(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Marker { variant, .. } => Some(*variant),
                Event::Tx { .. } => None,
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
            let (Event::Tx { timing, .. } | Event::Marker { timing, .. }) = e;
            assert!(timing.first_shred_ns <= timing.decodable_ns);
            assert!(timing.decodable_ns <= timing.decoded_ns);
        }
        // the header marker decodes from set 0 alone
        let Event::Marker { timing, slot, .. } = &events[0] else {
            panic!("first event should be the header marker");
        };
        assert_eq!(*slot, SLOT);
        assert_eq!(timing.fec_set_index, 0);
    }

    #[test]
    fn test_late_shreds_after_slot_done() {
        let packets = arrivals();
        let (mut asm, _) = run(&packets);
        assert!(asm.push(packets[0].1, 0).is_empty());
        assert!(asm.stats().late > 0);
    }

    #[test]
    fn test_old_slot_given_up() {
        // only half of set 0 arrives, then a much newer slot shows up
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() == 0 && is_data(p))
            .take(16)
            .collect();
        let (mut asm, events) = run(&packets);
        assert!(events.is_empty());

        let mut newer = packets[0].1.to_vec();
        newer[65..73].copy_from_slice(&(SLOT + MAX_SLOTS_IN_FLIGHT + 1).to_le_bytes());
        asm.push(&newer, 0);
        assert_eq!(asm.stats().sets_lost, 1);

        // the old slot is closed now, more of its shreds only count as late
        let late_before = asm.stats().late;
        asm.push(packets[1].1, 0);
        assert_eq!(asm.stats().late, late_before + 1);
    }

    #[test]
    fn test_finish_counts_unfinished_sets() {
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() != 0)
            .collect();
        let (mut asm, events) = run(&packets);
        assert!(events.is_empty());
        assert_eq!(asm.finish().sets_lost, 3);
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
        let s = asm.finish().clone();
        assert_eq!(s.packets, 15_907);
        assert_eq!(s.not_shreds, 1);
        assert_eq!(s.slots_complete, 45);
        assert_eq!(s.sets_decoded, 246);
        assert_eq!(s.decode_errors, 0);
        assert_eq!(txs, 2_394);
    }
}

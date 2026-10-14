//! Sums up the last minute of decoding every few seconds, worked out once on the node.
//!
//! Rollups::add sees every event the assembler hands out. Per slot it adds up data shreds,
//! the ones that never arrived, transactions and the rebuilt ones. Per set it keeps how long the set took to fill, first shred to 32nd.
//! Rollups::tick runs after every packet, and reads the capture's drops only when a rollup is due. Every EVERY_NS on the capture clock it forgets what is
//! older than WINDOW_NS and returns one Rollup, with the field names of the event contract.
//! A slot counts at its first shred, so a slot that closed late still falls in its own minute.
//! Slot numbers missing between the lowest and highest one in the window never came.

use std::collections::{HashMap, VecDeque};

use serde::Serialize;

use crate::assembler::{Event, SlotEnd, Stats};
use crate::fec::DATA_SHREDS;
use crate::pcap::Drops;
use crate::record::Published;

/// How far back a rollup looks.
pub const WINDOW_NS: u64 = 60_000_000_000;
/// How often a rollup is made.
pub const EVERY_NS: u64 = 5_000_000_000;

/// One summary of the last minute.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Rollup {
    /// Capture time the rollup was made.
    pub at_ns: u64,
    pub window_s: u64,
    /// Packets a second since the rollup before.
    pub packets_per_s: u64,
    /// Lost by the kernel since the capture opened, null from a file.
    pub kernel_drops: Option<u32>,
    pub slots_closed: u32,
    /// Slot numbers in the window that had no shred at all.
    pub slots_never_came: u32,
    /// Of the data shreds in complete slots, the share that never arrived.
    pub data_shreds_missing_pct: f64,
    /// First shred to 32nd over the sets in the window, null when there are none.
    pub set_fill_ms: Option<Fill>,
    /// Of the transactions in complete slots, the share holding bytes that never arrived.
    pub txs_rebuilt_pct: f64,
    /// Since the start, shreds dropped by the Merkle and leader checks.
    pub bad_proof: u64,
    pub bad_signature: u64,
    /// Messages the publisher dropped or lost since the start, null when nothing publishes.
    pub events_dropped: Option<u64>,
    /// Longest wait from queue to the server over the last 5 s, null when nothing went out.
    pub publish_lag_ms: Option<f64>,
}

/// Nearest rank percentiles, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Fill {
    pub p50: f64,
    pub p99: f64,
}

/// One closed slot, as the window keeps it.
#[derive(Default, Clone, Copy)]
struct SlotSample {
    slot: u64,
    at_ns: u64,
    complete: bool,
    data_shreds: u64,
    data_missing: u64,
    txs: u64,
    txs_rebuilt: u64,
}

/// Collects events and makes a Rollup every EVERY_NS.
#[derive(Default)]
pub struct Rollups {
    /// Slots whose events are still coming, their Slot event closes them.
    open: HashMap<u64, SlotSample>,
    slots: VecDeque<SlotSample>,
    /// When each set's first shred came, and how long it took to fill.
    fills: VecDeque<(u64, u64)>,
    next_at_ns: Option<u64>,
    /// Packets and time at the rollup before, for the packet rate.
    last_packets: u64,
    last_at_ns: u64,
}

impl Rollups {
    /// Takes one event, in the order the assembler hands them out.
    pub fn add(&mut self, event: &Event) {
        match event {
            Event::Set {
                slot,
                first_shred_ns,
                decodable_ns,
                rebuilt,
                decoded: true,
                ..
            } => {
                let s = self.open.entry(*slot).or_default();
                s.data_shreds += DATA_SHREDS as u64;
                s.data_missing += rebuilt.len() as u64;
                if let Some(t1) = decodable_ns {
                    self.fills
                        .push_back((*first_shred_ns, t1.saturating_sub(*first_shred_ns)));
                }
            }
            Event::Tx { slot, rebuilt, .. } => {
                let s = self.open.entry(*slot).or_default();
                s.txs += 1;
                s.txs_rebuilt += u64::from(*rebuilt);
            }
            Event::Slot {
                slot,
                first_shred_ns,
                end,
                ..
            } => {
                let mut s = self.open.remove(slot).unwrap_or_default();
                s.slot = *slot;
                s.at_ns = *first_shred_ns;
                s.complete = *end == SlotEnd::Complete;
                self.slots.push_back(s);
            }
            _ => {}
        }
    }

    /// Runs after every packet. Returns a Rollup once every EVERY_NS of capture time.
    /// drops and published are only called then, so the counters are not read for every packet.
    pub fn tick(
        &mut self,
        now_ns: u64,
        stats: &Stats,
        drops: impl FnOnce() -> Option<Drops>,
        published: impl FnOnce() -> Option<Published>,
    ) -> Option<Rollup> {
        let Some(mut next) = self.next_at_ns else {
            // the first packet starts the clock
            self.next_at_ns = Some(now_ns.saturating_add(EVERY_NS));
            self.last_packets = stats.packets;
            self.last_at_ns = now_ns;
            return None;
        };
        if now_ns < next {
            return None;
        }
        // after a gap with no packets, the next rollup is still a whole step ahead
        while next <= now_ns {
            next = next.saturating_add(EVERY_NS);
        }
        self.next_at_ns = Some(next);

        let since = now_ns.saturating_sub(WINDOW_NS);
        while self.slots.front().is_some_and(|s| s.at_ns < since) {
            self.slots.pop_front();
        }
        while self.fills.front().is_some_and(|(at, _)| *at < since) {
            self.fills.pop_front();
        }

        let elapsed = now_ns.saturating_sub(self.last_at_ns).max(1);
        let packets = stats.packets.saturating_sub(self.last_packets);
        self.last_packets = stats.packets;
        self.last_at_ns = now_ns;

        let complete = || self.slots.iter().filter(|s| s.complete);
        let data_shreds = complete().map(|s| s.data_shreds).sum();
        let data_missing = complete().map(|s| s.data_missing).sum();
        let txs = complete().map(|s| s.txs).sum();
        let txs_rebuilt = complete().map(|s| s.txs_rebuilt).sum();
        let mut fills: Vec<u64> = self.fills.iter().map(|(_, fill)| *fill).collect();
        fills.sort_unstable();

        let published = published();
        Some(Rollup {
            at_ns: now_ns,
            window_s: WINDOW_NS / 1_000_000_000,
            packets_per_s: (u128::from(packets) * 1_000_000_000 / u128::from(elapsed)) as u64,
            kernel_drops: drops().map(|d| d.kernel),
            slots_closed: self.slots.len() as u32,
            slots_never_came: self.never_came(),
            data_shreds_missing_pct: percent(data_missing, data_shreds),
            set_fill_ms: (!fills.is_empty()).then(|| Fill {
                p50: ms(rank(&fills, 50)),
                p99: ms(rank(&fills, 99)),
            }),
            txs_rebuilt_pct: percent(txs_rebuilt, txs),
            bad_proof: stats.bad_proof,
            bad_signature: stats.bad_signature,
            events_dropped: published.map(|p| p.dropped),
            publish_lag_ms: published.and_then(|p| p.lag_ns).map(ms),
        })
    }

    /// Slot numbers between the lowest and the highest closed slot in the window that never closed.
    fn never_came(&self) -> u32 {
        let (Some(low), Some(high)) = (
            self.slots.iter().map(|s| s.slot).min(),
            self.slots.iter().map(|s| s.slot).max(),
        ) else {
            return 0;
        };
        let span = high - low + 1;
        let mut seen: Vec<u64> = self.slots.iter().map(|s| s.slot).collect();
        seen.sort_unstable();
        seen.dedup();
        (span - seen.len() as u64) as u32
    }
}

/// Nearest rank, the smallest value with at least q percent at or below it.
fn rank(sorted: &[u64], q: usize) -> u64 {
    let i = (q * sorted.len()).div_ceil(100).max(1) - 1;
    sorted.get(i).copied().unwrap_or_default()
}

/// Two decimals are enough for a page.
fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    (part as f64 * 10_000.0 / whole as f64).round() / 100.0
}

fn ms(ns: u64) -> f64 {
    (ns as f64 / 10_000.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::Timing;
    use solana_transaction::Signature;

    const S: u64 = 1_000_000_000;
    const MS: u64 = 1_000_000;

    fn set(slot: u64, at: u64, fill: u64, rebuilt: &[u8]) -> Event {
        Event::Set {
            slot,
            fec_set_index: 0,
            first_shred_ns: at,
            decodable_ns: Some(at + fill),
            data_at_decode: 16,
            rebuilt: rebuilt.to_vec(),
            decoded: true,
        }
    }

    fn tx(slot: u64, rebuilt: bool) -> Event {
        Event::Tx {
            slot,
            signature: Signature::default(),
            timing: Timing {
                fec_set_index: 0,
                first_shred_ns: 0,
                decodable_ns: 0,
                decoded_ns: 0,
            },
            rebuilt,
        }
    }

    fn slot(slot: u64, at: u64) -> Event {
        Event::Slot {
            slot,
            leader: None,
            first_shred_ns: at,
            done_ns: Some(at + 250 * MS),
            sets_decoded: 1,
            sets_lost: 0,
            txs: 0,
            late_data: 0,
            footer: None,
            end: SlotEnd::Complete,
        }
    }

    fn packets(n: u64) -> Stats {
        Stats {
            packets: n,
            ..Stats::default()
        }
    }

    #[test]
    fn test_every_five_seconds_on_the_capture_clock() {
        let mut r = Rollups::default();
        assert!(r.tick(100 * S, &packets(0), || None, || None).is_none()); // starts the clock
        assert!(r.tick(104 * S, &packets(0), || None, || None).is_none());
        let first = r.tick(105 * S, &packets(6_750), || None, || None).unwrap();
        assert_eq!(first.at_ns, 105 * S);
        assert_eq!(first.packets_per_s, 1_350);
        assert!(r.tick(109 * S, &packets(0), || None, || None).is_none());
        // a gap of 20 s gives one rollup, and the next one is a whole step later
        assert!(r.tick(130 * S, &packets(0), || None, || None).is_some());
        assert!(r.tick(134 * S, &packets(0), || None, || None).is_none());
        assert!(r.tick(135 * S, &packets(0), || None, || None).is_some());
    }

    #[test]
    fn test_numbers_over_the_window() {
        let mut r = Rollups::default();
        r.tick(100 * S, &packets(0), || None, || None);
        // slot 10 lost 2 of 32 data shreds and 1 of its 2 txs holds rebuilt bytes.
        // slot 11 never came. slot 12 lost nothing
        for e in [
            set(10, 100 * S, 60 * MS, &[3, 9]),
            tx(10, true),
            tx(10, false),
            slot(10, 100 * S),
            set(12, 101 * S, 100 * MS, &[]),
            tx(12, false),
            slot(12, 101 * S),
        ] {
            r.add(&e);
        }
        let stats = Stats {
            bad_proof: 2,
            ..packets(0)
        };
        let drops = Drops {
            kernel: 3,
            interface: 1,
        };
        let published = Published {
            dropped: 4,
            lag_ns: Some(3_214_000),
        };
        let roll = r
            .tick(105 * S, &stats, || Some(drops), || Some(published))
            .unwrap();
        assert_eq!((roll.slots_closed, roll.slots_never_came), (2, 1));
        assert_eq!(roll.data_shreds_missing_pct, 3.13);
        assert_eq!(roll.txs_rebuilt_pct, 33.33);
        assert_eq!(
            roll.set_fill_ms,
            Some(Fill {
                p50: 60.0,
                p99: 100.0
            })
        );
        assert_eq!(roll.kernel_drops, Some(3));
        assert_eq!(roll.bad_proof, 2);
        assert_eq!(roll.events_dropped, Some(4));
        assert_eq!(roll.publish_lag_ms, Some(3.21));
    }

    #[test]
    fn test_old_slots_leave_the_window() {
        let mut r = Rollups::default();
        r.tick(100 * S, &packets(0), || None, || None);
        r.add(&set(1, 100 * S, 60 * MS, &[]));
        r.add(&slot(1, 100 * S));
        assert_eq!(
            r.tick(105 * S, &packets(0), || None, || None)
                .unwrap()
                .slots_closed,
            1
        );
        // 61 s on, the slot and its set are older than the window
        let roll = r.tick(161 * S, &packets(0), || None, || None).unwrap();
        assert_eq!(roll.slots_closed, 0);
        assert_eq!(roll.set_fill_ms, None);
        assert_eq!(roll.data_shreds_missing_pct, 0.0);
        // nothing publishes, so there is nothing to report
        assert_eq!((roll.events_dropped, roll.publish_lag_ms), (None, None));
    }
}

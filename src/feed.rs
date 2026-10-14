//! The compact public feed, what a public page may read, bounded to about 2 KB a second.
//!
//! Feed::add sees every event and hands out one Summary when a slot closes: its leader,
//! when its first shred came and its last batch decoded, how many transactions and missing
//! data shreds it had, how it ended, whether the finalization its footer carries took one round, and a sample of its first SAMPLE_TXS
//! transaction signatures. Public carries a Summary or a Rollup, each tagged with its kind.
//! Every transaction, set and marker, and anything else, stays private on the node.

use std::collections::HashMap;

use serde::Serialize;

use crate::assembler::Event;
use crate::record::base58;
use crate::rollup::Rollup;

/// Transaction signatures a slot summary carries, the rest are only counted.
pub const SAMPLE_TXS: usize = 2;

/// One message of the public feed.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Public {
    Summary(Summary),
    Stats(Rollup),
}

/// One closed slot, small enough to send for every slot.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Summary {
    pub v: u8,
    pub slot: u64,
    /// base58, null without a leader schedule.
    pub leader: Option<String>,
    pub first_shred_ns: u64,
    /// When the last batch decoded, null if nothing decoded.
    pub done_ns: Option<u64>,
    pub txs: u64,
    /// Data shreds that never arrived, so their bytes were rebuilt.
    pub data_missing: u64,
    pub end: &'static str,
    /// Whether the finalization certificate in the footer took one round, null without one.
    pub fast_final: Option<bool>,
    pub sample: Vec<SampleTx>,
}

/// One sampled transaction.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SampleTx {
    pub sig: String,
    /// Its bytes held a data shred that never arrived.
    pub rebuilt: bool,
}

/// What a slot has gathered before it closes.
#[derive(Default)]
struct Open {
    data_missing: u64,
    sample: Vec<SampleTx>,
}

/// Turns events into slot summaries.
#[derive(Default)]
pub struct Feed {
    open: HashMap<u64, Open>,
}

impl Feed {
    /// Takes one event, and hands out the slot's summary when the slot closes.
    pub fn add(&mut self, event: &Event) -> Option<Summary> {
        match event {
            Event::Set {
                slot,
                rebuilt,
                decoded: true,
                ..
            } => {
                self.open.entry(*slot).or_default().data_missing += rebuilt.len() as u64;
                None
            }
            Event::Tx {
                slot,
                signature,
                rebuilt,
                ..
            } => {
                let open = self.open.entry(*slot).or_default();
                if open.sample.len() < SAMPLE_TXS {
                    open.sample.push(SampleTx {
                        sig: signature.to_string(),
                        rebuilt: *rebuilt,
                    });
                }
                None
            }
            Event::Slot {
                slot,
                leader,
                first_shred_ns,
                done_ns,
                txs,
                footer,
                end,
                ..
            } => {
                let open = self.open.remove(slot).unwrap_or_default();
                Some(Summary {
                    v: 1,
                    slot: *slot,
                    leader: leader.map(base58),
                    first_shred_ns: *first_shred_ns,
                    done_ns: *done_ns,
                    txs: *txs,
                    data_missing: open.data_missing,
                    end: end.as_str(),
                    fast_final: footer
                        .as_ref()
                        .and_then(|f| f.final_cert.as_ref())
                        .map(|c| c.fast),
                    sample: open.sample,
                })
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::{Assembler, SlotEnd, Timing};
    use solana_transaction::Signature;
    use std::str::FromStr;

    // a real 88 character signature, the longest base58 form
    const SIG: &str =
        "4AbpiMLynSZh6xhuKRvFVYWv56nAdgtiJ17kHMeTeHbjgAP4SQXxn6CBRzkF2TukHjAhaDappzuDgkZ9gXfmuNBu";
    const MS: u64 = 1_000_000;

    fn tx(slot: u64, rebuilt: bool) -> Event {
        Event::Tx {
            slot,
            signature: Signature::from_str(SIG).unwrap(),
            timing: Timing {
                fec_set_index: 0,
                first_shred_ns: 0,
                decodable_ns: 0,
                decoded_ns: 0,
            },
            rebuilt,
        }
    }

    fn set(slot: u64, rebuilt: &[u8]) -> Event {
        Event::Set {
            slot,
            fec_set_index: 0,
            first_shred_ns: 0,
            decodable_ns: Some(60 * MS),
            data_at_decode: 16,
            rebuilt: rebuilt.to_vec(),
            decoded: true,
        }
    }

    fn slot(slot: u64, txs: u64) -> Event {
        Event::Slot {
            slot,
            leader: Some([7; 32]),
            first_shred_ns: 1_000 * MS,
            done_ns: Some(1_261 * MS),
            sets_decoded: 2,
            sets_lost: 0,
            txs,
            late_data: 0,
            footer: None,
            end: SlotEnd::Complete,
        }
    }

    #[test]
    fn test_summary_of_a_slot() {
        let mut feed = Feed::default();
        assert_eq!(feed.add(&set(5, &[1, 2])), None);
        assert_eq!(feed.add(&set(5, &[])), None);
        // five transactions, only the first two are sampled
        for rebuilt in [true, false, false, false, false] {
            assert_eq!(feed.add(&tx(5, rebuilt)), None);
        }
        let s = feed.add(&slot(5, 5)).unwrap();
        assert_eq!((s.slot, s.txs, s.data_missing), (5, 5, 2));
        assert_eq!(s.done_ns, Some(1_261 * MS));
        assert_eq!(s.end, "complete");
        assert_eq!(s.leader.as_deref(), Some(base58([7; 32]).as_str()));
        assert_eq!(s.sample.len(), SAMPLE_TXS);
        assert!(s.sample[0].rebuilt && !s.sample[1].rebuilt);
        // the slot is forgotten once it closed
        assert!(feed.open.is_empty());
    }

    #[test]
    fn test_messages_stay_small() {
        // the longest summary: a leader, two 88 character signatures, every field set
        let mut feed = Feed::default();
        for _ in 0..10 {
            feed.add(&tx(9, true));
        }
        let s = feed.add(&slot(9, 10)).unwrap();
        let line = serde_json::to_string(&Public::Summary(s)).unwrap();
        assert!(
            line.starts_with(r#"{"kind":"summary","v":1,"slot":9,"#),
            "{line}"
        );
        assert!(line.len() < 500, "{} bytes: {line}", line.len());
    }

    #[test]
    fn test_real_capture_fits_the_budget() {
        // the public feed of the 10 s capture, about 2 KB a second
        use crate::pcap::{PacketSource, PcapReader, udp_payload};
        use crate::rollup::Rollups;
        let Ok(file) = std::fs::File::open("tests/fixtures/real-10s.pcap") else {
            return;
        };
        let mut reader = PcapReader::new(std::io::BufReader::new(file)).unwrap();
        let (mut asm, mut feed, mut rollups) =
            (Assembler::new(), Feed::default(), Rollups::default());
        let (mut bytes, mut first, mut last) = (0, None, 0);
        let size = |msg: Public| serde_json::to_string(&msg).unwrap().len() + 1;
        while let Some(rec) = reader.next_record().unwrap() {
            first.get_or_insert(rec.recv_ns);
            last = rec.recv_ns;
            if let Some(payload) = udp_payload(&rec.frame) {
                for event in asm.push(payload, rec.recv_ns) {
                    rollups.add(&event);
                    if let Some(s) = feed.add(&event) {
                        bytes += size(Public::Summary(s));
                    }
                }
            }
            if let Some(r) = rollups.tick(rec.recv_ns, asm.stats(), || None) {
                bytes += size(Public::Stats(r));
            }
        }
        let seconds = (last - first.unwrap()) as f64 / 1e9;
        let per_second = bytes as f64 / seconds;
        assert!(per_second < 2_200.0, "{per_second:.0} bytes a second");
    }
}

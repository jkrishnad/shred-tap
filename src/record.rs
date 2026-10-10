//! Writes the assembler's events as JSON lines, one file per kind, and the run's totals as a summary.
//!
//! Every event becomes one small record, a flat struct whose fields serde writes in order.
//! Transactions go to tx.jsonl, block markers to markers.jsonl, FEC sets to sets.jsonl
//! and one line per slot to slots.jsonl.
//! Output is generic over the writer, files on disk for a real run and Vec<u8> in tests.
//! write_summary writes the Stats once at the end as pretty JSON.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::Serialize;

use crate::assembler::{Event, SlotEnd, Stats, Timing};
use crate::error::Result;

/// One line of tx.jsonl, keyed by the transaction's first signature.
#[derive(Serialize)]
struct TxRecord {
    slot: u64,
    sig: String,
    fec_set: u32,
    t0_ns: u64,
    t1_ns: u64,
    t2_ns: u64,
}

/// One line of markers.jsonl. The marker bytes are not written, only their length.
#[derive(Serialize)]
struct MarkerRecord {
    slot: u64,
    variant: u8,
    len: usize,
    fec_set: u32,
    t0_ns: u64,
    t1_ns: u64,
    t2_ns: u64,
}

/// One line of sets.jsonl. t1_ns is null for a set that never reached 32 shreds.
#[derive(Serialize)]
struct SetRecord {
    slot: u64,
    fec_set: u32,
    t0_ns: u64,
    t1_ns: Option<u64>,
    data_at_decode: u64,
    recovered: bool,
    decoded: bool,
}

/// One line of slots.jsonl, written when the slot closes.
#[derive(Serialize)]
struct SlotRecord {
    slot: u64,
    first_shred_ns: u64,
    /// When the last batch decoded, null if nothing did.
    done_ns: Option<u64>,
    sets_decoded: u32,
    sets_lost: u32,
    txs: u64,
    footer: bool,
    end: &'static str,
}

/// Where events are written. W is any writer, files on disk or a Vec<u8> in tests.
pub struct Output<W> {
    pub tx: W,
    pub markers: W,
    pub sets: W,
    pub slots: W,
}

impl<W: Write> Output<W> {
    pub fn new(tx: W, markers: W, sets: W, slots: W) -> Self {
        Self {
            tx,
            markers,
            sets,
            slots,
        }
    }

    /// Writes one event as one line in the file for its kind.
    pub fn write(&mut self, event: &Event) -> Result<()> {
        match event {
            Event::Tx {
                slot,
                signature,
                timing,
            } => {
                let Timing {
                    fec_set_index,
                    first_shred_ns,
                    decodable_ns,
                    decoded_ns,
                } = *timing;
                let record = TxRecord {
                    slot: *slot,
                    sig: signature.to_string(),
                    fec_set: fec_set_index,
                    t0_ns: first_shred_ns,
                    t1_ns: decodable_ns,
                    t2_ns: decoded_ns,
                };
                write_line(&mut self.tx, &record)
            }
            Event::Marker {
                slot,
                variant,
                data,
                timing,
            } => {
                let record = MarkerRecord {
                    slot: *slot,
                    variant: *variant,
                    len: data.len(),
                    fec_set: timing.fec_set_index,
                    t0_ns: timing.first_shred_ns,
                    t1_ns: timing.decodable_ns,
                    t2_ns: timing.decoded_ns,
                };
                write_line(&mut self.markers, &record)
            }
            Event::Set {
                slot,
                fec_set_index,
                first_shred_ns,
                decodable_ns,
                data_at_decode,
                recovered,
                decoded,
            } => {
                let record = SetRecord {
                    slot: *slot,
                    fec_set: *fec_set_index,
                    t0_ns: *first_shred_ns,
                    t1_ns: *decodable_ns,
                    data_at_decode: *data_at_decode,
                    recovered: *recovered,
                    decoded: *decoded,
                };
                write_line(&mut self.sets, &record)
            }
            Event::Slot {
                slot,
                first_shred_ns,
                done_ns,
                sets_decoded,
                sets_lost,
                txs,
                footer,
                end,
            } => {
                let record = SlotRecord {
                    slot: *slot,
                    first_shred_ns: *first_shred_ns,
                    done_ns: *done_ns,
                    sets_decoded: *sets_decoded,
                    sets_lost: *sets_lost,
                    txs: *txs,
                    footer: *footer,
                    end: match end {
                        SlotEnd::Complete => "complete",
                        SlotEnd::GivenUp => "given_up",
                        SlotEnd::EndOfInput => "end_of_input",
                    },
                };
                write_line(&mut self.slots, &record)
            }
        }
    }

    /// Pushes buffered lines out to the writers.
    pub fn flush(&mut self) -> Result<()> {
        self.tx.flush()?;
        self.markers.flush()?;
        self.sets.flush()?;
        self.slots.flush()?;
        Ok(())
    }
}

/// Files on disk, the one concrete writer a real run uses.
impl Output<BufWriter<File>> {
    /// Creates the folder if needed and the four files inside it, replacing old ones.
    pub fn create(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let open = |name: &str| -> Result<BufWriter<File>> {
            Ok(BufWriter::new(File::create(dir.join(name))?))
        };
        Ok(Self::new(
            open("tx.jsonl")?,
            open("markers.jsonl")?,
            open("sets.jsonl")?,
            open("slots.jsonl")?,
        ))
    }
}

/// Writes the run's totals as pretty JSON.
pub fn write_summary(mut w: impl Write, stats: &Stats) -> Result<()> {
    serde_json::to_writer_pretty(&mut w, stats)?;
    w.write_all(b"\n")?;
    Ok(())
}

/// One record as one JSON line.
fn write_line(w: &mut impl Write, record: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *w, record)?;
    w.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembler::{Event, Stats, Timing};
    use solana_transaction::Signature;
    use std::str::FromStr;

    const SIG: &str =
        "4AbpiMLynSZh6xhuKRvFVYWv56nAdgtiJ17kHMeTeHbjgAP4SQXxn6CBRzkF2TukHjAhaDappzuDgkZ9gXfmuNBu";

    fn timing() -> Timing {
        Timing {
            fec_set_index: 32,
            first_shred_ns: 100,
            decodable_ns: 150,
            decoded_ns: 160,
        }
    }

    fn memory_output() -> Output<Vec<u8>> {
        Output::new(Vec::new(), Vec::new(), Vec::new(), Vec::new())
    }

    fn lines(buf: &[u8]) -> Vec<String> {
        String::from_utf8(buf.to_vec())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn test_tx_line() {
        let mut out = memory_output();
        out.write(&Event::Tx {
            slot: 449_661_788,
            signature: Signature::from_str(SIG).unwrap(),
            timing: timing(),
        })
        .unwrap();
        assert_eq!(
            lines(&out.tx),
            [format!(
                r#"{{"slot":449661788,"sig":"{SIG}","fec_set":32,"t0_ns":100,"t1_ns":150,"t2_ns":160}}"#
            )]
        );
        assert!(out.markers.is_empty());
        assert!(out.sets.is_empty());
    }

    #[test]
    fn test_marker_line() {
        // the marker data itself is not written yet, only what it is and when it came
        let mut out = memory_output();
        out.write(&Event::Marker {
            slot: 449_661_788,
            variant: 0,
            data: vec![0u8; 670],
            timing: timing(),
        })
        .unwrap();
        assert_eq!(
            lines(&out.markers),
            [
                r#"{"slot":449661788,"variant":0,"len":670,"fec_set":32,"t0_ns":100,"t1_ns":150,"t2_ns":160}"#
            ]
        );
        assert!(out.tx.is_empty());
    }

    #[test]
    fn test_set_lines() {
        let mut out = memory_output();
        out.write(&Event::Set {
            slot: 449_661_788,
            fec_set_index: 32,
            first_shred_ns: 100,
            decodable_ns: Some(150),
            data_at_decode: 28,
            recovered: true,
            decoded: true,
        })
        .unwrap();
        out.write(&Event::Set {
            slot: 449_661_788,
            fec_set_index: 64,
            first_shred_ns: 120,
            decodable_ns: None,
            data_at_decode: 16,
            recovered: false,
            decoded: false,
        })
        .unwrap();
        assert_eq!(
            lines(&out.sets),
            [
                r#"{"slot":449661788,"fec_set":32,"t0_ns":100,"t1_ns":150,"data_at_decode":28,"recovered":true,"decoded":true}"#,
                // a set that never reached 32 shreds has no t1
                r#"{"slot":449661788,"fec_set":64,"t0_ns":120,"t1_ns":null,"data_at_decode":16,"recovered":false,"decoded":false}"#,
            ]
        );
    }

    #[test]
    fn test_slot_lines() {
        let mut out = memory_output();
        out.write(&Event::Slot {
            slot: 449_661_788,
            first_shred_ns: 100,
            done_ns: Some(300),
            sets_decoded: 4,
            sets_lost: 0,
            txs: 26,
            footer: true,
            end: SlotEnd::Complete,
        })
        .unwrap();
        out.write(&Event::Slot {
            slot: 449_661_789,
            first_shred_ns: 120,
            done_ns: None,
            sets_decoded: 0,
            sets_lost: 2,
            txs: 0,
            footer: false,
            end: SlotEnd::GivenUp,
        })
        .unwrap();
        assert_eq!(
            lines(&out.slots),
            [
                r#"{"slot":449661788,"first_shred_ns":100,"done_ns":300,"sets_decoded":4,"sets_lost":0,"txs":26,"footer":true,"end":"complete"}"#,
                r#"{"slot":449661789,"first_shred_ns":120,"done_ns":null,"sets_decoded":0,"sets_lost":2,"txs":0,"footer":false,"end":"given_up"}"#,
            ]
        );
        assert!(out.tx.is_empty());
    }

    #[test]
    fn test_one_line_per_event() {
        let mut out = memory_output();
        for _ in 0..3 {
            out.write(&Event::Tx {
                slot: 1,
                signature: Signature::from_str(SIG).unwrap(),
                timing: timing(),
            })
            .unwrap();
        }
        assert_eq!(lines(&out.tx).len(), 3);
        assert!(out.tx.ends_with(b"\n"));
    }

    #[test]
    fn test_summary() {
        let stats = Stats {
            packets: 255,
            txs: 26,
            slots_complete: 1,
            ..Stats::default()
        };
        let mut buf = Vec::new();
        write_summary(&mut buf, &stats).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(v["packets"], 255);
        assert_eq!(v["txs"], 26);
        assert_eq!(v["slots_complete"], 1);
        assert_eq!(v["sets_lost"], 0);
    }

    #[test]
    fn test_create_writes_files() {
        let dir = std::env::temp_dir().join(format!("shredtap-record-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut out = Output::create(&dir).unwrap();
        out.write(&Event::Tx {
            slot: 1,
            signature: Signature::from_str(SIG).unwrap(),
            timing: timing(),
        })
        .unwrap();
        out.flush().unwrap();
        for name in ["tx.jsonl", "markers.jsonl", "sets.jsonl", "slots.jsonl"] {
            assert!(dir.join(name).exists(), "{name}");
        }
        let tx = std::fs::read_to_string(dir.join("tx.jsonl")).unwrap();
        assert_eq!(tx.lines().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

//! Writes the assembler's events as JSON lines, and the run's totals as a summary.
//!
//! Every event becomes one small record, a flat struct whose fields serde writes in order.
//! An EventSink is where those records go. Output writes one file per kind: transactions
//! to tx.jsonl, block markers to markers.jsonl, FEC sets to sets.jsonl, slots to slots.jsonl
//! and the compact public feed, slot summaries and rollups, to public.jsonl.
//! LineSink writes every kind to one stream, each line tagged with its kind and flushed at once,
//! so a reader such as a terminal on stdout sees each event the moment it happens.
//! Both are generic over the writer, files or stdout for a real run and Vec<u8> in tests.
//! write_summary writes the Stats once at the end as pretty JSON.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use serde::Serialize;

use crate::assembler::{Event, Stats, Timing};
use crate::error::Result;
use crate::feed::Public;
use shred_core::footer::{FinalCert, Footer, RewardCert, Signers};
use solana_hash::Hash;

/// One line of tx.jsonl, keyed by the transaction's first signature.
#[derive(Serialize)]
struct TxRecord {
    slot: u64,
    sig: String,
    fec_set: u32,
    t0_ns: u64,
    t1_ns: u64,
    t2_ns: u64,
    rebuilt: bool,
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
    rebuilt: bool,
}

/// One line of sets.jsonl. t1_ns is null for a set that never reached 32 shreds.
/// rebuilt lists the data shards Reed-Solomon filled, by place in the set.
#[derive(Serialize)]
struct SetRecord<'a> {
    slot: u64,
    fec_set: u32,
    t0_ns: u64,
    t1_ns: Option<u64>,
    data_at_decode: u64,
    rebuilt: &'a [u8],
    decoded: bool,
}

/// One line of slots.jsonl, written when the slot closes.
#[derive(Serialize)]
struct SlotRecord<'a> {
    slot: u64,
    /// base58, null without a leader schedule.
    leader: Option<String>,
    first_shred_ns: u64,
    /// When the last batch decoded, null if nothing did.
    done_ns: Option<u64>,
    sets_decoded: u32,
    sets_lost: u32,
    txs: u64,
    late_data: u32,
    /// null if the slot's footer never decoded.
    footer: Option<FooterRecord<'a>>,
    end: &'static str,
}

/// The block footer inside a slot line, hashes in base58 as Solana shows them.
#[derive(Serialize)]
struct FooterRecord<'a> {
    bank_hash: String,
    producer_time_ns: u64,
    user_agent: &'a str,
    final_cert: Option<FinalCertRecord>,
    skip_reward: Option<RewardRecord>,
    notar_reward: Option<RewardRecord>,
}

#[derive(Serialize)]
struct FinalCertRecord {
    slot: u64,
    block_id: String,
    fast: bool,
    finalize: Signers,
    notarize: Option<Signers>,
}

/// block_id is null on the skip reward cert.
#[derive(Serialize)]
struct RewardRecord {
    slot: u64,
    block_id: Option<String>,
    signers: Signers,
}

impl<'a> From<&'a Footer> for FooterRecord<'a> {
    fn from(f: &'a Footer) -> Self {
        let reward = |r: &RewardCert| RewardRecord {
            slot: r.slot,
            block_id: r.block_id.map(base58),
            signers: r.signers,
        };
        Self {
            bank_hash: base58(f.bank_hash),
            producer_time_ns: f.producer_time_ns,
            user_agent: &f.user_agent,
            final_cert: f.final_cert.as_ref().map(|c: &FinalCert| FinalCertRecord {
                slot: c.slot,
                block_id: base58(c.block_id),
                fast: c.fast,
                finalize: c.finalize,
                notarize: c.notarize,
            }),
            skip_reward: f.skip_reward.as_ref().map(reward),
            notar_reward: f.notar_reward.as_ref().map(reward),
        }
    }
}

pub(crate) fn base58(bytes: [u8; 32]) -> String {
    Hash::new_from_array(bytes).to_string()
}

/// One event as the record its line holds. Tagged with its kind when every kind shares one stream.
// a Record lives only while its line is written, so the big slot variant costs nothing to keep inline
#[allow(clippy::large_enum_variant)]
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum Record<'a> {
    Tx(TxRecord),
    Marker(MarkerRecord),
    Set(SetRecord<'a>),
    Slot(SlotRecord<'a>),
}

impl<'a> From<&'a Event> for Record<'a> {
    fn from(event: &'a Event) -> Self {
        match event {
            Event::Tx {
                slot,
                signature,
                timing,
                rebuilt,
            } => {
                let Timing {
                    fec_set_index,
                    first_shred_ns,
                    decodable_ns,
                    decoded_ns,
                } = *timing;
                Record::Tx(TxRecord {
                    slot: *slot,
                    sig: signature.to_string(),
                    fec_set: fec_set_index,
                    t0_ns: first_shred_ns,
                    t1_ns: decodable_ns,
                    t2_ns: decoded_ns,
                    rebuilt: *rebuilt,
                })
            }
            Event::Marker {
                slot,
                variant,
                data,
                timing,
                rebuilt,
            } => Record::Marker(MarkerRecord {
                slot: *slot,
                variant: *variant,
                len: data.len(),
                fec_set: timing.fec_set_index,
                t0_ns: timing.first_shred_ns,
                t1_ns: timing.decodable_ns,
                t2_ns: timing.decoded_ns,
                rebuilt: *rebuilt,
            }),
            Event::Set {
                slot,
                fec_set_index,
                first_shred_ns,
                decodable_ns,
                data_at_decode,
                rebuilt,
                decoded,
            } => Record::Set(SetRecord {
                slot: *slot,
                fec_set: *fec_set_index,
                t0_ns: *first_shred_ns,
                t1_ns: *decodable_ns,
                data_at_decode: *data_at_decode,
                rebuilt,
                decoded: *decoded,
            }),
            Event::Slot {
                slot,
                leader,
                first_shred_ns,
                done_ns,
                sets_decoded,
                sets_lost,
                txs,
                late_data,
                footer,
                end,
            } => Record::Slot(SlotRecord {
                slot: *slot,
                leader: leader.map(base58),
                first_shred_ns: *first_shred_ns,
                done_ns: *done_ns,
                sets_decoded: *sets_decoded,
                sets_lost: *sets_lost,
                txs: *txs,
                late_data: *late_data,
                footer: footer.as_ref().map(FooterRecord::from),
                end: end.as_str(),
            }),
        }
    }
}

/// Where the assembler's events go.
pub trait EventSink {
    /// Writes one event.
    fn write(&mut self, event: &Event) -> Result<()>;
    /// Writes one message of the public feed.
    fn public(&mut self, message: &Public) -> Result<()>;
    /// Pushes anything still buffered out.
    fn flush(&mut self) -> Result<()>;
    /// How a sink that publishes is keeping up, None for one that only writes.
    fn published(&mut self) -> Option<Published> {
        None
    }
}

/// How a publishing sink is keeping up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Published {
    /// Messages dropped or lost since the start, because the queue was full or the publish failed.
    pub dropped: u64,
    /// Longest wait from queue to the server since the last time this was read, None if nothing went out.
    pub lag_ns: Option<u64>,
}

/// One event as the JSON of its line in the files, without the kind tag.
#[cfg(feature = "nats")]
pub(crate) fn untagged_json(event: &Event) -> Result<Vec<u8>> {
    Ok(match Record::from(event) {
        Record::Tx(r) => serde_json::to_vec(&r)?,
        Record::Marker(r) => serde_json::to_vec(&r)?,
        Record::Set(r) => serde_json::to_vec(&r)?,
        Record::Slot(r) => serde_json::to_vec(&r)?,
    })
}

/// One file per kind. W is any writer, files on disk or a Vec<u8> in tests.
pub struct Output<W> {
    pub tx: W,
    pub markers: W,
    pub sets: W,
    pub slots: W,
    pub public: W,
}

impl<W: Write> Output<W> {
    pub fn new(tx: W, markers: W, sets: W, slots: W, public: W) -> Self {
        Self {
            tx,
            markers,
            sets,
            slots,
            public,
        }
    }
}

impl<W: Write> EventSink for Output<W> {
    /// Writes one event as one line in the file for its kind, without the kind tag.
    fn write(&mut self, event: &Event) -> Result<()> {
        match Record::from(event) {
            Record::Tx(r) => write_line(&mut self.tx, &r),
            Record::Marker(r) => write_line(&mut self.markers, &r),
            Record::Set(r) => write_line(&mut self.sets, &r),
            Record::Slot(r) => write_line(&mut self.slots, &r),
        }
    }

    fn public(&mut self, message: &Public) -> Result<()> {
        write_line(&mut self.public, message)
    }

    fn flush(&mut self) -> Result<()> {
        self.tx.flush()?;
        self.markers.flush()?;
        self.sets.flush()?;
        self.slots.flush()?;
        self.public.flush()?;
        Ok(())
    }
}

/// Every kind on one stream, each line tagged with its kind and flushed as soon as it is written.
pub struct LineSink<W> {
    out: W,
}

impl<W: Write> LineSink<W> {
    pub fn new(out: W) -> Self {
        Self { out }
    }
}

impl<W: Write> EventSink for LineSink<W> {
    fn write(&mut self, event: &Event) -> Result<()> {
        write_line(&mut self.out, &Record::from(event))?;
        // a live reader must not wait for a buffer to fill
        self.out.flush()?;
        Ok(())
    }

    fn public(&mut self, message: &Public) -> Result<()> {
        write_line(&mut self.out, message)?;
        self.out.flush()?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.out.flush()?;
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
            open("public.jsonl")?,
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
    use crate::assembler::{Event, SlotEnd, Stats, Timing};
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

    // hashes of all zeros are 32 ones in base58
    fn footer() -> Footer {
        Footer {
            bank_hash: [0; 32],
            producer_time_ns: 5,
            user_agent: "agave".into(),
            final_cert: Some(FinalCert {
                slot: 449_661_787,
                block_id: [0; 32],
                fast: true,
                finalize: Signers {
                    bits: 473,
                    voted: 355,
                    fallback: 0,
                },
                notarize: None,
            }),
            skip_reward: None,
            notar_reward: Some(RewardCert {
                slot: 449_661_780,
                block_id: Some([0; 32]),
                signers: Signers {
                    bits: 473,
                    voted: 458,
                    fallback: 0,
                },
            }),
        }
    }

    fn memory_output() -> Output<Vec<u8>> {
        Output::new(Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new())
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
            rebuilt: false,
        })
        .unwrap();
        assert_eq!(
            lines(&out.tx),
            [format!(
                r#"{{"slot":449661788,"sig":"{SIG}","fec_set":32,"t0_ns":100,"t1_ns":150,"t2_ns":160,"rebuilt":false}}"#
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
            rebuilt: true,
        })
        .unwrap();
        assert_eq!(
            lines(&out.markers),
            [
                r#"{"slot":449661788,"variant":0,"len":670,"fec_set":32,"t0_ns":100,"t1_ns":150,"t2_ns":160,"rebuilt":true}"#
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
            rebuilt: vec![3, 10, 17, 31],
            decoded: true,
        })
        .unwrap();
        out.write(&Event::Set {
            slot: 449_661_788,
            fec_set_index: 64,
            first_shred_ns: 120,
            decodable_ns: None,
            data_at_decode: 16,
            rebuilt: Vec::new(),
            decoded: false,
        })
        .unwrap();
        assert_eq!(
            lines(&out.sets),
            [
                r#"{"slot":449661788,"fec_set":32,"t0_ns":100,"t1_ns":150,"data_at_decode":28,"rebuilt":[3,10,17,31],"decoded":true}"#,
                // a set that never reached 32 shreds has no t1
                r#"{"slot":449661788,"fec_set":64,"t0_ns":120,"t1_ns":null,"data_at_decode":16,"rebuilt":[],"decoded":false}"#,
            ]
        );
    }

    #[test]
    fn test_slot_lines() {
        let mut out = memory_output();
        out.write(&Event::Slot {
            slot: 449_661_788,
            leader: Some([0; 32]),
            first_shred_ns: 100,
            done_ns: Some(300),
            sets_decoded: 4,
            sets_lost: 0,
            txs: 26,
            late_data: 7,
            footer: Some(footer()),
            end: SlotEnd::Complete,
        })
        .unwrap();
        out.write(&Event::Slot {
            slot: 449_661_789,
            leader: None,
            first_shred_ns: 120,
            done_ns: None,
            sets_decoded: 0,
            sets_lost: 2,
            txs: 0,
            late_data: 0,
            footer: None,
            end: SlotEnd::GivenUp,
        })
        .unwrap();
        assert_eq!(
            lines(&out.slots),
            [
                r#"{"slot":449661788,"leader":"11111111111111111111111111111111","first_shred_ns":100,"done_ns":300,"sets_decoded":4,"sets_lost":0,"txs":26,"late_data":7,"footer":{"bank_hash":"11111111111111111111111111111111","producer_time_ns":5,"user_agent":"agave","final_cert":{"slot":449661787,"block_id":"11111111111111111111111111111111","fast":true,"finalize":{"bits":473,"voted":355,"fallback":0},"notarize":null},"skip_reward":null,"notar_reward":{"slot":449661780,"block_id":"11111111111111111111111111111111","signers":{"bits":473,"voted":458,"fallback":0}}},"end":"complete"}"#,
                r#"{"slot":449661789,"leader":null,"first_shred_ns":120,"done_ns":null,"sets_decoded":0,"sets_lost":2,"txs":0,"late_data":0,"footer":null,"end":"given_up"}"#,
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
                rebuilt: false,
            })
            .unwrap();
        }
        assert_eq!(lines(&out.tx).len(), 3);
        assert!(out.tx.ends_with(b"\n"));
    }

    // a writer that remembers how many times it was flushed
    #[derive(Default)]
    struct Counted {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for Counted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn test_line_sink_tags_and_flushes_every_event() {
        let mut sink = LineSink::new(Counted::default());
        sink.write(&Event::Tx {
            slot: 1,
            signature: Signature::from_str(SIG).unwrap(),
            timing: timing(),
            rebuilt: false,
        })
        .unwrap();
        // flushed already, a reader on the other end sees it now
        assert_eq!(sink.out.flushes, 1);
        sink.write(&Event::Set {
            slot: 1,
            fec_set_index: 0,
            first_shred_ns: 100,
            decodable_ns: None,
            data_at_decode: 16,
            rebuilt: Vec::new(),
            decoded: false,
        })
        .unwrap();
        assert_eq!(sink.out.flushes, 2);

        // every kind on one stream, told apart by the kind tag, the rest as in the files
        let text = lines(&sink.out.bytes);
        assert_eq!(text.len(), 2);
        assert!(
            text[0].starts_with(r#"{"kind":"tx","slot":1,"sig":""#),
            "{}",
            text[0]
        );
        assert!(
            text[1].starts_with(r#"{"kind":"set","slot":1,"fec_set":0,"#),
            "{}",
            text[1]
        );
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
            rebuilt: false,
        })
        .unwrap();
        out.flush().unwrap();
        for name in [
            "tx.jsonl",
            "markers.jsonl",
            "sets.jsonl",
            "slots.jsonl",
            "public.jsonl",
        ] {
            assert!(dir.join(name).exists(), "{name}");
        }
        let tx = std::fs::read_to_string(dir.join("tx.jsonl")).unwrap();
        assert_eq!(tx.lines().count(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

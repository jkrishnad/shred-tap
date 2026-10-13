//! The shredtap command line, a thin layer over the library.
//!
//! decode reads a pcap capture, from a file or from stdin when the input is "-",
//! runs every packet through the assembler and writes the events and a summary into a folder,
//! or with --out - streams every event to stdout as one JSON line, the moment it happens.
//! The totals are printed on stderr, so they never mix with the events on stdout.
//! With --leader-schedule it also checks every FEC set's signature against its slot's leader.
//! All the work happens in the library, this file only parses arguments and reports errors.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use shredtap::assembler::{Assembler, DEFAULT_SLOT_NS, Stats};
use shredtap::leaders::LeaderSchedule;
use shredtap::pcap::{PcapReader, udp_payload};
use shredtap::record::{EventSink, LineSink, Output, write_summary};

#[derive(Parser)]
#[command(
    version,
    about = "Observe and decode the shreds that reach a Solana validator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decode a pcap capture into tx, sets, markers and slots JSON lines plus summary.json
    Decode {
        /// Capture file, or - to read a pcap stream from stdin (for example a tcpdump pipe)
        input: PathBuf,
        /// Folder for the output files, created if missing, or - to stream every event to stdout
        #[arg(long)]
        out: PathBuf,
        /// Slot duration in milliseconds, it sets when an unfinished slot is given up on
        #[arg(long, default_value_t = DEFAULT_SLOT_NS / 1_000_000)]
        slot_ms: u64,
        /// Output of solana leader-schedule, repeat it for a capture that spans epochs
        #[arg(long)]
        leader_schedule: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Decode {
            input,
            out,
            slot_ms,
            leader_schedule,
        } => decode(&input, &out, slot_ms, &leader_schedule),
    }
}

fn decode(input: &Path, out: &Path, slot_ms: u64, schedules: &[PathBuf]) -> Result<()> {
    let source: Box<dyn Read> = if input == Path::new("-") {
        Box::new(io::stdin().lock())
    } else {
        let file =
            File::open(input).with_context(|| format!("opening capture {}", input.display()))?;
        Box::new(file)
    };
    let mut pcap = PcapReader::new(BufReader::new(source))
        .with_context(|| format!("reading pcap header of {}", input.display()))?;

    let to_stdout = out == Path::new("-");
    let mut output: Box<dyn EventSink> = if to_stdout {
        Box::new(LineSink::new(io::stdout().lock()))
    } else {
        Box::new(
            Output::create(out).with_context(|| format!("creating output in {}", out.display()))?,
        )
    };
    let mut assembler = Assembler::with_slot_duration_ns(slot_ms * 1_000_000);
    if !schedules.is_empty() {
        let mut leaders = LeaderSchedule::default();
        for path in schedules {
            let file = File::open(path)
                .with_context(|| format!("opening leader schedule {}", path.display()))?;
            leaders
                .read(BufReader::new(file))
                .with_context(|| format!("reading leader schedule {}", path.display()))?;
        }
        assembler = assembler.with_leaders(leaders);
    }

    while let Some(record) = pcap.next_record().context("reading capture")? {
        if let Some(payload) = udp_payload(&record.frame) {
            for event in assembler.push(payload, record.recv_ns) {
                output.write(&event).context("writing event")?;
            }
        }
    }
    for event in assembler.finish() {
        output.write(&event).context("writing event")?;
    }
    output.flush().context("flushing output")?;

    if !to_stdout {
        let summary_path = out.join("summary.json");
        let summary = File::create(&summary_path)
            .with_context(|| format!("creating {}", summary_path.display()))?;
        write_summary(summary, assembler.stats()).context("writing summary")?;
    }

    print_summary(assembler.stats(), out);
    Ok(())
}

fn print_summary(stats: &Stats, out: &Path) {
    eprintln!(
        "{} packets, {} slots complete, {} transactions, {} from rebuilt shreds",
        stats.packets, stats.slots_complete, stats.txs, stats.txs_rebuilt
    );
    eprintln!(
        "{} sets decoded, {} rebuilt at t1, {} never got all data, {} lost",
        stats.sets_decoded,
        stats.sets_rebuilt_at_t1,
        stats.sets_data_never_complete,
        stats.sets_lost
    );
    eprintln!(
        "{} bad proofs, {} bad signatures, {} with no known leader",
        stats.bad_proof, stats.bad_signature, stats.no_leader
    );
    if out != Path::new("-") {
        eprintln!("output in {}", out.display());
    }
}

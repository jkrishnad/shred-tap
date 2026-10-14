//! The shredtap command line, a thin layer over the library.
//!
//! decode reads a pcap capture, from a file or from stdin when the input is "-".
//! live, built with the live feature, reads shreds straight from a network interface.
//! Both run every packet through the assembler the same way, in run, and write the events
//! and a summary into a folder, or with --out - stream every event to stdout as one JSON line,
//! the moment it happens, with the compact public feed: a summary per slot and a rollup
//! of the last minute every 5 s. The totals are printed on stderr, so they never mix with the events.
//! Built with the nats feature, --nats publishes them to a NATS server instead.
//! With --leader-schedule every FEC set's signature is checked against its slot's leader.
//! All the work happens in the library, this file only parses arguments and reports errors.

use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use shredtap::assembler::{Assembler, DEFAULT_SLOT_NS, Stats};
use shredtap::feed::{Feed, Public};
use shredtap::leaders::{LeaderDir, LeaderSchedule};
use shredtap::pcap::{PacketSource, PcapReader, udp_payload};
use shredtap::record::{EventSink, LineSink, Output, write_summary};
use shredtap::rollup::Rollups;

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
        #[command(flatten)]
        options: Options,
    },
    /// Capture shreds live from a network interface and decode them as they arrive
    #[cfg(feature = "live")]
    Live {
        /// Network interface the shreds arrive on, like eth0
        #[arg(long)]
        interface: String,
        #[command(flatten)]
        options: Options,
    },
}

/// What decode and live share.
#[derive(Args)]
struct Options {
    /// Folder for the output files, created if missing, or - to stream every event to stdout
    #[arg(long)]
    out: Option<PathBuf>,
    /// NATS server to publish every event to, like 127.0.0.1:4222
    #[cfg(feature = "nats")]
    #[arg(long, conflicts_with = "out")]
    nats: Option<String>,
    /// Slot duration in milliseconds, it sets when an unfinished slot is given up on
    #[arg(long, default_value_t = DEFAULT_SLOT_NS / 1_000_000)]
    slot_ms: u64,
    /// Output of solana leader-schedule, repeat it for a capture that spans epochs
    #[arg(long)]
    leader_schedule: Vec<PathBuf>,
    /// Folder of leader schedule files, one per epoch, read again whenever a file in it changes
    #[arg(long, conflicts_with = "leader_schedule")]
    leader_schedule_dir: Option<PathBuf>,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Decode { input, options } => {
            let source: Box<dyn Read> = if input == Path::new("-") {
                Box::new(io::stdin().lock())
            } else {
                let file = File::open(&input)
                    .with_context(|| format!("opening capture {}", input.display()))?;
                Box::new(file)
            };
            let mut pcap = PcapReader::new(BufReader::new(source))
                .with_context(|| format!("reading pcap header of {}", input.display()))?;
            run(&mut pcap, &options)
        }
        #[cfg(feature = "live")]
        Command::Live { interface, options } => {
            let mut capture = shredtap::capture::LiveCapture::open(&interface)
                .with_context(|| format!("opening interface {interface}"))?;
            run(&mut capture, &options)
        }
    }
}

/// Feeds every packet of a source through the assembler into the sink, until the source ends.
fn run(source: &mut dyn PacketSource, options: &Options) -> Result<()> {
    // the folder the files and summary.json go in, None for stdout or NATS
    let folder = options.out.as_deref().filter(|out| *out != Path::new("-"));
    let mut output = sink(options, folder)?;
    let mut assembler = Assembler::with_slot_duration_ns(options.slot_ms * 1_000_000);
    if !options.leader_schedule.is_empty() {
        let mut leaders = LeaderSchedule::default();
        for path in &options.leader_schedule {
            let file = File::open(path)
                .with_context(|| format!("opening leader schedule {}", path.display()))?;
            leaders
                .read(BufReader::new(file))
                .with_context(|| format!("reading leader schedule {}", path.display()))?;
        }
        assembler = assembler.with_leaders(leaders);
    }

    let mut feed = Feed::default();
    let mut rollups = Rollups::default();
    let mut leader_dir = options.leader_schedule_dir.as_deref().map(LeaderDir::new);
    if let Some(dir) = &mut leader_dir {
        reload_leaders(dir, &mut assembler);
    }
    let mut next_leader_check_ns = 0;
    while let Some(record) = source.next_record().context("reading packets")? {
        // a new epoch's schedule is picked up within a minute, without a restart
        if let Some(dir) = &mut leader_dir {
            if next_leader_check_ns == 0 {
                next_leader_check_ns = record.recv_ns + LEADER_CHECK_NS;
            } else if record.recv_ns >= next_leader_check_ns {
                next_leader_check_ns = record.recv_ns + LEADER_CHECK_NS;
                reload_leaders(dir, &mut assembler);
            }
        }
        if let Some(payload) = udp_payload(&record.frame) {
            for event in assembler.push(payload, record.recv_ns) {
                rollups.add(&event);
                if let Some(summary) = feed.add(&event) {
                    output
                        .public(&Public::Summary(summary))
                        .context("writing summary")?;
                }
                output.write(&event).context("writing event")?;
            }
        }
        if let Some(rollup) = rollups.tick(
            record.recv_ns,
            assembler.stats(),
            || source.drops(),
            || output.published(),
        ) {
            output
                .public(&Public::Stats(rollup))
                .context("writing rollup")?;
        }
    }
    for event in assembler.finish() {
        if let Some(summary) = feed.add(&event) {
            output
                .public(&Public::Summary(summary))
                .context("writing summary")?;
        }
        output.write(&event).context("writing event")?;
    }
    output.flush().context("flushing output")?;

    if let Some(out) = folder {
        let summary_path = out.join("summary.json");
        let summary = File::create(&summary_path)
            .with_context(|| format!("creating {}", summary_path.display()))?;
        write_summary(summary, assembler.stats()).context("writing summary")?;
    }

    print_summary(assembler.stats(), folder);
    Ok(())
}

/// How often a live run looks for a changed leader schedule folder, on the capture clock.
const LEADER_CHECK_NS: u64 = 60_000_000_000;

/// Loads the folder again if it changed. A folder that can't be read keeps the schedule loaded.
fn reload_leaders(dir: &mut LeaderDir, assembler: &mut Assembler) {
    match dir.changed() {
        Ok(Some(leaders)) => {
            eprintln!("leader schedule: {} slots", leaders.len());
            assembler.set_leaders(leaders);
        }
        Ok(None) => {}
        Err(e) => eprintln!("leader schedule: {e}, keeping the one loaded"),
    }
}

/// The sink the options ask for: NATS, a folder of files, or stdout.
fn sink(options: &Options, folder: Option<&Path>) -> Result<Box<dyn EventSink>> {
    #[cfg(feature = "nats")]
    if let Some(addr) = &options.nats {
        let sink = shredtap::nats::NatsSink::connect(addr)
            .with_context(|| format!("connecting to NATS at {addr}"))?;
        return Ok(Box::new(sink));
    }
    match (folder, &options.out) {
        (Some(out), _) => {
            Ok(Box::new(Output::create(out).with_context(|| {
                format!("creating output in {}", out.display())
            })?))
        }
        (None, Some(_)) => Ok(Box::new(LineSink::new(io::stdout().lock()))),
        (None, None) => anyhow::bail!("pass --out, a folder or - for stdout"),
    }
}

fn print_summary(stats: &Stats, folder: Option<&Path>) {
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
    if let Some(out) = folder {
        eprintln!("output in {}", out.display());
    }
}

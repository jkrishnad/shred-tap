//! Runs the real shredtap binary on a small capture built from the fixture slot.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// Every shred of slot 449661788 in arrival order, each record recv_ns (u64), length (u16), shred.
const ARRIVALS: &[u8] = include_bytes!("fixtures/real-slot-arrivals.bin");

// From getBlock 449661788 on the public testnet RPC.
const FIRST_SIG: &str =
    "4AbpiMLynSZh6xhuKRvFVYWv56nAdgtiJ17kHMeTeHbjgAP4SQXxn6CBRzkF2TukHjAhaDappzuDgkZ9gXfmuNBu";

// A nanosecond pcap of Ethernet frames around the fixture shreds, with documentation range IPs.
fn capture() -> Vec<u8> {
    let mut f = vec![0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0];
    f.extend_from_slice(&[0u8; 8]);
    f.extend_from_slice(&65535u32.to_le_bytes());
    f.extend_from_slice(&1u32.to_le_bytes());
    for (recv_ns, shred) in arrivals() {
        f.extend(record(recv_ns, shred));
    }
    f
}

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

// One pcap record, the shred in a UDP packet to port 8001.
fn record(recv_ns: u64, shred: &[u8]) -> Vec<u8> {
    let len = shred.len();
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&[0x08, 0x00, 0x45, 0]);
    frame.extend_from_slice(&((20 + 8 + len) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    frame.extend_from_slice(&8000u16.to_be_bytes());
    frame.extend_from_slice(&8001u16.to_be_bytes());
    frame.extend_from_slice(&((8 + len) as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(shred);

    let mut r = Vec::new();
    r.extend_from_slice(&((recv_ns / 1_000_000_000) as u32).to_le_bytes());
    r.extend_from_slice(&((recv_ns % 1_000_000_000) as u32).to_le_bytes());
    r.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    r.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    r.extend_from_slice(&frame);
    r
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shredtap-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn check_output(out: &Path) {
    let tx = std::fs::read_to_string(out.join("tx.jsonl")).unwrap();
    assert_eq!(tx.lines().count(), 26);
    assert!(tx.lines().next().unwrap().contains(FIRST_SIG));

    let sets = std::fs::read_to_string(out.join("sets.jsonl")).unwrap();
    assert_eq!(sets.lines().count(), 4);

    let markers = std::fs::read_to_string(out.join("markers.jsonl")).unwrap();
    assert_eq!(markers.lines().count(), 2);

    let slots = std::fs::read_to_string(out.join("slots.jsonl")).unwrap();
    assert_eq!(slots.lines().count(), 1);
    assert!(slots.contains(r#""txs":26"#), "{slots}");
    assert!(slots.contains(r#""end":"complete""#), "{slots}");

    let summary = std::fs::read_to_string(out.join("summary.json")).unwrap();
    assert!(summary.contains(r#""packets": 255"#), "{summary}");
    assert!(summary.contains(r#""txs": 26"#), "{summary}");
}

#[test]
fn decode_file() {
    let dir = temp_dir("file");
    let pcap = dir.join("capture.pcap");
    std::fs::write(&pcap, capture()).unwrap();
    let out = dir.join("out");

    let status = Command::new(env!("CARGO_BIN_EXE_shredtap"))
        .args([
            "decode",
            pcap.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    check_output(&out);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn decode_stdin() {
    // the same command reads a tcpdump pipe when the input is "-"
    use std::io::Write;
    let dir = temp_dir("stdin");
    let out = dir.join("out");

    let mut child = Command::new(env!("CARGO_BIN_EXE_shredtap"))
        .args(["decode", "-", "--out", out.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&capture()).unwrap();
    assert!(child.wait().unwrap().success());
    check_output(&out);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn stream_events_before_the_input_ends() {
    // with --out - every event is a JSON line on stdout, written the moment its slot closes
    use std::io::{BufRead, BufReader, Write};
    let mut child = Command::new(env!("CARGO_BIN_EXE_shredtap"))
        .args(["decode", "-", "--out", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&capture()).unwrap();
    // a shred of a later slot, 2 s on, moves the capture clock past the fixture slot's deadline
    let (last_ns, shred) = *arrivals().last().unwrap();
    let mut later = shred.to_vec();
    later[65..73].copy_from_slice(&(449_661_788u64 + 100).to_le_bytes());
    stdin
        .write_all(&record(last_ns + 2_000_000_000, &later))
        .unwrap();
    stdin.flush().unwrap();

    // stdin is still open, yet the slot's lines arrive, the slot line last
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let lines: Vec<String> = (&mut stdout)
        .lines()
        .map(Result::unwrap)
        .take_while(|l| !l.starts_with(r#"{"kind":"slot""#))
        .collect();
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with(r#"{"kind":"tx""#))
            .count(),
        26
    );

    // the reader stays open to the end, shredtap still writes its last lines when stdin closes
    drop(stdin);
    std::io::copy(&mut stdout, &mut std::io::sink()).unwrap();
    assert!(child.wait().unwrap().success());
}

#[test]
fn bad_input_fails() {
    // a missing file and a file that is not a pcap both stop with an error on stderr
    let dir = temp_dir("bad");
    let bad = dir.join("bad.pcap");
    std::fs::write(&bad, b"definitely not a capture file").unwrap();
    for input in [Path::new("/nonexistent/capture.pcap"), bad.as_path()] {
        let output = Command::new(env!("CARGO_BIN_EXE_shredtap"))
            .args([
                "decode",
                input.to_str().unwrap(),
                "--out",
                dir.join("out").to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!output.stderr.is_empty());
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

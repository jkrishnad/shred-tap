//! shredtap reads the shreds that reach a Solana validator and rebuilds the block data from them.
//!
//! The flow, one module per step.
//! 1. pcap pulls each shred out of a tcpdump capture, with the time it arrived.
//!    capture does the same live from a network interface, behind the live feature.
//! 2. wire reads single header fields straight from the shred bytes.
//! 3. shred checks a packet once and works out its kind, its place in the FEC set and its byte layout.
//! 4. fec collects the shreds of one FEC set and rebuilds missing data shards with Reed-Solomon.
//!    merkle climbs a shred's Merkle proof to its set's root, to check the shred belongs there.
//!    leaders reads the leader schedule and checks the leader's signature on that root.
//! 5. block joins data shards into batches and decodes them into entries or block markers.
//!    footer reads the block footer marker, its bank hash, clock, client and certificates.
//! 6. assembler runs all of the above on a live or recorded stream, in the right order, with timing.
//! 7. record writes the assembler's events as JSON lines and the run's totals as a summary.
//!
//! error holds the one Error type every module returns.
pub mod assembler;
pub mod block;
#[cfg(feature = "live")]
pub mod capture;
pub mod error;
pub mod fec;
pub mod footer;
pub mod leaders;
pub mod merkle;
pub mod pcap;
pub mod record;
pub mod shred;
pub mod wire;

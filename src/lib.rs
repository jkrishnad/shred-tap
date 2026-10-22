//! shredtap watches the shreds that reach a Solana validator, rebuilt into blocks by shred-core.
//!
//! shred-core reads the shreds and its assembler turns them into transactions, markers and closed slots.
//! shredtap feeds it a live or recorded stream and publishes what it finds.
//! 1. capture reads shreds live from a network interface, behind the live feature.
//! 2. record writes the assembler's events as JSON lines and the run's totals as a summary.
//!    rollup sums up the last minute every 5 s, and feed makes the small public slot summaries.
//!    nats publishes the same events to a NATS server, behind the nats feature.
//!
//! error holds shredtap's Error, which wraps shred-core's.
#[cfg(feature = "live")]
pub mod capture;
pub mod error;
pub mod feed;
#[cfg(feature = "nats")]
pub mod nats;
pub mod record;
pub mod rollup;

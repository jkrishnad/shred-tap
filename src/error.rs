//! Error type for the whole crate.

/// Result with the crate's own Error.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while reading shreds.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Packet ended before the field we wanted to read.
    #[error("packet too short: expected {expected}, got {actual} bytes")]
    TooShort { expected: usize, actual: usize },
    /// Variant byte is not a shred type we know, so the packet is not a shred we can read.
    #[error("unknown shred variant byte: {0:#04x}")]
    UnknownVariant(u8),
    /// Data shred whose index is below its FEC set start, so the packet is junk.
    #[error("data shred index {index} is below its fec_set_index {fec_set_index}")]
    IndexBelowFecSet { index: u32, fec_set_index: u32 },
}

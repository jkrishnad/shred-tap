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
}

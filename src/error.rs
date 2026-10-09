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
    /// Merkle proof too long to fit in the shred, so the variant byte is junk.
    #[error("invalid proof size: {0}")]
    InvalidProofSize(u8),
    /// Shred pushed into a FEC set it does not belong to.
    #[error("shred for set {got:?} pushed into set {expected:?}")]
    WrongFecSet {
        expected: (u64, u32),
        got: (u64, u32),
    },
    /// Shard index outside the range its kind may use in a 32 data and 32 coding set.
    #[error("shard index {0} out of range for its kind")]
    ShardIndexOutOfRange(usize),
    /// Coding shred for a set that is not 32 data + 32 coding.
    #[error("unsupported erasure config: {num_data} data, {num_coding} coding")]
    UnsupportedErasureConfig { num_data: u16, num_coding: u16 },
    /// Fewer than 32 shreds, so the set can't be rebuilt yet.
    #[error("too few shreds: have {have}, need {need}")]
    TooFewShreds { have: usize, need: usize },
    /// Reed-Solomon failed, for example shards of different lengths.
    #[error("reed-solomon recovery failed: {0}")]
    Recovery(#[from] reed_solomon_erasure::Error),
    /// Data shred whose size field points before its headers end or past its shard.
    #[error("invalid data size {size} for a shard of {shard_len} bytes")]
    InvalidDataSize { size: u16, shard_len: usize },
    /// Entry batch bytes that don't decode as entries.
    #[error("entry decode failed: {0}")]
    Decode(#[from] wincode::ReadError),
}

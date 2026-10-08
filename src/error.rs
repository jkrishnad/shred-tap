pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("packet too short: expected {expected}, got {actual} bytes")]
    TooShort { expected: usize, actual: usize },
    #[error("unknown shred variant byte: {0:#04x}")]
    UnknownVariant(u8),
}

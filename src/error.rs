//! shredtap's own Error, wrapping shred-core's for everything that reads shreds.
//!
//! thiserror writes the Display and std::error::Error impls from the attributes.

/// Result with the crate's own Error.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong in shredtap.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Reading shreds or a capture failed, shown exactly as shred-core words it.
    #[error(transparent)]
    Core(#[from] shred_core::error::Error),
    /// Connecting or publishing to NATS failed.
    #[error("nats: {0}")]
    Nats(String),
    /// Writing the output failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Writing a record as JSON failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

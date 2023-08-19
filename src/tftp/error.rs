#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid Packet: {0}")]
    Malformed(String),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
}

// Alias Result to be the crate Result.
pub type Result<T> = core::result::Result<T, Error>;

// Personal preference.
pub use std::format as f;

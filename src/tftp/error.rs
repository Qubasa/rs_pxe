#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Invalid Packet: {0}")]
    Malformed(String),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error("Ignore")]
    Ignore(String),

    #[error("Ignore no log: {0}")]
    IgnoreNoLog(String),

    #[error("Tftp errror: {0}")]
    Tftp(String),

    #[error("Tftp received Error {0}: {1}")]
    TftpReceivedError(TftpError, String),

    #[error("Tftp end of file")]
    TftpEndOfFile,

    #[error("Max retries exceeded")]
    MaxRetriesExceeded,

    #[error("Kill current tftp connection")]
    StopTftpConnection(Vec<u8>),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error("Generic error: {0}")]
    Generic(String),
}

// Alias Result to be the crate Result.
pub type Result<T> = core::result::Result<T, Error>;

// Personal preference.
pub use std::format as f;

use super::construct::TftpError;

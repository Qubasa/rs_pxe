use crate::tftp::construct::TftpError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    // #[error(transparent)]
    // TftpError(#[from] crate::tftp::error::Error),

    // #[error(transparent)]
    // DhcpError(#[from] crate::dhcp::error::Error),
    #[error("Kill current tftp connection")]
    StopTftpConnection(Vec<u8>),

    #[error("Ignore")]
    Ignore(String),

    #[error("Ignore no log: {0}")]
    IgnoreNoLog(String),
}

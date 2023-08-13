use crate::tftp::construct::TftpError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// For starter, to remove as code matures.
    #[error("Generic error: {0}")]
    Generic(String),
    /// For starter, to remove as code matures.
    #[error("Static error: {0}")]
    Static(&'static str),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error("Unknown DHCP value")]
    UnknownDhcpValue(u64),

    #[error("Missing DHCP option: {0}")]
    MissingDhcpOption(&'static str),

    #[error("Invalid Packet: {0}")]
    Malformed(String),

    #[error("Max retries exceeded")]
    MaxRetriesExceeded,

    #[error("Kill current tftp connection")]
    StopTftpConnection(Vec<u8>),

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

    #[error(transparent)]
    DhcpError(#[from] crate::dhcp::error::Error),
}

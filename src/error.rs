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

    #[error("Missing DHCP option")]
    MissingDhcpOption,

    #[error("Invalid Packet: {0}")]
    Malformed(String),

    #[error("Ignore")]
    Ignore(String),

    #[error("Ignore no log: {0}")]
    IgnoreNoLog(String),

    #[error("Tftp errror: {0}")]
    Tftp(String),

    #[error("Tftp received Error {0}: {1}")]
    TftpReceivedError(u16, String),

    #[error("Tftp end of file")]
    TftpEndOfFile,
}

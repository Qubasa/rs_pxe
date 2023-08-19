#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Wait for DHCP Ack")]
    WaitForDhcpAck,
    #[error("Unknown DHCP value: {0}")]
    UnknownDhcpValue(u64),
    #[error("Missing DHCP option: {0}")]
    MissingDhcpOption(&'static str),
    #[error("Ignoring Packet. Reason: {0}")]
    Ignore(String),
    #[error("Ignore no log: {0}")]
    IgnoreNoLog(String),
    #[error("Invalid Packet: {0}")]
    Malformed(String),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("DHCP Protocol Finished")]
    DhcpProtocolFinished,
}

// Alias Result to be the crate Result.
pub type Result<T> = core::result::Result<T, Error>;

// Personal preference.
pub use std::format as f;

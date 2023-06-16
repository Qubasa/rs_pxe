use smoltcp::{
    time::{Duration, Instant},
    wire::IpEndpoint,
};

use smolapps::wire::tftp;
use smolapps::wire::tftp::ErrorCode;
use smolapps::wire::tftp::{Packet, Repr};

use crate::prelude::*;

/// Maximum number of retransmissions attempted by the server before giving up.
const MAX_RETRIES: u8 = 10;

/// Interval between consecutive retries in case of no answer.
const RETRY_TIMEOUT: Duration = Duration::from_millis(200);

/// IANA port for TFTP servers.
const TFTP_PORT: u16 = 69;

use ouroboros::self_referencing;
use std::{fs::File, io::Read};

#[self_referencing]
#[derive(Debug)]
pub struct TftpReprWrapper {
    mdata: Vec<u8>,
    #[borrows(mdata)]
    #[covariant]
    pub repr: tftp::Repr<'this>,
}

pub struct TestTftp {
    pub file: File,
}

impl Handle for TestTftp {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.file.read(buf)?)
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        todo!()
    }
}

/// An open file handle returned by a [`Context::open()`] operation.
///
/// [`Context::open()`]: trait.Context.html#tymethod.open
pub trait Handle {
    /// Pulls some bytes from this handle into the specified buffer, returning how many bytes were read.
    ///
    /// `buf` is guaranteed to be exactly 512 bytes long, the maximum packet size allowed by the protocol.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Writes a buffer into this handle's buffer, returning how many bytes were written.
    ///
    /// `buf` can be anywhere from 0 to 512 bytes long.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
}

/// An active TFTP transfer.
#[derive(Debug, Clone, Copy)]
pub struct Transfer<H> {
    pub handle: H,
    pub ep: IpEndpoint,
    pub is_write: bool,
    pub block_num: u16,
    // FIXME: I'd reeeally love to avoid a potential stack allocation this big :\
    pub last_data: Option<[u8; 512]>,
    pub last_len: usize,

    pub retries: u8,
    pub timeout: Instant,
}

impl<H> Transfer<H>
where
    H: Handle,
{
    pub fn new(xfer_idx: H, ep: IpEndpoint, is_write: bool) -> Self {
        Self {
            handle: xfer_idx,
            ep,
            is_write,
            block_num: 0,
            last_data: Some([0; 512]),
            last_len: 0,
            retries: 0,
            timeout: Instant::now() + Duration::from_millis(200),
        }
    }
}

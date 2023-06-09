use smoltcp::{
    time::{Duration, Instant},
    wire::IpEndpoint,
};

/// Maximum number of retransmissions attempted by the server before giving up.
const MAX_RETRIES: u8 = 10;

/// Interval between consecutive retries in case of no answer.
const RETRY_TIMEOUT: Duration = Duration::from_millis(200);

/// IANA port for TFTP servers.
const TFTP_PORT: u16 = 69;

use std::{fs::File, io::Read};

use crate::prelude::*;

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
pub struct Transfer<H> {
    handle: H,
    ep: IpEndpoint,

    is_write: bool,
    block_num: u16,
    // FIXME: I'd reeeally love to avoid a potential stack allocation this big :\
    last_data: Option<[u8; 512]>,
    last_len: usize,

    retries: u8,
    timeout: Instant,
}

impl<H> Transfer<H> where H: Handle {}

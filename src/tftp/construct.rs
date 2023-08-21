use log::*;
use smoltcp::{
    time::{Duration, Instant},
    wire::{ArpRepr, EthernetAddress, Ipv4Address},
};

use super::error::*;
use super::parse::Repr;
use super::parse::{self, TftpOption};
use super::utils;

use std::{collections::BTreeMap, fmt::Formatter, io::Seek};

/// Maximum number of retransmissions attempted by the server before giving up.
// const MAX_RETRIES: u8 = 10;

// /// Interval between consecutive retries in case of no answer.
// const RETRY_TIMEOUT: Duration = Duration::from_millis(200);

// /// IANA port for TFTP servers.
// const TFTP_PORT: u16 = 69;
use ouroboros::self_referencing;

use std::{collections::HashMap, fmt::Display, fs::File, io::Read};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TftpError {
    Unknown,
    FileNotFound,
    AccessViolation,
    DiskFull,
    IllegalOperation,
    UnknownTransferId,
    FileAlreadyExists,
    NoSuchUser,
}

impl Display for TftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TftpError::Unknown => write!(f, "Unknown"),
            TftpError::FileNotFound => write!(f, "FileNotFound"),
            TftpError::AccessViolation => write!(f, "AccessViolation"),
            TftpError::DiskFull => write!(f, "DiskFull"),
            TftpError::IllegalOperation => write!(f, "IllegalOperation"),
            TftpError::UnknownTransferId => write!(f, "UnknownTransferId"),
            TftpError::FileAlreadyExists => write!(f, "FileAlreadyExists"),
            TftpError::NoSuchUser => write!(f, "NoSuchUser"),
        }
    }
}

impl From<TftpError> for u16 {
    fn from(e: TftpError) -> Self {
        match e {
            TftpError::Unknown => 0,
            TftpError::FileNotFound => 1,
            TftpError::AccessViolation => 2,
            TftpError::DiskFull => 3,
            TftpError::IllegalOperation => 4,
            TftpError::UnknownTransferId => 5,
            TftpError::FileAlreadyExists => 6,
            TftpError::NoSuchUser => 7,
        }
    }
}
impl From<u16> for TftpError {
    fn from(e: u16) -> Self {
        match e {
            0 => TftpError::Unknown,
            1 => TftpError::FileNotFound,
            2 => TftpError::AccessViolation,
            3 => TftpError::DiskFull,
            4 => TftpError::IllegalOperation,
            5 => TftpError::UnknownTransferId,
            6 => TftpError::FileAlreadyExists,
            7 => TftpError::NoSuchUser,
            _ => TftpError::Unknown,
        }
    }
}

#[self_referencing]
#[derive(Debug)]
pub struct TftpReprWrapper {
    mdata: Vec<u8>,
    #[borrows(mdata)]
    #[covariant]
    pub repr: Repr<'this>,
}

#[derive(Debug)]
pub struct TestTftp {
    pub file: File,
    last_read: usize,
}

impl TestTftp {
    pub fn new(file: File) -> Self {
        Self { file, last_read: 0 }
    }
}

impl Handle for TestTftp {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let read_bytes = self.file.read(buf)?;
        self.last_read = read_bytes;
        Ok(read_bytes)
    }

    fn write(&mut self, _buf: &[u8]) -> Result<usize> {
        todo!()
    }

    fn repeat_last_read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() != self.last_read {
            return Err(Error::Generic(
                "Buffer size does not match last read size".to_string(),
            ));
        }

        self.file
            .seek(std::io::SeekFrom::Current(-(self.last_read as i64)))?;

        self.read(buf)
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

    fn repeat_last_read(&mut self, buf: &mut [u8]) -> Result<usize>;

    /// Writes a buffer into this handle's buffer, returning how many bytes were written.
    ///
    /// `buf` can be anywhere from 0 to 512 bytes long.
    fn write(&mut self, buf: &[u8]) -> Result<usize>;
}

#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub enum TftpOptionEnum {
    Blksize,
    Tsize,
}

impl From<&TftpOptionEnum> for &str {
    fn from(opt: &TftpOptionEnum) -> Self {
        match &opt {
            TftpOptionEnum::Blksize => "blksize",
            TftpOptionEnum::Tsize => "tsize",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TftpOptions {
    opts: BTreeMap<TftpOptionEnum, usize>,
}

impl TftpOptions {
    pub fn new() -> Self {
        Self {
            opts: BTreeMap::new(),
        }
    }

    pub fn to_str_str(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();

        for (k, v) in self.opts.iter() {
            let k: &str = k.into();
            map.insert(k.to_string(), v.to_string());
        }

        map
    }

    pub fn has(&self, option: TftpOptionEnum) -> bool {
        self.opts.contains_key(&option)
    }

    pub fn add(&mut self, option: TftpOptionEnum, value: usize) {
        self.opts.insert(option, value);
    }

    pub fn get(&self, option: TftpOptionEnum) -> Option<usize> {
        self.opts.get(&option).copied()
    }
}

impl Default for TftpOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// An active TFTP transfer.
#[derive(Debug, Clone)]
pub struct Transfer<H> {
    pub handle: H,
    pub connection: TftpConnection,
    pub is_write: bool,
    pub last_block_num: u16,
    pub options: TftpOptions,
    pub retries: u8,
    pub timeout: Instant,
}

impl<H> Display for Transfer<H>
where
    H: Handle + std::fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Transfer: connection: {}, is_write {}, handle: {:?}",
            self.connection, self.is_write, self.handle
        )
    }
}

impl<H> Transfer<H>
where
    H: Handle,
{
    pub fn new(xfer_idx: H, connection: TftpConnection, is_write: bool) -> Self {
        Self {
            handle: xfer_idx,
            connection,
            options: TftpOptions::new(),
            is_write,
            retries: 0,
            timeout: Instant::now() + Duration::from_millis(200),
            last_block_num: 0,
        }
    }

    pub fn process_timeout(&mut self) -> Result<Vec<u8>> {
        if self.retries >= 10 {
            return Err(Error::MaxRetriesExceeded);
        }

        if self.timeout <= Instant::now() {
            info!(
                "Timeout detected. Resending last data packet. Attempt: {}",
                self.retries
            );
            self.retries += 1;
            self.reset_timeout();
            return self.resend_last_data();
        }
        Err(Error::IgnoreNoLog("".to_string()))
    }

    pub fn reset_timeout(&mut self) {
        self.timeout = Instant::now() + Duration::from_millis(200);
    }

    pub fn resend_last_data(&mut self) -> Result<Vec<u8>> {
        // Read file in chunks of blksize into buffer s
        let blksize = self.options.get(TftpOptionEnum::Blksize).unwrap();
        let mut s = vec![0u8; blksize];
        let bytes_read = match self.handle.repeat_last_read(s.as_mut_slice()) {
            Ok(len) => len,
            Err(e) => {
                return Err(Error::Tftp(f!("tftp: error reading file: {}", e)));
            }
        };
        if bytes_read == 0 {
            log::info!("End of file reached");
            return Err(Error::TftpEndOfFile);
        }

        let data = Repr::Data {
            block_num: self.last_block_num,
            data: &s.as_slice()[..bytes_read],
        };
        log::debug!(
            "Sending data block {} of size {}",
            self.last_block_num,
            bytes_read
        );

        let packet = utils::tftp_to_ether_unicast(&data, &self.connection);
        Ok(packet)
    }

    pub fn send_timeout(&mut self) -> Result<Vec<u8>> {
        let err = Repr::Error {
            code: parse::ErrorCode::Unknown(0),
            msg: "Connection timed out",
        };

        let packet = utils::tftp_to_ether_unicast(&err, &self.connection);
        Ok(packet)
    }

    pub fn send_data(&mut self, ack_block_num: u16) -> Result<Vec<u8>> {
        if ack_block_num != self.last_block_num {
            return Err(Error::Tftp(f!(
                "tftp: received ack for block {} but expected {}",
                ack_block_num,
                self.last_block_num
            )));
        }

        self.reset_timeout();

        // Read file in chunks of blksize into buffer s
        let blksize = self.options.get(TftpOptionEnum::Blksize).unwrap();
        let mut s = vec![0u8; blksize];
        let bytes_read = match self.handle.read(s.as_mut_slice()) {
            Ok(len) => len,
            Err(e) => {
                return Err(Error::Tftp(f!("tftp: error reading file: {}", e)));
            }
        };

        if bytes_read == 0 {
            log::info!("End of file reached");
            return Err(Error::TftpEndOfFile);
        }

        let data = Repr::Data {
            block_num: self.last_block_num + 1,
            data: &s.as_slice()[..bytes_read],
        };
        self.last_block_num += 1;
        log::debug!(
            "Sending data block {} of size {}",
            self.last_block_num,
            bytes_read
        );

        let packet = utils::tftp_to_ether_unicast(&data, &self.connection);
        Ok(packet)
    }

    pub fn ack_options(&self) -> Result<Vec<u8>> {
        let ack_opts = self.options.to_str_str();
        let needed_bytes = ack_opts.iter().fold(0, |acc, (name, value)| {
            acc + (TftpOption { name, value }).len()
        });

        let mut resp_opt_buf = vec![0u8; needed_bytes];
        let mut opt_resp = parse::TftpOptsWriter::new(resp_opt_buf.as_mut_slice());

        for (name, value) in ack_opts {
            let opt = TftpOption {
                name: &name,
                value: &value,
            };
            opt_resp.emit(opt).unwrap();
        }
        let written_bytes = opt_resp.written_bytes();

        debug_assert!(written_bytes == needed_bytes);
        let opts = parse::TftpOptsReader::new(&resp_opt_buf[..written_bytes]);

        let ack = Repr::OptionAck { opts };
        let packet = utils::tftp_to_ether_unicast(&ack, &self.connection);
        Ok(packet)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TftpConnection {
    pub server_ip: Ipv4Address,
    pub server_mac: EthernetAddress,
    pub client_ip: Ipv4Address,
    pub client_mac: EthernetAddress,
    pub server_port: u16,
    pub client_port: u16,
}

impl Display for TftpConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.client_ip, self.client_port, self.server_ip, self.server_port
        )
    }
}

use smoltcp::{
    time::{Duration, Instant},
    wire::{EthernetAddress, Ipv4Address},
};

use smolapps::wire::tftp::Repr;
use smolapps::wire::tftp::{self, TftpOption};

use crate::{prelude::*, utils};

/// Maximum number of retransmissions attempted by the server before giving up.
const MAX_RETRIES: u8 = 10;

/// Interval between consecutive retries in case of no answer.
const RETRY_TIMEOUT: Duration = Duration::from_millis(200);

/// IANA port for TFTP servers.
const TFTP_PORT: u16 = 69;

use ouroboros::self_referencing;

use std::{collections::HashMap, fs::File, io::Read};

#[self_referencing]
#[derive(Debug)]
pub struct TftpReprWrapper {
    mdata: Vec<u8>,
    #[borrows(mdata)]
    #[covariant]
    pub repr: tftp::Repr<'this>,
}

#[derive(Debug)]
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
    pub connection: TftpConnection,
    pub is_write: bool,
    pub block_num: u16,
    pub retries: u8,
    pub timeout: Instant,
}

impl<H> Transfer<H>
where
    H: Handle,
{
    pub fn new(xfer_idx: H, connection: TftpConnection, is_write: bool) -> Self {
        Self {
            handle: xfer_idx,
            connection,
            is_write,
            retries: 0,
            timeout: Instant::now() + Duration::from_millis(200),
            block_num: 0,
        }
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

#[self_referencing]
#[derive(Debug)]
pub struct TftpPacketWrapper {
    pub data: Vec<u8>,
    pub is_write: bool,

    #[borrows(data)]
    #[covariant]
    pub packet: tftp::Packet<&'this [u8]>,

    #[borrows(packet)]
    #[covariant]
    pub repr: tftp::Repr<'this>,
}

pub fn reply_tsize<H>(
    tx_token: H,
    wrapper: &TftpPacketWrapper,
    tftp_con: TftpConnection,
    transfers: &mut HashMap<TftpConnection, Transfer<TestTftp>>,
) -> Result<()>
where
    H: smoltcp::phy::TxToken,
{
    let xfer_idx = transfers.get(&tftp_con);
    {
        match (*wrapper.borrow_repr(), xfer_idx) {
            (
                Repr::ReadRequest {
                    filename,
                    mode,
                    opts,
                },
                None,
            ) => {
                if mode != tftp::Mode::Octet {
                    return Err(Error::Tftp("Only octet mode is supported".to_string()));
                }

                let t = {
                    let xfer_idx = TestTftp {
                        file: File::open("ipxe.pxe").unwrap(),
                    };

                    let transfer = Transfer::new(xfer_idx, tftp_con, *wrapper.borrow_is_write());

                    transfers.insert(tftp_con, transfer);
                    transfers.get_mut(&tftp_con).unwrap()
                };

                log::debug!("tftp: request for file: {}", filename);
                log::debug!(
                    "tftp: {} request from: {:?}",
                    if t.is_write { "write" } else { "read" },
                    tftp_con
                );
                let options = {
                    let mut map = HashMap::new();
                    for opt in opts.options() {
                        map.insert(opt.name, opt.value);
                    }
                    map
                };

                if let Some(&tsize) = options.get("tsize") {
                    if tsize != "0" {
                        return Err(Error::Tftp(f!(
                            "tftp: tsize option should be zero is however {}",
                            tsize
                        )));
                    }

                    let tsize = t.handle.file.metadata()?.len();

                    let tsize_response = tsize.to_string();

                    let mut opt_buf = [0u8; 64];
                    let opts = {
                        let opt = TftpOption {
                            name: "tsize",
                            value: &tsize_response,
                        };

                        let mut opt_resp = tftp::TftpOptsWriter::new(&mut opt_buf);
                        opt_resp.emit(opt).unwrap();
                        let written_bytes = opt_resp.len();
                        tftp::TftpOptsReader::new(&opt_buf[..written_bytes])
                    };

                    let ack = Repr::OptionAck { opts };
                    let packet = crate::utils::tftp_to_ether_unicast(&ack, &tftp_con);

                    tx_token.consume(packet.len(), |buffer| {
                        buffer.copy_from_slice(&packet);
                    });
                } else {
                    return Err(Error::Tftp("tftp: tsize option not found".to_string()));
                }
            }
            (Repr::Error { code, msg }, None | Some(_)) => {
                return Err(Error::Tftp(f!("tftp error: {} code: {:?}", msg, code)));
            }
            (packet, ..) => {
                return Err(Error::Tftp(f!(
                    "Received unexpected tftp packet: {:?}. ",
                    packet
                )));
            }
        };
    }
    Ok(())
}

pub fn reply_blksize<H>(
    tx_token: H,
    wrapper: &TftpPacketWrapper,
    tftp_con: TftpConnection,
    transfers: &mut HashMap<TftpConnection, Transfer<TestTftp>>,
) -> Result<usize>
where
    H: smoltcp::phy::TxToken,
{
    let xfer_idx = transfers.get(&tftp_con);
    {
        match (*wrapper.borrow_repr(), xfer_idx) {
            (
                Repr::ReadRequest {
                    filename,
                    mode,
                    opts,
                },
                None,
            ) => {
                if mode != tftp::Mode::Octet {
                    return Err(Error::Tftp("Only octet mode is supported".to_string()));
                }

                let t = {
                    let xfer_idx = TestTftp {
                        file: File::open("ipxe.pxe").unwrap(),
                    };

                    let transfer = Transfer::new(xfer_idx, tftp_con, *wrapper.borrow_is_write());

                    transfers.insert(tftp_con, transfer);
                    transfers.get_mut(&tftp_con).unwrap()
                };

                let options = {
                    let mut map = HashMap::new();
                    for opt in opts.options() {
                        map.insert(opt.name, opt.value);
                    }
                    map
                };

                if let Some(&blksize) = options.get("blksize") {
                    let blksize = match blksize.parse::<usize>() {
                        Ok(blksize) => blksize,
                        Err(_) => {
                            return Err(Error::Tftp(f!(
                                "tftp: blksize option should be a number is however {}",
                                blksize
                            )));
                        }
                    };

                    log::debug!("Acking blksize: {}", blksize);

                    let blksize_response = blksize.to_string();
                    let mut opt_buf = [0u8; 64];
                    let opts = {
                        let opt = TftpOption {
                            name: "blksize",
                            value: &blksize_response,
                        };

                        let mut opt_resp = tftp::TftpOptsWriter::new(&mut opt_buf);
                        opt_resp.emit(opt).unwrap();
                        let written_bytes = opt_resp.len();
                        tftp::TftpOptsReader::new(&opt_buf[..written_bytes])
                    };

                    let ack = Repr::OptionAck { opts };

                    let packet = crate::utils::tftp_to_ether_unicast(&ack, &tftp_con);

                    tx_token.consume(packet.len(), |buffer| {
                        buffer.copy_from_slice(&packet);
                    });
                    Ok(blksize)
                } else {
                    Err(Error::Tftp("tftp: blksize option not found".to_string()))
                }
            }
            (Repr::Error { code, msg }, None | Some(_)) => match code {
                tftp::ErrorCode::Undefined => Err(Error::Ignore(
                    "Expected undefined tftp error as response. Ignoring".to_string(),
                )),
                _ => Err(Error::Tftp(f!("tftp error: {} code: {:?}", msg, code))),
            },
            (packet, ..) => Err(Error::Tftp(f!(
                "Received unexpected tftp packet: {:?}. ",
                packet
            ))),
        }
    }
}

pub fn reply_data<H>(
    tx_token: H,
    wrapper: &TftpPacketWrapper,
    tftp_con: TftpConnection,
    transfers: &mut HashMap<TftpConnection, Transfer<TestTftp>>,
    blksize: usize,
) -> Result<bool>
where
    H: smoltcp::phy::TxToken,
{
    let xfer_idx = transfers.get_mut(&tftp_con);

    match (*wrapper.borrow_repr(), xfer_idx) {
        (Repr::Ack { block_num }, Some(t)) => {
            let mut s = vec![0u8; blksize];

            let bytes_read = match t.handle.read(s.as_mut_slice()) {
                Ok(len) => len,
                Err(e) => {
                    return Err(Error::Tftp(f!("tftp: error reading file: {}", e)));
                }
            };

            if bytes_read == 0 {
                log::info!("End of file reached");
                return Ok(true);
            }

            let data = Repr::Data {
                block_num: block_num + 1,
                data: &s.as_slice()[..bytes_read],
            };
            log::debug!(
                "Sending data block {} of size {}",
                block_num + 1,
                bytes_read
            );

            let packet = crate::utils::tftp_to_ether_unicast(&data, &tftp_con);

            tx_token.consume(packet.len(), |buffer| {
                buffer.copy_from_slice(&packet);
            });
            Ok(false)
        }
        (Repr::Error { code, msg }, None | Some(_)) => {
            Err(Error::Tftp(f!("tftp error: {} code: {:?}", msg, code)))
        }
        (packet, ..) => Err(Error::Tftp(f!(
            "Received unexpected tftp packet: {:?}. ",
            packet
        ))),
    }
}
pub fn recv_tftp<H>(
    rx_token: H,
    server_mac: &EthernetAddress,
    server_ip: &Ipv4Address,
) -> Result<(TftpConnection, TftpPacketWrapper)>
where
    H: smoltcp::phy::RxToken,
{
    let (client, wrapper) = rx_token.consume(|buffer| {
        let (udp, src_endpoint, src_mac_addr) =
            crate::utils::unicast_ether_to_udp(buffer, server_mac, server_ip)?;

        let tftp_packet = match tftp::Packet::new_checked(udp.payload()) {
            Ok(packet) => packet,
            Err(e) => {
                return Err(Error::Malformed(f!("tftp: invalid packet: {}", e)));
            }
        };

        let is_write = tftp_packet.opcode() == tftp::OpCode::Write;

        match tftp::Repr::parse(&tftp_packet) {
            Ok(repr) => repr,
            Err(e) => {
                return Err(Error::Malformed(f!("tftp: invalid packet: {}", e)));
            }
        };

        let client = TftpConnection {
            server_ip: *server_ip,
            server_mac: src_mac_addr,
            client_ip: Ipv4Address::from_bytes(src_endpoint.addr.as_bytes()),
            client_mac: src_mac_addr,
            server_port: udp.dst_port(),
            client_port: udp.src_port(),
        };

        let wrapper = TftpPacketWrapperBuilder {
            data: udp.payload().to_vec(),
            is_write,
            packet_builder: |data| tftp::Packet::new_checked(data.as_ref()).unwrap(),
            repr_builder: |packet| tftp::Repr::parse(packet).unwrap(),
        }
        .build();
        Ok((client, wrapper))
    })?;

    Ok((client, wrapper))
}

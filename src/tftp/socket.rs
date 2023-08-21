use log::*;

use smoltcp::{
    time::{Duration, Instant},
    wire::{ArpRepr, EthernetAddress, Ipv4Address},
};

use crate::dhcp::parse::FirmwareType;

use super::error::*;
use super::utils;
use super::{construct::TftpConnection, parse::Repr};
use super::{
    construct::{TestTftp, TftpError, TftpOptionEnum, Transfer},
    parse::{self, TftpOption},
};

use ouroboros::self_referencing;
use std::{
    collections::BTreeMap,
    fmt::Display,
    fs::File,
    io::Seek,
    path::{Path, PathBuf},
};

#[self_referencing(pub_extras)]
#[derive(Debug)]
pub struct TftpPacketWrapper {
    pub data: Vec<u8>,
    pub is_write: bool,

    #[borrows(data)]
    #[covariant]
    pub packet: parse::Packet<&'this [u8]>,

    #[borrows(packet)]
    #[covariant]
    pub repr: parse::Repr<'this>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TftpStates {
    ReadRequest,
    SecondReadRequest,
    Data,
    Error,
}

impl Display for TftpStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TftpStates::ReadRequest => write!(f, "Tsize"),
            TftpStates::SecondReadRequest => write!(f, "SecondReadRequest"),
            TftpStates::Data => write!(f, "Data"),
            TftpStates::Error => write!(f, "Error"),
        }
    }
}

#[derive(Debug)]
pub struct TftpSocket {
    _state: TftpStates,
    server_mac: EthernetAddress,
    server_ip: Ipv4Address,
    file_path: PathBuf,
    firmware_type: FirmwareType,
    transfer: Option<Transfer<TestTftp>>,
}

impl TftpSocket {
    pub fn new(
        server_mac: EthernetAddress,
        server_ip: Ipv4Address,
        file_path: &Path,
        firmware_type: FirmwareType,
    ) -> Self {
        Self {
            _state: TftpStates::ReadRequest,
            firmware_type,
            file_path: file_path.to_path_buf(),
            server_mac,
            server_ip,
            transfer: None,
        }
    }

    pub fn set_state(&mut self, state: TftpStates) {
        self._state = state;
    }

    pub fn get_state(&self) -> TftpStates {
        self._state
    }

    pub fn process_timeout(&mut self) -> Result<Vec<u8>> {
        if let Some(trans) = &mut self.transfer {
            return match trans.process_timeout() {
                Ok(packet) => Ok(packet),
                Err(Error::MaxRetriesExceeded) => {
                    error!("Killing connection. Sending timeout");
                    let packet = trans.send_timeout().unwrap();
                    Err(Error::StopTftpConnection(packet))
                }
                Err(Error::Ignore(_) | Error::IgnoreNoLog(_)) => Err(Error::Ignore("".to_string())),
                Err(e) => panic!("Error: {}", e),
            };
        }
        Err(Error::IgnoreNoLog("".to_string()))
    }

    pub fn process(&mut self, rx_buffer: &[u8]) -> Result<Vec<u8>> {
        let (tftp_con, wrapper) = self.recv_tftp(rx_buffer)?;

        match self.get_state() {
            TftpStates::ReadRequest => {
                let trans = match self.parse_ack_options(&wrapper, tftp_con) {
                    Ok(transfer) => transfer,
                    Err(e) => panic!("Received unexpected tftp error: {}", e),
                };

                let packet = trans.ack_options().unwrap();
                self.transfer = Some(trans);

                match self.firmware_type {
                    FirmwareType::Intel => self.set_state(TftpStates::SecondReadRequest),
                    FirmwareType::IPxe => self.set_state(TftpStates::Data),
                }

                Ok(packet)
            }
            TftpStates::SecondReadRequest => {
                let trans = {
                    match self.parse_ack_options(&wrapper, tftp_con) {
                        Ok(ack_opts) => ack_opts,
                        Err(e) => {
                            if let Error::TftpReceivedError(_, msg) = e {
                                // Reset transfer because we received an error
                                // This is expected and this is how the Intel firmware does
                                // multiple tftp options in separate packets. This is not spec
                                // compliant. Eyyy
                                self.transfer = None;
                                return Err(Error::IgnoreNoLog(msg));
                            } else {
                                panic!("Received unexpected tftp error: {}", e);
                                //return Err(e);
                            }
                        }
                    }
                };

                let packet = trans.ack_options().unwrap();
                self.transfer = Some(trans);
                self.set_state(TftpStates::Data);
                Ok(packet)
            }
            TftpStates::Data => match self.reply_data(&wrapper) {
                Ok(packet) => Ok(packet),
                Err(Error::TftpEndOfFile) => {
                    self.transfer = None;
                    Err(Error::TftpEndOfFile)
                }
                Err(Error::Ignore(e)) => Err(Error::Ignore(e)),
                Err(e) => panic!("Received unexpected tftp error: {}", e),
            },
            TftpStates::Error => todo!(),
        }
    }

    pub fn reply_data(&mut self, wrapper: &TftpPacketWrapper) -> Result<Vec<u8>> {
        match (*wrapper.borrow_repr(), &mut self.transfer) {
            (Repr::Ack { block_num }, Some(t)) => {
                // Read file in chunks of blksize into buffer s
                let packet = t.send_data(block_num)?;
                Ok(packet)
            }
            (Repr::Error { code, msg }, None | Some(_)) => {
                let code: u16 = code.into();
                let error = TftpError::from(code);
                Err(Error::TftpReceivedError(error, msg.to_string()))
            }
            (packet, trans) => Err(Error::Tftp(f!(
                "Received unexpected tftp packet: {:?}. transfer: {:?} ",
                packet,
                trans
            ))),
        }
    }

    pub fn parse_ack_options(
        &self,
        wrapper: &TftpPacketWrapper,
        tftp_con: TftpConnection,
    ) -> Result<Transfer<TestTftp>> {
        {
            match (*wrapper.borrow_repr(), &self.transfer) {
                (
                    Repr::ReadRequest {
                        filename,
                        mode,
                        opts,
                    },
                    None,
                ) => {
                    if mode != super::parse::Mode::Octet {
                        return Err(Error::Tftp("Only octet mode is supported".to_string()));
                    }

                    let mut t = {
                        log::debug!(
                            "Creating TFTP transfer with file: {}",
                            self.file_path.display()
                        );
                        let file = File::open(&self.file_path)?;
                        let file_len = file.metadata()?.len();
                        let xfer_idx = TestTftp::new(file);
                        log::debug!("Opened file size: {}", file_len);
                        Transfer::new(xfer_idx, tftp_con, *wrapper.borrow_is_write())
                    };

                    for opt in opts.options() {
                        let (name, value) = (opt.name, opt.value);

                        match name {
                            "blksize" => {
                                match value.parse::<usize>() {
                                    Ok(blksize) => {
                                        t.options.add(TftpOptionEnum::Blksize, blksize);
                                    }
                                    Err(_) => {
                                        return Err(Error::Tftp(f!(
                                            "tftp: blksize option should be a number is however {}",
                                            value
                                        )));
                                    }
                                };
                            }
                            "tsize" => {
                                let tsize = t.handle.file.metadata()?.len();
                                log::debug!("tftp: tsize: {}", tsize);
                                t.options.add(TftpOptionEnum::Tsize, tsize as usize);
                            }
                            "windowsize" => {
                                t.options.add(TftpOptionEnum::WindowSize, 1);
                            }
                            _ => warn!("Unhandled tftp option: {}={}", name, value),
                        }
                    }

                    log::debug!("tftp: request for file: {}", filename);
                    log::debug!(
                        "tftp: {} request from: {}",
                        if t.is_write { "write" } else { "read" },
                        t
                    );
                    Ok(t)
                }
                (Repr::Error { code, msg }, None | Some(_)) => {
                    let code: u16 = code.into();
                    let error = TftpError::from(code);
                    Err(Error::TftpReceivedError(error, msg.to_string()))
                }
                (packet, trans) => Err(Error::Tftp(f!(
                    "Received unexpected tftp packet: {:?}. Transfer: {:?} ",
                    packet,
                    trans
                ))),
            }
        }
    }

    pub fn recv_tftp(&self, rx_buffer: &[u8]) -> Result<(TftpConnection, TftpPacketWrapper)> {
        let (udp, src_endpoint, src_mac_addr) =
            utils::unicast_ether_to_udp(rx_buffer, &self.server_mac, &self.server_ip)?;

        let tftp_packet = match super::parse::Packet::new_checked(udp.payload()) {
            Ok(packet) => packet,
            Err(e) => {
                return Err(Error::Malformed(f!("tftp: invalid packet: {}", e)));
            }
        };

        let is_write = tftp_packet.opcode() == super::parse::OpCode::Write;

        match super::parse::Repr::parse(&tftp_packet) {
            Ok(repr) => repr,
            Err(e) => {
                return Err(Error::Malformed(f!("tftp: invalid packet: {}", e)));
            }
        };

        let client = TftpConnection {
            server_ip: self.server_ip,
            server_mac: self.server_mac,
            client_ip: Ipv4Address::from_bytes(src_endpoint.addr.as_bytes()),
            client_mac: src_mac_addr,
            server_port: udp.dst_port(),
            client_port: udp.src_port(),
        };

        let wrapper = TftpPacketWrapperBuilder {
            data: udp.payload().to_vec(),
            is_write,
            packet_builder: |data| super::parse::Packet::new_checked(data.as_ref()).unwrap(),
            repr_builder: |packet| super::parse::Repr::parse(packet).unwrap(),
        }
        .build();
        Ok((client, wrapper))
    }
}

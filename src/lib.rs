#![allow(dead_code)]
#![allow(unused_imports)]

pub mod dhcp;
pub mod error;
pub mod prelude;

pub mod tftp;
pub mod udp_port_check;
mod utils;

#[cfg(test)]
mod tests;

use prelude::*;
use smoltcp::wire::ArpRepr;
use tftp::parse::Repr;
use tftp::socket::TftpOptionEnum;

use log::*;
use tftp::socket::Handle;
use tftp::socket::TestTftp;
use tftp::socket::TftpConnection;
use tftp::socket::Transfer;

use core::panic;
use ouroboros::self_referencing;
use rand::prelude::*;
use tftp::parse::TftpOption;
use tftp::parse::TftpOptsReader;

use smoltcp::iface::Config;
use smoltcp::iface::Routes;
use smoltcp::iface::SocketSet;
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::Checksum;
use smoltcp::phy::Device;
use smoltcp::phy::Medium;
use smoltcp::phy::RawSocket;
use smoltcp::phy::RxToken;
use smoltcp::phy::TxToken;
use smoltcp::socket::dhcpv4;
use smoltcp::time::Duration;
use smoltcp::time::Instant;
use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::IpListenEndpoint;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Cidr;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;
use smoltcp::{iface::Interface, phy::ChecksumCapabilities};
use std::borrow::BorrowMut;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use uuid::Uuid;

#[self_referencing]
#[derive(Debug)]
pub struct TftpPacketWrapper {
    pub data: Vec<u8>,
    pub is_write: bool,

    #[borrows(data)]
    #[covariant]
    pub packet: tftp::parse::Packet<&'this [u8]>,

    #[borrows(packet)]
    #[covariant]
    pub repr: tftp::parse::Repr<'this>,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PxeStates {
    Discover,
    Request(u32),
    ArpRequest,
    Tftp(TftpStates),
}

impl Display for PxeStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PxeStates::Discover => write!(f, "Discover"),
            PxeStates::Request(transaction_id) => {
                write!(f, "Request {{ transaction_id: {:#x} }}", transaction_id)
            }
            PxeStates::ArpRequest => write!(f, "ArpRequest"),
            PxeStates::Tftp(tftp_state) => write!(f, "Tftp({})", tftp_state),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TftpStates {
    Tsize,
    BlkSize,
    Data,
    Error,
}

impl Display for TftpStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TftpStates::Tsize => write!(f, "Tsize"),
            TftpStates::BlkSize => write!(f, "BlkSize"),
            TftpStates::Data => write!(f, "Data"),
            TftpStates::Error => write!(f, "Error"),
        }
    }
}

#[derive(Debug)]
pub struct PxeSocket {
    _state: PxeStates,
    stage_one: PathBuf,
    stage_one_name: String,
    stage_two: PathBuf,
    stage_two_name: String,
    is_stage_two: bool,
    transfer: Option<Transfer<TestTftp>>,
    tftp_con: Option<TftpConnection>,
    server_mac: EthernetAddress,
    server_ip: Ipv4Address,
    tftp_endpoint: IpListenEndpoint,
}

impl PxeSocket {
    pub fn get_server_ip(&self) -> Ipv4Address {
        self.server_ip
    }
    pub fn get_server_mac(&self) -> EthernetAddress {
        self.server_mac
    }
    pub fn get_state(&self) -> &PxeStates {
        &self._state
    }
    pub fn get_stage_two(&self) -> &PathBuf {
        &self.stage_two
    }
    pub fn get_stage_one(&self) -> &PathBuf {
        &self.stage_one
    }
    fn set_state(&mut self, state: PxeStates) {
        debug!("Changing state to {}", state);
        self._state = state;
    }
    pub fn reset_transfer(&mut self) {
        self.transfer = None;
        self.set_state(PxeStates::Tftp(TftpStates::Tsize));
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

    pub fn new(
        server_ip: Ipv4Address,
        server_mac: EthernetAddress,
        stage_one: &Path,
        stage_two: &Path,
    ) -> Self {
        log::info!(
            "Creating pxe socket with ip: {} and mac {}",
            server_ip,
            server_mac
        );

        // Find free tftp port in userspace range
        let tftp_endpoint = {
            let free_port = crate::udp_port_check::free_local_port_in_range(32768, 60999)
                .expect("No free UDP port found");

            IpListenEndpoint {
                addr: Some(smoltcp::wire::IpAddress::Ipv4(server_ip)),
                port: free_port,
            }
        };

        let server_ip = Ipv4Address::from_bytes(server_ip.as_bytes());

        // State machine
        let state = PxeStates::Discover;

        let stage_one_name = stage_one.file_name().unwrap().to_str().unwrap().to_string();

        if stage_one_name.len() > 127 {
            panic!("Stage one file name is too long");
        }

        let stage_two_name = stage_two.file_name().unwrap().to_str().unwrap().to_string();

        if stage_two_name.len() > 127 {
            panic!("Stage two file name is too long");
        }

        Self {
            _state: state,
            is_stage_two: false,
            transfer: None,
            tftp_con: None,
            server_mac,
            server_ip,
            tftp_endpoint,
            stage_two: stage_two.to_path_buf(),
            stage_two_name,
            stage_one: stage_one.to_path_buf(),
            stage_one_name,
        }
    }

    pub fn process(&mut self, rx_buffer: &[u8]) -> Result<Vec<u8>> {
        match self.get_state() {
            PxeStates::Discover => {
                /* ================== Parse PXE Discover ================== */
                /*
                Step 1. The client broadcasts a DHCPDISCOVER message to the standard DHCP port (67).
                An option field in this packet contains the following:
                   - A tag for client identifier (UUID).
                   - A tag for the client UNDI version.
                   - A tag for the client system architecture.
                   - A DHCP option 60, Class ID, set to “PXEClient:Arch:xxxxx:UNDI:yyyzzz”.
                */
                let info = {
                    let dhcp = crate::utils::broadcast_ether_to_dhcp(rx_buffer)?;
                    let info = crate::dhcp::parse::pxe_discover(dhcp)?;

                    if info.msg_type != DhcpMessageType::Discover {
                        Err(Error::Ignore("Not a dhcp discover packet".to_string()))
                    } else {
                        Ok(info)
                    }
                }?;

                log::info!("Parsed PXE Discover");
                log::info!("Sending PXE Offer");

                /*  ================== Send PXE Offer ================== */
                /*
                Step 2. The DHCP or Proxy DHCP Service responds by sending a DHCPOFFER message to the
                client on the standard DHCP reply port (68). If this is a Proxy DHCP Service, then the client IP
                address field is null (0.0.0.0). If this is a DHCP Service, then the returned client IP address
                field is valid.
                */
                let dhcp_repr =
                    dhcp::construct::pxe_offer(&info, &self.server_ip, &self.stage_one_name);
                let packet = utils::dhcp_to_ether_brdcast(
                    dhcp_repr.borrow_repr(),
                    &self.server_ip,
                    &self.server_mac,
                );

                log::info!("Sent PXE Offer");

                /*
                Step 3. From the DHCPOFFER(s) that it receives, the client records the following:
                - The Client IP address (and other parameters) offered by a standard DHCP or BOOTP Service.
                - The Boot Server list from the Boot Server field in the PXE tags from the DHCPOFFER.
                - The Discovery Control Options (if provided).
                - The Multicast Discovery IP address (if provided).

                Step 4. If the client selects an IP address offered by a DHCP Service, then it must complete the
                standard DHCP protocol by sending a request for the address back to the Service and then waiting for
                an acknowledgment from the Service. If the client selects an IP address from a BOOTP reply, it can
                simply use the address.
                */
                match info.firmware_type {
                    dhcp::parse::FirmwareType::Uknown => {
                        self.set_state(PxeStates::Request(info.transaction_id));
                    }
                    dhcp::parse::FirmwareType::IPxe => {
                        info!("iPXE firmware detected. Jumping to TFTP phase");
                        self.is_stage_two = true;
                        self.set_state(PxeStates::Tftp(TftpStates::Tsize));
                    }
                }

                Ok(packet)
            }
            PxeStates::Request(transaction_id) => {
                /*  ================== Parse PXE Request ================== */
                /*
                Step 5. The client selects and discovers a Boot Server. This packet may be sent broadcast (port 67),
                multicast (port 4011), or unicast (port 4011) depending on discovery control options included in the
                previous DHCPOFFER containing the PXE service extension tags. This packet is the same as the
                initial DHCPDISCOVER in Step 1, except that it is coded as a DHCPREQUEST and now contains
                the following:
                  - The IP address assigned to the client from a DHCP Service.
                  - A tag for client identifier (UUID)
                  - A tag for the client UNDI version.
                  - A tag for the client system architecture.
                  - A DHCP option 60, Class ID, set to “PXEClient:Arch:xxxxx:UNDI:yyyzzz”.
                  - The Boot Server type in a PXE option field
                */
                let (info, ip, mac) = {
                    let dhcp = crate::utils::uni_broad_ether_to_dhcp(
                        rx_buffer,
                        &self.server_mac,
                        &self.server_ip,
                    )?;

                    let info = dhcp::parse::pxe_discover(dhcp)?;

                    if info.msg_type != DhcpMessageType::Request {
                        return Err(Error::Ignore("Not a dhcp request packet".to_string()));
                    }

                    if info.transaction_id != *transaction_id {
                        return Err(Error::Ignore("Not the same transaction id".to_string()));
                    }

                    Ok::<_, Error>((info, dhcp.client_ip(), dhcp.client_hardware_address()))
                }?;

                log::info!("Parsed PXE Request");
                log::info!("Sending PXE ACK to {} with ip {}", mac, ip);

                /* ================== Send PXE ACK ================== */
                /*
                Step 6. The Boot Server unicasts a DHCPACK packet back to the client on the client source port.
                This reply packet contains:
                    - Boot file name.
                    - MTFTP configuration parameters.
                    - Any other options the NBP requires before it can be successfully executed.
                */

                let dhcp_repr =
                    dhcp::construct::pxe_ack(&info, &self.tftp_endpoint, &self.stage_one_name);
                let packet = utils::dhcp_to_ether_unicast(
                    dhcp_repr.borrow_repr(),
                    &ip,
                    &mac,
                    &self.server_ip,
                    &self.server_mac,
                );

                log::info!("Sent PXE ACK");

                /*
                Step 7. The client downloads the executable file using either standard TFTP (port69) or MTFTP
                (port assigned in Boot Server Ack packet). The file downloaded and the placement of the
                downloaded code in memory is dependent on the client’s CPU architecture.
                */

                self.set_state(PxeStates::Tftp(TftpStates::Tsize));

                Ok(packet)
            }
            PxeStates::ArpRequest => {
                let packet = self.arp_respond(rx_buffer)?;
                self.set_state(PxeStates::Tftp(TftpStates::Tsize));

                Ok(packet)
            }
            PxeStates::Tftp(ref tftp_state) => {
                let (tftp_con, wrapper) = self.recv_tftp(rx_buffer)?;

                match tftp_state {
                    TftpStates::Tsize => {
                        let trans = self.parse_ack_options(&wrapper, tftp_con).unwrap();

                        // If both tsize and blksize are present, we can go straight to data state
                        if trans.options.has(TftpOptionEnum::Tsize)
                            && trans.options.has(TftpOptionEnum::Blksize)
                        {
                            self.set_state(PxeStates::Tftp(TftpStates::Data));

                        // If only tsize is present, we need to request blksize
                        } else if trans.options.has(TftpOptionEnum::Tsize) {
                            self.set_state(PxeStates::Tftp(TftpStates::BlkSize));

                        // Else throw error
                        } else {
                            return Err(Error::Tftp(f!(
                                "Missing tsize option. Got options: {:?}",
                                trans.options
                            )));
                        }
                        let packet = trans.ack_options().unwrap();
                        self.transfer = Some(trans);
                        Ok(packet)
                    }
                    TftpStates::BlkSize => {
                        let trans = {
                            match self.parse_ack_options(&wrapper, tftp_con) {
                                Ok(ack_opts) => ack_opts,
                                Err(e) => {
                                    if let Error::TftpReceivedError(code, msg) = e {
                                        if u16::from(code) == 0u16 {
                                            // Reset transfer because we received an error
                                            // This is expected and this is how the Intel firmware does
                                            // multiple tftp options in separate packets. This is not spec
                                            // compliant. Eyyy
                                            self.transfer = None;
                                            return Err(Error::IgnoreNoLog(msg));
                                        } else {
                                            panic!(
                                                "Received unexpected tftp error: {}",
                                                Error::TftpReceivedError(code, msg)
                                            );
                                            //return Err(Error::TftpReceivedError(code, msg));
                                        }
                                    } else {
                                        panic!("Received unexpected tftp error: {}", e);
                                        //return Err(e);
                                    }
                                }
                            }
                        };

                        let packet = trans.ack_options().unwrap();
                        self.transfer = Some(trans);
                        self.set_state(PxeStates::Tftp(TftpStates::Data));
                        Ok(packet)
                    }
                    TftpStates::Data => match self.reply_data(&wrapper) {
                        Ok(packet) => Ok(packet),
                        Err(Error::TftpEndOfFile) => {
                            self.transfer = None;
                            self.is_stage_two = false;
                            self.set_state(PxeStates::Discover);
                            Err(Error::IgnoreNoLog("End of file reached".to_string()))
                        }
                        Err(e) => panic!("Received unexpected tftp error: {}", e),
                    },
                    TftpStates::Error => todo!(),
                }
            }
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
                    if mode != tftp::parse::Mode::Octet {
                        return Err(Error::Tftp("Only octet mode is supported".to_string()));
                    }

                    let mut t = {
                        let file = {
                            if self.is_stage_two {
                                File::open(self.get_stage_two())?
                            } else {
                                File::open(self.get_stage_one())?
                            }
                        };
                        let xfer_idx = TestTftp::new(file);

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
                                t.options.add(TftpOptionEnum::Tsize, tsize as usize);
                            }
                            _ => warn!("Unhandled tftp option: {}={}", name, value),
                        }
                    }

                    log::debug!("tftp: request for file: {}", filename);
                    log::debug!(
                        "tftp: {} request from: {:?}",
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
            crate::utils::unicast_ether_to_udp(rx_buffer, &self.server_mac, &self.server_ip)?;

        let tftp_packet = match tftp::parse::Packet::new_checked(udp.payload()) {
            Ok(packet) => packet,
            Err(e) => {
                return Err(Error::Malformed(f!("tftp: invalid packet: {}", e)));
            }
        };

        let is_write = tftp_packet.opcode() == tftp::parse::OpCode::Write;

        match tftp::parse::Repr::parse(&tftp_packet) {
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
            packet_builder: |data| tftp::parse::Packet::new_checked(data.as_ref()).unwrap(),
            repr_builder: |packet| tftp::parse::Repr::parse(packet).unwrap(),
        }
        .build();

        Ok((client, wrapper))
    }

    pub fn arp_respond(&self, rx_buffer: &[u8]) -> Result<Vec<u8>> {
        let arp = utils::ether_to_arp(rx_buffer)?;

        match arp {
            ArpRepr::EthernetIpv4 {
                operation,
                target_protocol_addr,
                target_hardware_addr: _,
                source_hardware_addr,
                source_protocol_addr,
            } => {
                if target_protocol_addr != self.server_ip {
                    return Err(Error::Ignore(f!(
                        "Ignoring arp packet with target ip: {}",
                        target_protocol_addr
                    )));
                }

                if operation != smoltcp::wire::ArpOperation::Request {
                    return Err(Error::Ignore(f!(
                        "Ignoring arp packet with operation: {:?}",
                        operation
                    )));
                }

                let arp = ArpRepr::EthernetIpv4 {
                    operation: smoltcp::wire::ArpOperation::Reply,
                    source_hardware_addr: self.server_mac,
                    source_protocol_addr: self.server_ip,
                    target_hardware_addr: source_hardware_addr,
                    target_protocol_addr: source_protocol_addr,
                };

                let packet = utils::arp_reply(arp);

                Ok(packet)
            }
            _ => todo!(),
        }
    }
}

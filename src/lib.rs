#![allow(dead_code)]
#![allow(unused_imports)]

pub mod construct;
pub mod dhcp_options;
pub mod error;
pub mod parse;
pub mod prelude;

pub mod tftp_state;
pub mod udp_port_check;
mod utils;
use prelude::*;
use smolapps::wire::tftp::Repr;
use smoltcp::wire::ArpRepr;

use crate::tftp_state::Handle;
use crate::tftp_state::TestTftp;
use crate::tftp_state::TftpConnection;
use crate::tftp_state::Transfer;
use log::*;

use core::panic;
use ouroboros::self_referencing;
use rand::prelude::*;
use smolapps::wire::tftp::TftpOption;
use smolapps::wire::tftp::TftpOptsReader;
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
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use uuid::Uuid;

use smolapps::wire::tftp;

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

#[derive(Debug)]
enum PxeStates {
    Discover,
    Request(u32),
    ArpRequest,
    Tftp(TftpStates),
    Done,
}

#[derive(Debug)]
pub enum TftpStates {
    Tsize,
    BlkSize,
    Data { blksize: usize },
    Error,
}

#[derive(Debug)]
pub struct PxeSocket {
    pub(crate) state: PxeStates,
    pub(crate) stage_one: PathBuf,
    pub(crate) transfers: HashMap<TftpConnection, Transfer<TestTftp>>,
    pub(crate) server_mac: EthernetAddress,
    pub(crate) server_ip: Ipv4Address,
    pub(crate) tftp_endpoint: IpListenEndpoint,
}

impl PxeSocket {
    pub fn new(server_ip: Ipv4Address, server_mac: EthernetAddress, stage_one: &Path) -> Self {
        log::info!("Starting server with ip: {}", server_ip);

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

        let transfers: HashMap<TftpConnection, Transfer<TestTftp>> = HashMap::new();

        Self {
            state,
            transfers,
            server_mac,
            server_ip,
            tftp_endpoint,
            stage_one: stage_one.to_path_buf(),
        }
    }

    pub fn process(&mut self, rx_buffer: &[u8]) -> Result<Vec<u8>> {
        match self.state {
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
                    let info = crate::parse::pxe_discover(dhcp)?;

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

                let dhcp_repr = construct::pxe_offer(&info, &self.server_ip);
                let packet = utils::dhcp_to_ether_brdcast(
                    dhcp_repr.borrow_repr(),
                    &self.server_ip,
                    &self.server_mac,
                );

                log::info!("Sent PXE Offer");
                log::info!("Waiting for PXE Request");

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
                self.state = PxeStates::Request(info.transaction_id);

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

                    let info = crate::parse::pxe_discover(dhcp)?;

                    if info.msg_type != DhcpMessageType::Request {
                        return Err(Error::Ignore("Not a dhcp request packet".to_string()));
                    }

                    if info.transaction_id != transaction_id {
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
                let dhcp_repr = construct::pxe_ack(&info, &self.tftp_endpoint);
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
                log::info!("Changing to tftp tsize state");
                self.state = PxeStates::Tftp(TftpStates::Tsize);

                Ok(packet)
            }
            PxeStates::ArpRequest => {
                let packet = self.arp_respond(rx_buffer)?;
                self.state = PxeStates::Tftp(TftpStates::Tsize);

                Ok(packet)
            }
            PxeStates::Tftp(ref tftp_state) => {
                let (tftp_con, wrapper) = self.recv_tftp(rx_buffer)?;

                match tftp_state {
                    TftpStates::Tsize => {
                        let packet = self.reply_tsize(&wrapper, tftp_con).unwrap();

                        log::info!("Changing to blksize state");
                        self.state = PxeStates::Tftp(TftpStates::BlkSize);

                        Ok(packet)
                    }
                    TftpStates::BlkSize => {
                        let (packet, blksize) = self.reply_blksize(&wrapper, tftp_con)?;

                        log::info!("Changing to tftp data state");
                        self.state = PxeStates::Tftp(TftpStates::Data { blksize });

                        Ok(packet)
                    }
                    TftpStates::Data { blksize } => {
                        match self.reply_data(&wrapper, tftp_con, *blksize) {
                            Ok(packet) => Ok(packet),
                            Err(Error::TftpEndOfFile) => {
                                log::info!("Changing to tftp done state");
                                self.state = PxeStates::Done;
                                Err(Error::IgnoreNoLog("End of file reached".to_string()))
                            }
                            Err(e) => Err(e),
                        }
                    }
                    TftpStates::Error => todo!(),
                }
            }
            PxeStates::Done => {
                log::info!("PXE Done");
                self.state = PxeStates::Discover;
                self.transfers.clear();
                Err(Error::IgnoreNoLog("PXE Done".to_string()))
            }
        }
    }

    pub fn reply_data(
        &mut self,
        wrapper: &TftpPacketWrapper,
        tftp_con: TftpConnection,
        blksize: usize,
    ) -> Result<Vec<u8>> {
        let xfer_idx = self.transfers.get_mut(&tftp_con);

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
                    return Err(Error::TftpEndOfFile);
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

                Ok(packet)
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

    pub fn reply_blksize(
        &mut self,
        wrapper: &TftpPacketWrapper,
        tftp_con: TftpConnection,
    ) -> Result<(Vec<u8>, usize)> {
        let xfer_idx = self.transfers.get(&tftp_con);
        {
            match (*wrapper.borrow_repr(), xfer_idx) {
                (
                    Repr::ReadRequest {
                        filename: _,
                        mode,
                        opts,
                    },
                    None,
                ) => {
                    if mode != tftp::Mode::Octet {
                        return Err(Error::Tftp("Only octet mode is supported".to_string()));
                    }

                    let _t = {
                        let xfer_idx = TestTftp {
                            file: File::open(&self.stage_one)
                                .expect("Failed to open stage one bootloader"),
                        };

                        let transfer =
                            Transfer::new(xfer_idx, tftp_con, *wrapper.borrow_is_write());

                        self.transfers.insert(tftp_con, transfer);
                        self.transfers.get_mut(&tftp_con).unwrap()
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

                        Ok((packet, blksize))
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

    pub fn reply_tsize(
        &mut self,
        wrapper: &TftpPacketWrapper,
        tftp_con: TftpConnection,
    ) -> Result<Vec<u8>> {
        let xfer_idx = self.transfers.get(&tftp_con);
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

                        let transfer =
                            Transfer::new(xfer_idx, tftp_con, *wrapper.borrow_is_write());

                        self.transfers.insert(tftp_con, transfer);
                        self.transfers.get_mut(&tftp_con).unwrap()
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

                        Ok(packet)
                    } else {
                        Err(Error::Tftp("tftp: tsize option not found".to_string()))
                    }
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
    }

    pub fn recv_tftp(&self, rx_buffer: &[u8]) -> Result<(TftpConnection, TftpPacketWrapper)> {
        let (udp, src_endpoint, src_mac_addr) =
            crate::utils::unicast_ether_to_udp(rx_buffer, &self.server_mac, &self.server_ip)?;

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
            server_ip: self.server_ip,
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

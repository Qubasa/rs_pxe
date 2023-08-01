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
pub enum PxeStates {
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
    _state: PxeStates,
    stage_one: PathBuf,
    stage_one_name: String,
    transfers: HashMap<TftpConnection, Transfer<TestTftp>>,
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
    pub fn get_stage_one(&self) -> &PathBuf {
        &self.stage_one
    }
    fn set_state(&mut self, state: PxeStates) {
        debug!("Changing state to {:?}", state);
        self._state = state;
    }

    pub fn new(server_ip: Ipv4Address, server_mac: EthernetAddress, stage_one: &Path) -> Self {
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

        let transfers: HashMap<TftpConnection, Transfer<TestTftp>> = HashMap::new();

        let stage_one_name = stage_one.file_name().unwrap().to_str().unwrap().to_string();

        if stage_one_name.len() > 127 {
            panic!("Stage one file name is too long");
        }

        Self {
            _state: state,
            transfers,
            server_mac,
            server_ip,
            tftp_endpoint,
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
                let dhcp_repr = construct::pxe_offer(&info, &self.server_ip, &self.stage_one_name);
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
                self.set_state(PxeStates::Request(info.transaction_id));

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
                    construct::pxe_ack(&info, &self.tftp_endpoint, &self.stage_one_name);
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
                        let ack_opts = self.parse_ack_options(&wrapper, tftp_con)?;

                        if ack_opts.contains_key("tsize") && ack_opts.contains_key("blksize") {
                            let blksize =
                                ack_opts.get("blksize").unwrap().parse::<usize>().unwrap();
                            self.set_state(PxeStates::Tftp(TftpStates::Data { blksize }));
                        } else if ack_opts.contains_key("tsize") {
                            self.set_state(PxeStates::Tftp(TftpStates::BlkSize));
                        } else {
                            return Err(Error::Tftp(f!(
                                "Missing tsize option. Got options: {:?}",
                                ack_opts
                            )));
                        }
                        let packet = self.ack_options(&ack_opts, &tftp_con)?;
                        Ok(packet)
                    }
                    TftpStates::BlkSize => {
                        let ack_opts = {
                            match self.parse_ack_options(&wrapper, tftp_con) {
                                Ok(ack_opts) => ack_opts,
                                Err(e) => {
                                    if let Error::TftpReceivedError(code, msg) = e {
                                        if code == 0 {
                                            return Err(Error::IgnoreNoLog(msg));
                                        } else {
                                            return Err(Error::TftpReceivedError(code, msg));
                                        }
                                    } else {
                                        return Err(e);
                                    }
                                }
                            }
                        };

                        match ack_opts.get("blksize") {
                            Some(blksize) => {
                                let blksize = blksize.parse::<usize>().unwrap();
                                self.set_state(PxeStates::Tftp(TftpStates::Data { blksize }));
                            }
                            None => {
                                return Err(Error::Tftp(f!(
                                    "Missing blksize option. Got options: {:?}",
                                    ack_opts
                                )));
                            }
                        }

                        let packet = self.ack_options(&ack_opts, &tftp_con)?;
                        Ok(packet)
                    }
                    TftpStates::Data { blksize } => {
                        match self.reply_data(&wrapper, tftp_con, *blksize) {
                            Ok(packet) => Ok(packet),
                            Err(Error::TftpEndOfFile) => {
                                self.set_state(PxeStates::Done);
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
                self.set_state(PxeStates::Discover);
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
                Err(Error::TftpReceivedError(code.into(), msg.to_string()))
            }
            (packet, ..) => Err(Error::Tftp(f!(
                "Received unexpected tftp packet: {:?}. ",
                packet
            ))),
        }
    }

    pub fn ack_options(
        &mut self,
        ack_opts: &HashMap<String, String>,
        tftp_con: &TftpConnection,
    ) -> Result<Vec<u8>> {
        let needed_bytes = ack_opts
            .iter()
            .fold(0, |acc, (name, value)| acc + name.len() + value.len() + 2);

        let mut resp_opt_buf = vec![0u8; needed_bytes];
        let mut written_bytes = 0;
        let mut opt_resp = tftp::TftpOptsWriter::new(resp_opt_buf.as_mut_slice());

        for (name, value) in ack_opts {
            let opt = TftpOption { name, value };
            opt_resp.emit(opt).unwrap();
            written_bytes += opt_resp.len();
        }

        debug_assert!(written_bytes == needed_bytes);
        let opts = tftp::TftpOptsReader::new(&resp_opt_buf[..written_bytes]);

        let ack = Repr::OptionAck { opts };
        let packet = crate::utils::tftp_to_ether_unicast(&ack, tftp_con);
        Ok(packet)
    }

    pub fn parse_ack_options(
        &mut self,
        wrapper: &TftpPacketWrapper,
        tftp_con: TftpConnection,
    ) -> Result<HashMap<String, String>> {
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

                    let t: &mut Transfer<TestTftp> = {
                        let xfer_idx = TestTftp {
                            file: File::open(self.get_stage_one()).unwrap(),
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

                    let mut ack_opts: HashMap<String, String> = HashMap::new();
                    for opt in opts.options() {
                        let (name, value) = (opt.name, opt.value);

                        match name {
                            "blksize" => {
                                let blksize = match value.parse::<usize>() {
                                    Ok(blksize) => blksize,
                                    Err(_) => {
                                        return Err(Error::Tftp(f!(
                                            "tftp: blksize option should be a number is however {}",
                                            value
                                        )));
                                    }
                                };
                                ack_opts.insert(name.to_string(), blksize.to_string());
                            }
                            "tsize" => {
                                let tsize = t.handle.file.metadata()?.len();
                                ack_opts.insert(name.to_string(), tsize.to_string());
                            }
                            _ => {}
                        }
                    }

                    Ok(ack_opts)
                }
                (Repr::Error { code, msg }, None | Some(_)) => {
                    Err(Error::TftpReceivedError(code.into(), msg.to_string()))
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
            server_mac: self.server_mac,
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

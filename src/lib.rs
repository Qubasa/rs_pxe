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
use tftp::construct::TftpError;
use tftp::construct::TftpOptionEnum;
use tftp::parse::Repr;
use tftp::socket::{TftpPacketWrapper, TftpPacketWrapperBuilder, TftpSocket};

use log::*;
use tftp::construct::Handle;
use tftp::construct::TestTftp;
use tftp::construct::TftpConnection;
use tftp::construct::Transfer;

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

use crate::tftp::socket::TftpStates;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PxeStates {
    Discover,
    Request(u32),
    Tftp,
}

impl Display for PxeStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PxeStates::Discover => write!(f, "Discover"),
            PxeStates::Request(transaction_id) => {
                write!(f, "Request {{ transaction_id: {:#x} }}", transaction_id)
            }
            PxeStates::Tftp => write!(f, "Tftp"),
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
    server_mac: EthernetAddress,
    server_ip: Ipv4Address,
    free_port: IpListenEndpoint,
    tftp_socket: Option<TftpSocket>,
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

    pub fn process_timeout(&mut self) -> Result<Vec<u8>> {
        if let Some(tftp_socket) = &mut self.tftp_socket {
            return tftp_socket.process_timeout();
        }
        Err(Error::IgnoreNoLog("Nothing todo".to_string()))
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
        let free_port = {
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
            tftp_socket: None,
            is_stage_two: false,
            server_mac,
            server_ip,
            free_port,
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
                        self.set_state(PxeStates::Tftp);
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
                    dhcp::construct::pxe_ack(&info, &self.free_port, &self.stage_one_name);
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

                self.set_state(PxeStates::Tftp);

                Ok(packet)
            }

            PxeStates::Tftp => {
                if let None = self.tftp_socket {
                    let tftp_socket = {
                        if self.is_stage_two {
                            TftpSocket::new(self.server_mac, self.server_ip, self.get_stage_two())
                        } else {
                            TftpSocket::new(self.server_mac, self.server_ip, self.get_stage_one())
                        }
                    };
                    self.tftp_socket = Some(tftp_socket);
                }

                match self.tftp_socket.as_mut().unwrap().process(rx_buffer) {
                    Err(Error::TftpEndOfFile) => {
                        self.set_state(PxeStates::Discover);
                        Err(Error::TftpEndOfFile)
                    }
                    Ok(packet) => Ok(packet),
                    Err(e) => Err(e),
                }
            }
        }
    }
}

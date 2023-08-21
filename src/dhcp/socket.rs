#![allow(unused_imports)]

use log::*;
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
use std::fmt::write;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use uuid::Uuid;

use crate::dhcp;
use crate::dhcp::utils::DhcpConnection;

use super::parse::PxeClientInfo;
use super::utils;

use super::error::*;
use super::utils::TargetingScope;

#[derive(Debug, Clone)]
pub enum DhcpStates {
    Discover,
    Request,
    WaitForDhcpAck(PxeClientInfo),
    ArpReply,
    Done,
}

impl Display for DhcpStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DhcpStates::Discover => write!(f, "Discover"),
            DhcpStates::Request => {
                write!(f, "Request")
            }
            DhcpStates::Done => write!(f, "Done"),
            DhcpStates::WaitForDhcpAck(_info) => {
                write!(f, "WaitForDhcpAck")
            }
            DhcpStates::ArpReply => write!(f, "ArpReply"),
        }
    }
}

#[derive(Debug)]
pub struct DhcpSocket {
    _state: DhcpStates,
    offer_file_name: String,
    server_mac: EthernetAddress,
    server_ip: Ipv4Address,
    firmware_type: Option<dhcp::parse::FirmwareType>,
}

impl DhcpSocket {
    pub fn get_server_ip(&self) -> Ipv4Address {
        self.server_ip
    }
    pub fn get_firmware_type(&self) -> Option<dhcp::parse::FirmwareType> {
        self.firmware_type
    }
    pub fn get_server_mac(&self) -> EthernetAddress {
        self.server_mac
    }
    pub fn get_state(&self) -> &DhcpStates {
        &self._state
    }
    fn set_state(&mut self, state: DhcpStates) {
        debug!("Changing state to {}", state);
        self._state = state;
    }

    pub fn new(server_ip: Ipv4Address, server_mac: EthernetAddress, offer_file: &Path) -> Self {
        log::debug!(
            "Creating DHCP socket with ip: {} and mac {}",
            server_ip,
            server_mac
        );

        let server_ip = Ipv4Address::from_bytes(server_ip.as_bytes());

        // State machine
        let state = DhcpStates::Discover;

        let offer_file_name = offer_file
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        if offer_file_name.len() > 127 {
            panic!("Offer file name is too long");
        }

        Self {
            _state: state,
            server_mac,
            server_ip,
            offer_file_name,
            firmware_type: None,
        }
    }

    pub fn process(&mut self, rx_buffer: &[u8]) -> Result<Vec<u8>> {
        match self.get_state() {
            DhcpStates::Discover => {
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
                    let dhcp = super::utils::broadcast_ether_to_dhcp(rx_buffer)?;
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
                    dhcp::construct::pxe_offer(&info, &self.server_ip, &self.offer_file_name);
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
                    dhcp::parse::FirmwareType::Unknown => {
                        self.set_state(DhcpStates::ArpReply);
                    }
                    dhcp::parse::FirmwareType::IPxe => {
                        info!("iPXE firmware detected. Jumping to TFTP phase");
                        self.set_state(DhcpStates::Done);
                    }
                }
                self.firmware_type = Some(info.firmware_type);

                Ok(packet)
            }
            DhcpStates::Request => {
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
                let (info, connection) = {
                    let (dhcp, scope, connection) = utils::uni_broad_ether_to_dhcp(
                        rx_buffer,
                        &self.server_mac,
                        &self.server_ip,
                    )?;

                    let info = dhcp::parse::pxe_discover(dhcp)?;

                    if info.msg_type != DhcpMessageType::Request {
                        return Err(Error::Ignore("Not a dhcp request packet".to_string()));
                    }

                    match scope {
                        utils::TargetingScope::Unicast => (),
                        utils::TargetingScope::Broadcast => {
                            self.set_state(DhcpStates::WaitForDhcpAck(info));
                            return Err(Error::WaitForDhcpAck);
                        }
                        utils::TargetingScope::Multicast => todo!("Multicast is not supported"),
                    }

                    Ok::<_, Error>((info, connection))
                }?;

                log::info!("Parsed PXE Request");
                log::info!("Sending PXE ACK.");

                // Breaks here because we send an ACK with IP broadcast back but we need to send an ACK with IP unicast
                // However to know the IP Address of the PXE Client we need to wait for the DHCP server to ACK the Requested IP first
                // Then we use that IP to send ourselves a PXE ACK

                /* ================== Send PXE ACK ================== */
                /*
                Step 6. The Boot Server unicasts a DHCPACK packet back to the client on the client source port.
                This reply packet contains:
                    - Boot file name.
                    - MTFTP configuration parameters.
                    - Any other options the NBP requires before it can be successfully executed.
                */

                let dhcp_repr =
                    dhcp::construct::pxe_ack(&info, self.server_ip, &self.offer_file_name);
                let packet = utils::dhcp_to_ether_unicast(dhcp_repr.borrow_repr(), connection);

                log::info!("Sent PXE ACK");

                /*
                Step 7. The client downloads the executable file using either standard TFTP (port69) or MTFTP
                (port assigned in Boot Server Ack packet). The file downloaded and the placement of the
                downloaded code in memory is dependent on the client’s CPU architecture.
                */

                self.set_state(DhcpStates::Done);

                Ok(packet)
            }
            DhcpStates::WaitForDhcpAck(info) => {
                let dhcp = utils::handle_dhcp_ack(rx_buffer).unwrap();
                let client_ip_addr = dhcp.your_ip();

                let dhcp_repr =
                    dhcp::construct::pxe_ack(info, self.server_ip, &self.offer_file_name);
                // let packet = utils::dhcp_to_ether_unicast(
                //     dhcp_repr.borrow_repr(),
                //     &client_ip_addr,
                //     &dhcp.client_hardware_address(),
                //     &self.server_ip,
                //     &self.server_mac,
                // );

                log::info!("Sent PXE ACK");

                /*
                Step 7. The client downloads the executable file using either standard TFTP (port69) or MTFTP
                (port assigned in Boot Server Ack packet). The file downloaded and the placement of the
                downloaded code in memory is dependent on the client’s CPU architecture.
                */

                self.set_state(DhcpStates::ArpReply);
                todo!();
                // Ok(packet)

                //self.set_state(DhcpStates::Request(info.transaction_id));
            }
            DhcpStates::ArpReply => {
                let packet = utils::arp_respond(rx_buffer, &self.server_ip, &self.server_mac)?;
                self.set_state(DhcpStates::Request);
                Ok(packet)
            }
            DhcpStates::Done => Err(Error::DhcpProtocolFinished),
        }
    }
}

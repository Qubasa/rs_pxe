use log::*;
use smoltcp::iface::Config;
use smoltcp::iface::Routes;
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::Checksum;
use smoltcp::phy::Device;
use smoltcp::phy::Medium;
use smoltcp::phy::RawSocket;
use smoltcp::phy::RxToken;
use smoltcp::phy::TxToken;
use smoltcp::time::Instant;
use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::HardwareAddress;

use crate::dhcp_options::DhcpOption;
use crate::{prelude::*, *};
use rand::prelude::*;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;
use smoltcp::{iface::Interface, phy::ChecksumCapabilities};
use std::borrow::BorrowMut;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use uuid::Uuid;

pub struct PxeClientInfo {
    system_arches: Vec<ClientArchType>,
    vendor_id: Option<String>,
    msg_type: DhcpMessageType,
    network_interface_version: NetworkInterfaceVersion,
}

pub fn pxe_recv(buffer: &mut [u8]) -> Result<PxeClientInfo> {
    let mut system_arches: Vec<ClientArchType> = vec![];
    let mut vendor_id: Option<String> = None;
    let mut msg_type: Option<DhcpMessageType> = None;
    let mut network_interface_version: Option<NetworkInterfaceVersion> = None;
    let ether = EthernetFrame::new_checked(&buffer).unwrap();

    if ether.dst_addr() != EthernetAddress::BROADCAST {
        return Err(Error::Ignore("Not a broadcast packet".to_string()));
    }
    log::info!("Received broadcast packet from {}", ether.src_addr());

    let ipv4 = match Ipv4Packet::new_checked(ether.payload()) {
        Ok(i) => i,
        Err(e) => {
            let err = format!("Parsing ipv4 packet failed: {}", e);
            return Err(Error::Ignore(err));
        }
    };

    if ipv4.dst_addr() != Ipv4Address::BROADCAST {
        return Err(Error::Ignore("Not a broadcast packet".to_string()));
    }

    let udp = match UdpPacket::new_checked(ipv4.payload()) {
        Ok(u) => u,
        Err(e) => {
            let err = format!("Parsing udp packet failed: {}", e);
            return Err(Error::Ignore(err));
        }
    };

    if udp.dst_port() != 67 {
        return Err(Error::Ignore("Not a dhcp packet".to_string()));
    }

    let dhcp = match DhcpPacket::new_checked(udp.payload()) {
        Ok(d) => d,
        Err(e) => {
            let err = format!("Parsing dhcp packet failed: {}", e);
            return Err(Error::Ignore(err));
        }
    };

    if dhcp.opcode() != DhcpMessageType::Request.opcode() {
        return Err(Error::Ignore("Not a dhcp request".to_string()));
    }

    for option in dhcp.options() {
        if let Ok(opt_kind) = DhcpOption::try_from(option.kind) {
            match opt_kind {
                DhcpOption::MessageType => {
                    // Message Type
                    let mtype = DhcpMessageType::try_from(option.data[0])
                        .map_err(|e| Error::Malformed(f!("Invalid message type: {}", e)))?;
                    msg_type = Some(mtype);
                }
                DhcpOption::ClientSystemArchitecture => {
                    // Client System Architecture
                    let (prefix, body, suffix) = unsafe { option.data.align_to::<u16>() };
                    if !prefix.is_empty() || !suffix.is_empty() {
                        return Err(Error::Static("Invalid arch type list. Improperly aligned"));
                    }
                    system_arches = body
                        .iter()
                        .map(|&i| ClientArchType::try_from(u16::from_be(i)).unwrap())
                        .collect();
                }
                DhcpOption::ClientNetworkInterfaceIdentifier => {
                    let t = NetworkInterfaceVersion::try_from(option.data).map_err(|e| {
                        Error::Malformed(f!("Invalid network interface version: {}", e))
                    })?;

                    network_interface_version = Some(t);
                }
                DhcpOption::ClientUuid => {
                    // Client Machine ID
                    let uuid = Uuid::from_slice(option.data)
                        .map_err(|e| Error::Malformed(f!("Invalid UUID: {}", e)))?;
                }
                DhcpOption::VendorClassIdentifier => {
                    // Class Identifier
                    let s = String::from_utf8(option.data.to_vec())
                        .map_err(|e| Error::Malformed(f!("Invalid class identifier: {}", e)))?;

                    vendor_id = Some(s);
                }

                _ => {
                    warn!("Unhandled PXE option: {:?}", opt_kind)
                }
            }
        }
    }

    Ok(PxeClientInfo {
        system_arches,
        vendor_id,
        msg_type: msg_type.ok_or(Error::MissingDhcpOption)?,
        network_interface_version: network_interface_version.ok_or(Error::MissingDhcpOption)?,
    })
}

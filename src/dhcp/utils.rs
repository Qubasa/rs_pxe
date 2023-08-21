use std::fmt::Display;
use std::net::IpAddr;
use std::os::fd::AsRawFd;

use crate::dhcp::parse::PxeClientInfo;
use crate::tftp;
use crate::tftp::construct::Handle;
use crate::tftp::construct::TftpConnection;

use env_logger::Target;
use ouroboros::self_referencing;

use smoltcp::iface::Interface;
use smoltcp::iface::SocketSet;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::phy::Device;
use smoltcp::phy::RawSocket;
use smoltcp::socket::dhcpv4;
use smoltcp::time::Instant;
use smoltcp::wire::ArpRepr;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Cidr;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::Ipv4Repr;
use smoltcp::wire::UdpPacket;
use smoltcp::wire::UdpRepr;

use super::error::*;

pub fn broadcast_ether_to_dhcp(buffer: &[u8]) -> Result<DhcpPacket<&[u8]>> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
    if ether.dst_addr() != EthernetAddress::BROADCAST {
        return Err(Error::IgnoreNoLog("Not a broadcast packet".to_string()));
    }

    let ipv4 = match Ipv4Packet::new_checked(ether.payload()) {
        Ok(i) => i,
        Err(e) => {
            let err = format!("Parsing ipv4 packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    if ipv4.dst_addr() != Ipv4Address::BROADCAST {
        return Err(Error::IgnoreNoLog("Not a broadcast packet".to_string()));
    }

    let udp = match UdpPacket::new_checked(ipv4.payload()) {
        Ok(u) => u,
        Err(e) => {
            let err = format!("Parsing udp packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    if udp.dst_port() != 67 {
        return Err(Error::IgnoreNoLog("Not a dhcp packet".to_string()));
    }

    let dhcp = match DhcpPacket::new_checked(udp.payload()) {
        Ok(d) => d,
        Err(e) => {
            let err = format!("Parsing dhcp packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };
    Ok(dhcp)
}

#[derive(Debug, Copy, Clone)]
pub enum TargetingScope {
    Unicast,
    Broadcast,
    Multicast,
}

pub fn arp_reply(repr: ArpRepr) -> Vec<u8> {
    match repr {
        ArpRepr::EthernetIpv4 {
            operation: smoltcp::wire::ArpOperation::Reply,
            source_hardware_addr,
            source_protocol_addr: _,
            target_hardware_addr,
            target_protocol_addr: _,
        } => {
            let eth_packet = EthernetRepr {
                dst_addr: target_hardware_addr,
                src_addr: source_hardware_addr,
                ethertype: EthernetProtocol::Arp,
            };

            let packet_size = eth_packet.buffer_len() + repr.buffer_len();

            let mut buffer = vec![0; packet_size];

            let mut packet = EthernetFrame::new_unchecked(&mut buffer[..]);
            eth_packet.emit(&mut packet);

            let mut packet = smoltcp::wire::ArpPacket::new_unchecked(packet.payload_mut());
            repr.emit(&mut packet);

            buffer
        }
        _ => todo!(),
    }
}

pub fn ether_to_arp(buffer: &[u8]) -> Result<ArpRepr> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
    if ether.dst_addr() != EthernetAddress::BROADCAST {
        return Err(Error::IgnoreNoLog("Not a broadcast packet".to_string()));
    }

    let packet = match smoltcp::wire::ArpPacket::new_checked(ether.payload()) {
        Ok(p) => p,
        Err(e) => {
            let err = format!("Parsing arp packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    let arp = match ArpRepr::parse(&packet) {
        Ok(a) => a,
        Err(e) => {
            let err = format!("Parsing arp packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };
    Ok(arp)
}

pub fn arp_respond(
    rx_buffer: &[u8],
    server_ip: &Ipv4Address,
    server_mac: &EthernetAddress,
) -> Result<Vec<u8>> {
    let arp = ether_to_arp(rx_buffer)?;

    match arp {
        ArpRepr::EthernetIpv4 {
            operation,
            target_protocol_addr,
            target_hardware_addr: _,
            source_hardware_addr,
            source_protocol_addr,
        } => {
            if target_protocol_addr != *server_ip {
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
                source_hardware_addr: *server_mac,
                source_protocol_addr: *server_ip,
                target_hardware_addr: source_hardware_addr,
                target_protocol_addr: source_protocol_addr,
            };

            let packet = arp_reply(arp);

            Ok(packet)
        }
        _ => todo!(),
    }
}

pub fn handle_dhcp_ack(buffer: &[u8]) -> Result<DhcpPacket<&[u8]>> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();

    if !ether.dst_addr().is_broadcast() {
        let err: String = format!("Mac address {} isn't broadcast", ether.dst_addr());
        return Err(Error::IgnoreNoLog(err));
    }

    let ipv4 = match Ipv4Packet::new_checked(ether.payload()) {
        Ok(i) => i,
        Err(e) => {
            let err = format!("Parsing ipv4 packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    if !ipv4.dst_addr().is_broadcast() {
        return Err(Error::IgnoreNoLog("Ip address isn't broadcast".to_string()));
    }

    let udp = match UdpPacket::new_checked(ipv4.payload()) {
        Ok(u) => u,
        Err(e) => {
            let err = format!("Parsing udp packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    if udp.dst_port() != 68 {
        return Err(Error::IgnoreNoLog(format!(
            "Not a dhcp packet. Port does not match ({} != 68)",
            udp.dst_port()
        )));
    }

    let dhcp = match DhcpPacket::new_checked(udp.payload()) {
        Ok(d) => d,
        Err(e) => {
            let err = format!("Parsing dhcp packet failed: {}", e);
            return Err(Error::Ignore(err));
        }
    };
    Ok(dhcp)
}

pub fn uni_broad_ether_to_dhcp<'a>(
    buffer: &'a [u8],
    server_mac: &'a EthernetAddress,
    server_ip: &'a Ipv4Address,
) -> Result<(DhcpPacket<&'a [u8]>, TargetingScope, DhcpConnection)> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
    if ether.dst_addr() != *server_mac {
        // && !ether.dst_addr().is_broadcast()
        let err: String = format!(
            "Mac address {} does not match with ours. And isn't broadcast",
            ether.dst_addr()
        );
        return Err(Error::IgnoreNoLog(err));
    }

    let ipv4 = match Ipv4Packet::new_checked(ether.payload()) {
        Ok(i) => i,
        Err(e) => {
            let err = format!("Parsing ipv4 packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    let target_scope: TargetingScope = {
        if ipv4.dst_addr().is_broadcast() {
            TargetingScope::Broadcast
        } else if ipv4.dst_addr().is_multicast() {
            TargetingScope::Multicast
        } else {
            debug_assert!(ipv4.dst_addr().is_unicast());
            TargetingScope::Unicast
        }
    };

    if ipv4.dst_addr() != *server_ip && !ipv4.dst_addr().is_broadcast() {
        return Err(Error::IgnoreNoLog(
            "IP destination does not match our server ip".to_string(),
        ));
    }

    let udp = match UdpPacket::new_checked(ipv4.payload()) {
        Ok(u) => u,
        Err(e) => {
            let err = format!("Parsing udp packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    if ipv4.dst_addr().is_broadcast() {
        if udp.dst_port() != 67 {
            return Err(Error::IgnoreNoLog(format!(
                "Not a dhcp packet. Port does not match ({} != 67)",
                udp.dst_port()
            )));
        }
    } else if udp.dst_port() != 4011 {
        return Err(Error::IgnoreNoLog(format!(
            "Not a dhcp packet. Port does not match ({} != 4011)",
            udp.dst_port()
        )));
    }

    let dhcp = match DhcpPacket::new_checked(udp.payload()) {
        Ok(d) => d,
        Err(e) => {
            let err = format!("Parsing dhcp packet failed: {}", e);
            return Err(Error::Ignore(err));
        }
    };

    let connection = DhcpConnection {
        server_ip: server_ip.clone(),
        server_mac: server_mac.clone(),
        client_ip: dhcp.client_ip(),
        client_mac: dhcp.client_hardware_address(),
        server_port: udp.dst_port(),
        client_port: udp.src_port(),
    };

    Ok((dhcp, target_scope, connection))
}

pub fn dhcp_to_ether_brdcast<'a>(
    dhcp: &'a DhcpRepr<'a>,
    server_ip: &'a Ipv4Address,
    server_mac: &'a EthernetAddress,
) -> Vec<u8> {
    let mut checksum = ChecksumCapabilities::ignored();
    checksum.ipv4 = Checksum::Both;
    checksum.udp = Checksum::Both;

    let udp_packet = UdpRepr {
        src_port: 67,
        dst_port: 68,
    };
    let ip_packet = Ipv4Repr {
        src_addr: *server_ip,
        dst_addr: Ipv4Address::BROADCAST,
        hop_limit: 128,
        payload_len: dhcp.buffer_len() + udp_packet.header_len(),
        next_header: IpProtocol::Udp,
    };

    let eth_packet = EthernetRepr {
        dst_addr: EthernetAddress::BROADCAST,
        src_addr: *server_mac,
        ethertype: EthernetProtocol::Ipv4,
    };

    let packet_size = eth_packet.buffer_len()
        + ip_packet.buffer_len()
        + udp_packet.header_len()
        + dhcp.buffer_len();

    let mut buffer = vec![0; packet_size];

    let mut packet = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth_packet.emit(&mut packet);

    let mut packet = Ipv4Packet::new_unchecked(packet.payload_mut());
    ip_packet.emit(&mut packet, &checksum);

    assert!(dhcp.subnet_mask.is_none());

    let mut packet = UdpPacket::new_unchecked(packet.payload_mut());
    udp_packet.emit(
        &mut packet,
        &ip_packet.src_addr.into_address(),
        &ip_packet.dst_addr.into_address(),
        dhcp.buffer_len(),
        |buf| {
            let mut packet = DhcpPacket::new_unchecked(buf);
            dhcp.emit(&mut packet).unwrap();
        },
        &checksum,
    );
    buffer
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DhcpConnection {
    pub server_ip: Ipv4Address,
    pub server_mac: EthernetAddress,
    pub client_ip: Ipv4Address,
    pub client_mac: EthernetAddress,
    pub server_port: u16,
    pub client_port: u16,
}

impl Display for DhcpConnection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.client_ip, self.client_port, self.server_ip, self.server_port
        )
    }
}

pub fn dhcp_to_ether_unicast<'a>(dhcp: &'a DhcpRepr<'a>, con: DhcpConnection) -> Vec<u8> {
    let mut checksum = ChecksumCapabilities::ignored();
    checksum.ipv4 = Checksum::Both;
    checksum.udp = Checksum::Both;

    let udp_packet = UdpRepr {
        src_port: con.server_port,
        dst_port: con.client_port,
    };
    let ip_packet = Ipv4Repr {
        src_addr: con.server_ip,
        dst_addr: con.client_ip,
        hop_limit: 128,
        payload_len: dhcp.buffer_len() + udp_packet.header_len(),
        next_header: IpProtocol::Udp,
    };

    let eth_packet = EthernetRepr {
        dst_addr: con.client_mac,
        src_addr: con.server_mac,
        ethertype: EthernetProtocol::Ipv4,
    };

    let packet_size = eth_packet.buffer_len()
        + ip_packet.buffer_len()
        + udp_packet.header_len()
        + dhcp.buffer_len();

    let mut buffer = vec![0; packet_size];

    let mut packet = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth_packet.emit(&mut packet);

    let mut packet = Ipv4Packet::new_unchecked(packet.payload_mut());
    ip_packet.emit(&mut packet, &checksum);

    assert!(dhcp.subnet_mask.is_none());

    let mut packet = UdpPacket::new_unchecked(packet.payload_mut());
    udp_packet.emit(
        &mut packet,
        &ip_packet.src_addr.into_address(),
        &ip_packet.dst_addr.into_address(),
        dhcp.buffer_len(),
        |buf| {
            let mut packet = DhcpPacket::new_unchecked(buf);
            dhcp.emit(&mut packet).unwrap();
        },
        &checksum,
    );

    buffer
}

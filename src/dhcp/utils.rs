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

pub fn handle_dhcp_ack<'a>(
    buffer: &'a [u8],
    server_mac: &'a EthernetAddress,
    server_ip: &'a Ipv4Address,
) -> Result<DhcpPacket<&'a [u8]>> {
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
) -> Result<(DhcpPacket<&'a [u8]>, TargetingScope)> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
    if ether.dst_addr() != *server_mac && !ether.dst_addr().is_broadcast() {
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
    Ok((dhcp, target_scope))
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

pub fn dhcp_to_ether_unicast<'a>(
    dhcp: &'a DhcpRepr<'a>,
    ip_dst_addr: &'a Ipv4Address,
    mac_dst_addr: &'a EthernetAddress,
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
        dst_addr: *ip_dst_addr,
        hop_limit: 128,
        payload_len: dhcp.buffer_len() + udp_packet.header_len(),
        next_header: IpProtocol::Udp,
    };

    let eth_packet = EthernetRepr {
        dst_addr: *mac_dst_addr,
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

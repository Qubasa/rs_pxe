#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parse::PxeClientInfo;
use crate::tftp_state::Handle;
use crate::tftp_state::TftpConnection;
use ouroboros::self_referencing;
use smolapps::wire::tftp;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::phy::RawSocket;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Repr;
use smoltcp::wire::UdpRepr;

use crate::prelude::*;

use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;

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

pub fn uni_broad_ether_to_dhcp<'a>(
    buffer: &'a [u8],
    server_mac: &'a EthernetAddress,
    server_ip: &'a Ipv4Address,
) -> Result<DhcpPacket<&'a [u8]>> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
    if ether.dst_addr() != *server_mac && ether.dst_addr() != EthernetAddress::BROADCAST {
        return Err(Error::IgnoreNoLog(
            "Mac address does not match with ours. And isn't broardcast".to_string(),
        ));
    }

    let ipv4 = match Ipv4Packet::new_checked(ether.payload()) {
        Ok(i) => i,
        Err(e) => {
            let err = format!("Parsing ipv4 packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    if ipv4.dst_addr() != *server_ip && ipv4.dst_addr() != Ipv4Address::BROADCAST {
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

    if udp.dst_port() != 4011 && udp.dst_port() != 67 {
        return Err(Error::IgnoreNoLog(
            "Not a dhcp packet. Port does not match".to_string(),
        ));
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

pub fn unicast_ether_to_udp<'a>(
    buffer: &'a [u8],
    server_mac: &'a EthernetAddress,
    server_ip: &'a Ipv4Address,
) -> Result<(UdpPacket<&'a [u8]>, IpEndpoint, EthernetAddress)> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
    if ether.dst_addr() != *server_mac {
        return Err(Error::IgnoreNoLog(
            "Mac address does not match with ours. And isn't broardcast".to_string(),
        ));
    }

    let ipv4 = match Ipv4Packet::new_checked(ether.payload()) {
        Ok(i) => i,
        Err(e) => {
            let err = format!("Parsing ipv4 packet failed: {}", e);
            return Err(Error::IgnoreNoLog(err));
        }
    };

    if ipv4.dst_addr() != *server_ip {
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

    if udp.dst_port() != 69 {
        return Err(Error::IgnoreNoLog(
            "Not a TFTP packet. Port does not match".to_string(),
        ));
    }

    let src_endpoint = IpEndpoint::new(ipv4.src_addr().into_address(), udp.src_port());
    Ok((udp, src_endpoint, ether.src_addr()))
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

pub fn tftp_to_ether_unicast<'a>(tftp: &'a tftp::Repr<'a>, con: &'a TftpConnection) -> Vec<u8> {
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
        payload_len: tftp.buffer_len() + udp_packet.header_len(),
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
        + tftp.buffer_len();

    let mut buffer = vec![0; packet_size];

    let mut packet = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth_packet.emit(&mut packet);

    let mut packet = Ipv4Packet::new_unchecked(packet.payload_mut());
    ip_packet.emit(&mut packet, &checksum);

    let mut packet = UdpPacket::new_unchecked(packet.payload_mut());
    udp_packet.emit(
        &mut packet,
        &ip_packet.src_addr.into_address(),
        &ip_packet.dst_addr.into_address(),
        tftp.buffer_len(),
        |buf| {
            let mut packet = tftp::Packet::new_unchecked(buf);
            tftp.emit(&mut packet).unwrap();
        },
        &checksum,
    );
    buffer
}

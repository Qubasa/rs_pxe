#![allow(dead_code)]
#![allow(unused_imports)]

use std::net::IpAddr;
use std::os::fd::AsRawFd;

use crate::dhcp::parse::PxeClientInfo;
use crate::tftp;
use crate::tftp::construct::Handle;
use crate::tftp::construct::TftpConnection;

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

pub fn tftp_to_ether_unicast<'a>(
    tftp: &'a tftp::parse::Repr<'a>,
    con: &'a TftpConnection,
) -> Vec<u8> {
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
    log::trace!(
        "Sending tftp packet to {}:{} from {}:{}",
        ip_packet.dst_addr,
        udp_packet.dst_port,
        ip_packet.src_addr,
        udp_packet.src_port
    );

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
            let mut packet = tftp::parse::Packet::new_unchecked(buf);
            tftp.emit(&mut packet).unwrap();
        },
        &checksum,
    );
    buffer
}

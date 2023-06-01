#![allow(dead_code)]
#![allow(unused_imports)]

use crate::parse::PxeClientInfo;
use smoltcp::phy::Checksum;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::EthernetProtocol;
use smoltcp::wire::EthernetRepr;
use smoltcp::wire::IpProtocol;
use smoltcp::wire::Ipv4Repr;
use smoltcp::wire::UdpRepr;

use crate::prelude::*;

use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;

pub fn ether_to_dhcp(buffer: &[u8]) -> Result<DhcpPacket<&[u8]>> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
    if ether.dst_addr() != EthernetAddress::BROADCAST {
        return Err(Error::Ignore("Not a broadcast packet".to_string()));
    }

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
    Ok(dhcp)
}

pub fn dhcp_to_ether<'a>(
    buffer: &'a mut [u8],
    dhcp: &'a DhcpRepr<'a>,
    server_ip: &'a Ipv4Address,
    server_mac: &'a EthernetAddress,
) {
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
}

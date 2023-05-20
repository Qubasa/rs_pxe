#![allow(dead_code)]

pub mod construct;
pub mod dhcp_options;
pub mod error;
pub mod parse;
pub mod prelude;
mod utils;

use smoltcp::wire::DhcpPacket;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;

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

// let udp_packet = UdpRepr {
//     src_port: 67,
//     dst_port: 68,
// };

// let mut packet = EthernetFrame::new_unchecked(buffer);
// let eth_packet = EthernetRepr {
//     dst_addr: EthernetAddress::BROADCAST,
//     src_addr: server_mac_address,
//     ethertype: EthernetProtocol::Ipv4,
// };
// eth_packet.emit(&mut packet);

// let mut packet = Ipv4Packet::new_unchecked(packet.payload_mut());
// let ip_packet = Ipv4Repr {
//     src_addr: server_ip,
//     dst_addr: Ipv4Address::BROADCAST,
//     protocol: IpProtocol::Udp,
//     hop_limit: 128,
//     payload_len: dhcp_packet.buffer_len() + udp_packet.header_len(),
// };
// ip_packet.emit(&mut packet, &checksum);

// let mut packet = UdpPacket::new_unchecked(packet.payload_mut());
// udp_packet.emit(
//     &mut packet,
//     &server_ip.into(),
//     &Ipv4Address::BROADCAST.into(),
//     dhcp_packet.buffer_len(),
//     |buf| {
//         let mut packet = DhcpPacket::new_unchecked(buf);
//         dhcp_packet.emit(&mut packet).unwrap();
//     },
//     &checksum,
// );

// info!("Sending DHCP offer...");
// Ok(())

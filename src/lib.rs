#![allow(dead_code)]

pub mod dhcp_options;
pub mod error;
pub mod parse;
pub mod prelude;

use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;

use crate::dhcp_options::*;
use crate::prelude::*;

use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;

use std::convert::TryFrom;

use uuid::Uuid;

pub fn ether_to_dhcp(buffer: &[u8]) -> Result<DhcpPacket<&[u8]>> {
    let ether = EthernetFrame::new_checked(buffer).unwrap();
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
    Ok(dhcp)
}

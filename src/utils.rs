#![allow(dead_code)]
#![allow(unused_imports)]

use std::os::fd::AsRawFd;

use crate::parse::PxeClientInfo;
use crate::tftp_state::Handle;
use crate::tftp_state::TftpConnection;
use ouroboros::self_referencing;
use smolapps::wire::tftp;
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

    if udp.dst_port() != 4011 {
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
    log::debug!(
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
            let mut packet = tftp::Packet::new_unchecked(buf);
            tftp.emit(&mut packet).unwrap();
        },
        &checksum,
    );
    buffer
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

pub fn arp_announce(address: EthernetAddress, ip_addr: Ipv4Address) -> Vec<u8> {
    let arp_repr = ArpRepr::EthernetIpv4 {
        operation: smoltcp::wire::ArpOperation::Request,
        source_hardware_addr: address,
        source_protocol_addr: ip_addr,
        target_hardware_addr: EthernetAddress::from_bytes(&[0; 6]),
        target_protocol_addr: ip_addr,
    };

    let eth_packet = EthernetRepr {
        dst_addr: EthernetAddress::BROADCAST,
        src_addr: address,
        ethertype: EthernetProtocol::Arp,
    };

    let packet_size = eth_packet.buffer_len() + arp_repr.buffer_len();

    let mut buffer = vec![0; packet_size];

    let mut packet = EthernetFrame::new_unchecked(&mut buffer[..]);
    eth_packet.emit(&mut packet);

    let mut packet = smoltcp::wire::ArpPacket::new_unchecked(packet.payload_mut());
    arp_repr.emit(&mut packet);

    buffer
}

pub fn request_dhcp_ip<DeviceT: AsRawFd>(device: &mut DeviceT, iface: &mut Interface)
where
    DeviceT: for<'d> Device,
{
    // Create sockets
    let dhcp_socket = dhcpv4::Socket::new();

    let mut sockets = SocketSet::new(vec![]);
    let dhcp_handle = sockets.add(dhcp_socket);
    let fd = device.as_raw_fd();

    loop {
        let timestamp = Instant::now();
        iface.poll(timestamp, device, &mut sockets);

        let event = sockets.get_mut::<dhcpv4::Socket>(dhcp_handle).poll();
        match event {
            None => {}
            Some(dhcpv4::Event::Configured(config)) => {
                log::debug!("DHCP config acquired!");

                log::debug!("IP address:      {}", config.address);
                iface.update_ip_addrs(|ip_addr| {
                    ip_addr
                        .push(smoltcp::wire::IpCidr::Ipv4(config.address))
                        .unwrap();
                });

                if let Some(router) = config.router {
                    log::debug!("Default gateway: {}", router);
                    iface.routes_mut().add_default_ipv4_route(router).unwrap();
                } else {
                    log::debug!("Default gateway: None");
                    iface.routes_mut().remove_default_ipv4_route();
                }

                for (i, s) in config.dns_servers.iter().enumerate() {
                    log::debug!("DNS server {}:    {}", i, s);
                }
                break;
            }
            Some(dhcpv4::Event::Deconfigured) => {
                log::debug!("DHCP lost config!");
                //set_ipv4_addr(&mut iface, Ipv4Cidr::new(Ipv4Address::UNSPECIFIED, 0));
                iface.routes_mut().remove_default_ipv4_route();
            }
        }

        smoltcp::phy::wait(fd, iface.poll_delay(timestamp, &sockets)).expect("wait error");
    }
    let time = Instant::now();
    smoltcp::phy::wait(fd, None).unwrap();
    let (_rx_token, tx_token) = device.receive(time).unwrap();

    // Get interface mac and ip
    let server_mac = match iface.hardware_addr() {
        HardwareAddress::Ethernet(addr) => addr,
        _ => panic!("Currently we only support ethernet"),
    };
    let server_ip = iface.ipv4_addr().unwrap();

    use smoltcp::phy::TxToken;
    let packet = arp_announce(server_mac, server_ip);
    tx_token.consume(packet.len(), |buffer| {
        buffer.copy_from_slice(&packet);
    });
}

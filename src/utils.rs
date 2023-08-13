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

use crate::prelude::*;

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

pub fn get_ip<DeviceT: AsRawFd + smoltcp::phy::Device>(
    device: &mut DeviceT,
    iface: &mut Interface,
) {
    match local_ip_address::local_ip() {
        Ok(ip) => {
            let ip = match ip {
                IpAddr::V4(ip) => {
                    let t = Ipv4Address::from_bytes(&ip.octets());
                    Ipv4Cidr::new(t, 24)
                }
                IpAddr::V6(_ip) => {
                    panic!("IPv6 not supported");
                }
            };
            log::info!("Local IP address: {}", ip);
            iface.update_ip_addrs(|ip_addr| {
                ip_addr.push(smoltcp::wire::IpCidr::Ipv4(ip)).unwrap();
            });
        }
        Err(e) => {
            log::error!("Failed to get local ip address: {}", e);
            request_dhcp_ip(device, iface);
        }
    };
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

    log::info!("Requesting DHCP IP address");
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
                iface.routes_mut().remove_default_ipv4_route();
            }
        }

        smoltcp::phy::wait(fd, iface.poll_delay(timestamp, &sockets)).expect("dhcp timeout error");
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

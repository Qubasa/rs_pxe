#![allow(clippy::option_map_unit_fn)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(dead_code)]
mod cli_opts;

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

use crate::dhcp_options::*;
use prelude::*;
use rs_pxe::*;

//RFC: https://datatracker.ietf.org/doc/html/rfc2132
fn main() {
    cli_opts::setup_logging("");
    info!("Starting pxe....");

    let (mut opts, mut _free) = cli_opts::create_options();

    let mut matches = cli_opts::parse_options(&opts, _free);
    let t = &matches.opt_str("mac").unwrap();
    let hardware_addr: &EthernetAddress = &EthernetAddress::from_str(t).unwrap();
    let t = &matches.opt_str("ip").unwrap();
    let ip = &matches
        .opt_get_default("ip", IpAddress::from_str(t).unwrap())
        .unwrap();
    let ip_addrs = [IpCidr::new(*ip, 24)];

    if matches.opt_present("raw") {
        let interface = matches.opt_str("raw").unwrap();
        let mut device = RawSocket::new(&interface, Medium::Ethernet).unwrap();

        // Create interface
        let mut config = match device.capabilities().medium {
            Medium::Ethernet => Config::new(Into::into(*hardware_addr)),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device);

        iface.update_ip_addrs(|ip_addr| {
            ip_addr.push(IpCidr::new(*ip, 24)).unwrap();
        });

        server(&mut device, &mut iface);
    } else if matches.opt_present("tun") || matches.opt_present("tap") {
        let mut device = cli_opts::parse_tuntap_options(&mut matches);

        // Create interface
        let mut config = match device.capabilities().medium {
            Medium::Ethernet => Config::new(Into::into(*hardware_addr)),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device);

        iface.update_ip_addrs(|ip_addr| {
            ip_addr.push(IpCidr::new(*ip, 24)).unwrap();
        });

        server(&mut device, &mut iface);
    } else {
        let brief = "Either --raw or --tun or --tap must be specified";
        panic!("{}", opts.usage(brief));
    };
}

pub fn server<DeviceT: AsRawFd>(device: &mut DeviceT, iface: &mut Interface)
where
    DeviceT: for<'d> Device,
{
    log::info!("Starting server");
    let fd = device.as_raw_fd();
    let server_mac_address = match iface.hardware_addr() {
        HardwareAddress::Ethernet(addr) => addr,
        _ => panic!("Currently we only support ethernet"),
    };
    let server_ip = iface.ipv4_addr().unwrap();
    let mut checksum = ChecksumCapabilities::ignored();
    checksum.ipv4 = Checksum::Both;
    checksum.udp = Checksum::Both;

    loop {
        let time = Instant::now();
        phy_wait(fd, None).unwrap();
        let (rx_token, tx_token) = device.receive(time).unwrap();
        let info = match rx_token.consume(|buffer| {
            let dhcp = rs_pxe::ether_to_dhcp(buffer)?;
            let info = rs_pxe::parse::pxe_discover(dhcp)?;

            if info.msg_type != DhcpMessageType::Discover {
                return Err(Error::Ignore("Not a dhcp discover packet".to_string()));
            }
            Ok(info)
        }) {
            Ok(info) => info,
            Err(Error::Ignore(e)) => {
                trace!("Ignoring packet. Reason: {}", e);
                continue;
            }
            Err(e) => panic!("Error: {}", e),
        };

        tx_token.consume(300, |buffer| {});

        //     tx_token
        //         .consume(Instant::now(), 300, |buffer| {
        //             const IP_NULL: Ipv4Address = Ipv4Address([0, 0, 0, 0]);
        //             let dhcp_packet = DhcpRepr {
        //                 message_type: DhcpMessageType::Offer,
        //                 transaction_id: transaction_id.unwrap(),
        //                 client_hardware_address: client_mac_address,
        //                 secs: secs,
        //                 client_ip: IP_NULL,
        //                 your_ip: IP_NULL,
        //                 server_ip: IP_NULL,
        //                 broadcast: true,
        //                 sname: None,
        //                 boot_file: None,
        //                 relay_agent_ip: IP_NULL,

        //                 // unimportant
        //                 router: None,
        //                 subnet_mask: None,
        //                 requested_ip: None,
        //                 client_identifier: None,
        //                 server_identifier: None,
        //                 parameter_request_list: None,
        //                 dns_servers: None,
        //                 max_size: None,
        //                 lease_duration: None,
        //                 client_arch_list: None,
        //                 client_interface_id: None,
        //                 client_machine_id: None,
        //                 time_offset: None,
        //                 vendor_class_id: None,
        //             };

        //             let udp_packet = UdpRepr {
        //                 src_port: 67,
        //                 dst_port: 68,
        //             };

        //             let mut packet = EthernetFrame::new_unchecked(buffer);
        //             let eth_packet = EthernetRepr {
        //                 dst_addr: EthernetAddress::BROADCAST,
        //                 src_addr: server_mac_address,
        //                 ethertype: EthernetProtocol::Ipv4,
        //             };
        //             eth_packet.emit(&mut packet);

        //             let mut packet = Ipv4Packet::new_unchecked(packet.payload_mut());
        //             let ip_packet = Ipv4Repr {
        //                 src_addr: server_ip,
        //                 dst_addr: Ipv4Address::BROADCAST,
        //                 protocol: IpProtocol::Udp,
        //                 hop_limit: 128,
        //                 payload_len: dhcp_packet.buffer_len() + udp_packet.header_len(),
        //             };
        //             ip_packet.emit(&mut packet, &checksum);

        //             let mut packet = UdpPacket::new_unchecked(packet.payload_mut());
        //             udp_packet.emit(
        //                 &mut packet,
        //                 &server_ip.into(),
        //                 &Ipv4Address::BROADCAST.into(),
        //                 dhcp_packet.buffer_len(),
        //                 |buf| {
        //                     let mut packet = DhcpPacket::new_unchecked(buf);
        //                     dhcp_packet.emit(&mut packet).unwrap();
        //                 },
        //                 &checksum,
        //             );

        //             info!("Sending DHCP offer...");
        //             Ok(())
        //         })
        //         .unwrap();
    }
}

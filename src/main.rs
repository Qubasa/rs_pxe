#![allow(clippy::option_map_unit_fn)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(dead_code)]
mod cli_opts;

mod utils;

use log::*;
use rs_pxe::tftp_state::Handle;
use rs_pxe::tftp_state::TestTftp;
use rs_pxe::tftp_state::TftpConnection;
use rs_pxe::tftp_state::Transfer;
use smolapps::wire::tftp::TftpOption;
use smolapps::wire::tftp::TftpOptsReader;
use smoltcp::iface::Config;
use smoltcp::iface::Routes;
use smoltcp::iface::SocketSet;
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::Checksum;
use smoltcp::phy::Device;
use smoltcp::phy::Medium;
use smoltcp::phy::RawSocket;
use smoltcp::phy::RxToken;
use smoltcp::phy::TxToken;
use smoltcp::socket::dhcpv4;
use smoltcp::time::Duration;
use smoltcp::time::Instant;
use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::HardwareAddress;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::IpListenEndpoint;

use core::panic;
use rand::prelude::*;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Cidr;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;
use smoltcp::{iface::Interface, phy::ChecksumCapabilities};
use std::borrow::BorrowMut;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use uuid::Uuid;

use smolapps::wire::tftp;

use crate::dhcp_options::*;
use prelude::*;
use rs_pxe::*;

//RFC: https://datatracker.ietf.org/doc/html/rfc2132
fn main() {
    let (mut opts, mut _free) = cli_opts::create_options();

    let mut matches = cli_opts::parse_options(&opts, _free);

    let v = match matches.opt_str("level") {
        Some(v) => v,
        None => "INFO".to_owned(),
    };

    let pxe_image = match matches.opt_str("ipxe") {
        Some(image) => std::path::PathBuf::from_str(&image).expect("Invalid path to ipxe image"),
        None => {
            let path = std::env::var("IPXE_IMAGE")
                .expect("IPXE_IMAGE env var not set. Or use --ipxe flag.");

            std::path::PathBuf::from_str(&path).expect("Invalid path to ipxe image")
        }
    };

    let level_filter = LevelFilter::from_str(&v).unwrap();
    cli_opts::setup_logging(level_filter);
    info!("Starting pxe....");

    let interface = matches
        .opt_str("interface")
        .expect("Interface not specified");
    let mac = mac_address::mac_address_by_name(&interface)
        .unwrap()
        .unwrap();
    let hardware_addr: &EthernetAddress = &EthernetAddress::from_bytes(&mac.bytes());

    if matches.opt_present("raw") {
        let mut device = match RawSocket::new(&interface, Medium::Ethernet) {
            Ok(device) => device,
            Err(e) => {
                panic!("Failed to create raw socket: {}", e);
            }
        };

        // Create interface
        let mut config = match device.capabilities().medium {
            Medium::Ethernet => Config::new(Into::into(*hardware_addr)),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device);

        utils::get_ip(&mut device, &mut iface);

        // Get interface mac and ip
        let server_mac = match iface.hardware_addr() {
            HardwareAddress::Ethernet(addr) => addr,
            _ => panic!("Currently we only support ethernet"),
        };
        let server_ip: Ipv4Address = iface.ipv4_addr().unwrap();

        let mut pxe_socket = PxeSocket::new(server_ip, server_mac, &pxe_image);

        loop {
            let fd: i32 = device.as_raw_fd();
            phy_wait(fd, None).unwrap();
            let (rx, tx) = device.receive(Instant::now()).unwrap();

            let packet = rx.consume(|buffer| pxe_socket.process(buffer));

            match packet {
                Ok(packet) => {
                    tx.consume(packet.len(), |buffer| {
                        buffer.copy_from_slice(&packet);
                        Ok::<(), Error>(())
                    })
                    .unwrap();
                }
                Err(Error::Ignore(e)) => {
                    debug!("Ignore: {:?}", e);
                }
                Err(Error::IgnoreNoLog(e)) => {
                    trace!("IgnoreNoLog: {:?}", e);
                }
                Err(e) => {
                    panic!("{:?}", e);
                }
            }
        }
    } else if matches.opt_present("tap") {
        // let mut device = smoltcp::phy::TunTapInterface::new(&interface, Medium::Ethernet).unwrap();

        // // Create interface
        // let mut config = match device.capabilities().medium {
        //     Medium::Ethernet => Config::new(Into::into(*hardware_addr)),
        //     Medium::Ip => panic!("Tap interface does not support IP"),
        //     Medium::Ieee802154 => todo!(),
        // };
        // config.random_seed = rand::random();
        // let mut iface = Interface::new(config, &mut device);

        // utils::get_ip(&mut device, &mut iface);

        // let mut socket = MyRawSocket::new(device, iface);
        // let mut pxe_socket = PxeSocket::new(&socket);
        // pxe_socket.process(&mut socket);
        todo!("Tap not supported yet");
    } else if matches.opt_present("tun") {
        // let mut device = smoltcp::phy::TunTapInterface::new(&interface, Medium::Ip).unwrap();

        // // Create interface
        // let mut config = match device.capabilities().medium {
        //     Medium::Ethernet => panic!("Tun interface does not support Ethernet"),
        //     Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
        //     Medium::Ieee802154 => todo!(),
        // };
        // config.random_seed = rand::random();
        // let mut iface = Interface::new(config, &mut device);

        // utils::get_ip(&mut device, &mut iface);

        // let mut socket = MyRawSocket::new(device, iface);
        // let mut pxe_socket = PxeSocket::new(&socket);
        // pxe_socket.process(&mut socket);
        todo!("Tun not supported yet");
    } else {
        let brief = "Either --raw or --tun or --tap must be specified";
        panic!("{}", brief);
    };
}

#[cfg(test)]
mod test {
    use smoltcp::phy::Loopback;

    use super::*;

    fn create_ethernet() -> (Interface, Loopback) {
        // Create a basic device
        let mut device = Loopback::new(Medium::Ethernet);

        let config = Config::new(HardwareAddress::Ethernet(EthernetAddress::default()));
        let mut iface = Interface::new(config, &mut device);
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64))
                .unwrap();
        });

        (iface, device)
    }

    #[test]
    pub fn test_pxe() {
        // let (mut iface, mut device) = create_ethernet();
        // let mut testsocket = TestSocket::new(device, iface);

        //server(&mut testsocket);
    }
}

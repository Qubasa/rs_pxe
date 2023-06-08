#![allow(clippy::option_map_unit_fn)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(dead_code)]
mod cli_opts;

mod utils;

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
use smoltcp::wire::IpListenEndpoint;

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

enum States {
    Discover,
    Request(u32),
    TFTP,
    Done,
}

pub fn server<DeviceT: AsRawFd>(device: &mut DeviceT, iface: &mut Interface)
where
    DeviceT: for<'d> Device,
{
    log::info!("Starting server");
    let fd = device.as_raw_fd();

    // Get interface mac and ip
    let server_mac = match iface.hardware_addr() {
        HardwareAddress::Ethernet(addr) => addr,
        _ => panic!("Currently we only support ethernet"),
    };
    let server_ip = iface.ipv4_addr().unwrap();

    // Find free tftp port in userspace range
    let tftp_endpoint = {
        let free_port = crate::udp_port_check::free_local_port_in_range(32768, 60999)
            .expect("No free UDP port found");

        IpListenEndpoint {
            addr: Some(server_ip.into_address()),
            port: free_port,
        }
    };

    // State machine
    let mut state = States::Discover;

    loop {
        let time = Instant::now();
        phy_wait(fd, None).unwrap();
        let (rx_token, tx_token) = device.receive(time).unwrap();

        match state {
            States::Discover => {
                /* ================== Parse PXE Discover ================== */
                /*
                Step 1. The client broadcasts a DHCPDISCOVER message to the standard DHCP port (67).
                An option field in this packet contains the following:
                   - A tag for client identifier (UUID).
                   - A tag for the client UNDI version.
                   - A tag for the client system architecture.
                   - A DHCP option 60, Class ID, set to “PXEClient:Arch:xxxxx:UNDI:yyyzzz”.
                */
                let info = match rx_token.consume(|buffer| {
                    let dhcp = crate::utils::broadcast_ether_to_dhcp(buffer)?;
                    let info = rs_pxe::parse::pxe_discover(dhcp)?;

                    if info.msg_type != DhcpMessageType::Discover {
                        return Err(Error::Ignore("Not a dhcp discover packet".to_string()));
                    }
                    Ok(info)
                }) {
                    Ok(info) => info,
                    Err(Error::IgnoreNoLog(e)) => {
                        trace!("Ignoring packet. Reason: {}", e);
                        continue;
                    }
                    Err(Error::Ignore(e)) => {
                        debug!("Ignoring packet. Reason: {}", e);
                        continue;
                    }
                    Err(e) => panic!("Error: {}", e),
                };

                log::info!("Parsed PXE Discover");
                log::info!("Sending PXE Offer");

                /*  ================== Send PXE Offer ================== */
                /*
                Step 2. The DHCP or Proxy DHCP Service responds by sending a DHCPOFFER message to the
                client on the standard DHCP reply port (68). If this is a Proxy DHCP Service, then the client IP
                address field is null (0.0.0.0). If this is a DHCP Service, then the returned client IP address
                field is valid.
                */
                tx_token.consume(500, |buffer| {
                    let dhcp_repr = construct::pxe_offer(&info, &server_ip);
                    utils::dhcp_to_ether_brdcast(
                        buffer,
                        dhcp_repr.borrow_repr(),
                        &server_ip,
                        &server_mac,
                    );
                });

                log::info!("Sent PXE Offer");
                log::info!("Waiting for PXE Request");

                /*
                Step 3. From the DHCPOFFER(s) that it receives, the client records the following:
                - The Client IP address (and other parameters) offered by a standard DHCP or BOOTP Service.
                - The Boot Server list from the Boot Server field in the PXE tags from the DHCPOFFER.
                - The Discovery Control Options (if provided).
                - The Multicast Discovery IP address (if provided).

                Step 4. If the client selects an IP address offered by a DHCP Service, then it must complete the
                standard DHCP protocol by sending a request for the address back to the Service and then waiting for
                an acknowledgment from the Service. If the client selects an IP address from a BOOTP reply, it can
                simply use the address.
                */
                state = States::Request(info.transaction_id);
            }
            States::Request(transaction_id) => {
                /*  ================== Parse PXE Request ================== */
                /*
                Step 5. The client selects and discovers a Boot Server. This packet may be sent broadcast (port 67),
                multicast (port 4011), or unicast (port 4011) depending on discovery control options included in the
                previous DHCPOFFER containing the PXE service extension tags. This packet is the same as the
                initial DHCPDISCOVER in Step 1, except that it is coded as a DHCPREQUEST and now contains
                the following:
                  - The IP address assigned to the client from a DHCP Service.
                  - A tag for client identifier (UUID)
                  - A tag for the client UNDI version.
                  - A tag for the client system architecture.
                  - A DHCP option 60, Class ID, set to “PXEClient:Arch:xxxxx:UNDI:yyyzzz”.
                  - The Boot Server type in a PXE option field
                */
                let (info, ip, mac) = match rx_token.consume(|buffer| {
                    let dhcp =
                        crate::utils::unicast_ether_to_dhcp(buffer, &server_mac, &server_ip)?;

                    let info = rs_pxe::parse::pxe_discover(dhcp)?;

                    if info.msg_type != DhcpMessageType::Request {
                        return Err(Error::Ignore("Not a dhcp request packet".to_string()));
                    }

                    if info.transaction_id != transaction_id {
                        return Err(Error::Ignore("Not the same transaction id".to_string()));
                    }

                    Ok((info, dhcp.client_ip(), dhcp.client_hardware_address()))
                }) {
                    Ok(info) => info,
                    Err(Error::IgnoreNoLog(e)) => {
                        trace!("Ignoring packet. Reason: {}", e);
                        continue;
                    }
                    Err(Error::Ignore(e)) => {
                        debug!("Ignoring packet. Reason: {}", e);
                        continue;
                    }
                    Err(e) => panic!("Error: {}", e),
                };

                log::info!("Parsed PXE Request");
                log::info!("Sending PXE ACK to {} with ip {}", mac, ip);

                /* ================== Send PXE ACK ================== */
                /*
                Step 6. The Boot Server unicasts a DHCPACK packet back to the client on the client source port.
                This reply packet contains:
                    - Boot file name.
                    - MTFTP configuration parameters.
                    - Any other options the NBP requires before it can be successfully executed.
                */
                tx_token.consume(500, |buffer| {
                    let dhcp_repr = construct::pxe_ack(&info, &tftp_endpoint);
                    utils::dhcp_to_ether_unicast(
                        buffer,
                        dhcp_repr.borrow_repr(),
                        &ip,
                        &mac,
                        &server_ip,
                        &server_mac,
                    );
                });

                log::info!("Sent PXE ACK");

                /*
                Step 7. The client downloads the executable file using either standard TFTP (port69) or MTFTP
                (port assigned in Boot Server Ack packet). The file downloaded and the placement of the
                downloaded code in memory is dependent on the client’s CPU architecture.
                */
                state = States::TFTP;
            }
            States::TFTP => {
                state = States::Discover;
            }
            States::Done => todo!(),
        }
    }
}

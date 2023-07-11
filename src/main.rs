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

    let level_filter = LevelFilter::from_str(&v).unwrap();
    cli_opts::setup_logging(level_filter);
    info!("Starting pxe....");

    let interface = matches.opt_str("interface").unwrap();
    let mac = mac_address::mac_address_by_name(&interface)
        .unwrap()
        .unwrap();
    let hardware_addr: &EthernetAddress = &EthernetAddress::from_bytes(&mac.bytes());

    if matches.opt_present("raw") {
        let mut device = RawSocket::new(&interface, Medium::Ethernet).unwrap();

        // Create interface
        let mut config = match device.capabilities().medium {
            Medium::Ethernet => Config::new(Into::into(*hardware_addr)),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        config.random_seed = rand::random();

        let mut iface = Interface::new(config, &mut device);

        utils::get_ip(&mut device, &mut iface);
        let mut socket = MyRawSocket::new(device, iface);

        server(&mut socket);
    } else if matches.opt_present("tap") {
        let mut device = smoltcp::phy::TunTapInterface::new(&interface, Medium::Ethernet).unwrap();

        // Create interface
        let mut config = match device.capabilities().medium {
            Medium::Ethernet => Config::new(Into::into(*hardware_addr)),
            Medium::Ip => panic!("Tap interface does not support IP"),
            Medium::Ieee802154 => todo!(),
        };
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device);

        utils::get_ip(&mut device, &mut iface);

        let mut socket = MyRawSocket::new(device, iface);
        server(&mut socket);
    } else if matches.opt_present("tun") {
        let mut device = smoltcp::phy::TunTapInterface::new(&interface, Medium::Ip).unwrap();

        // Create interface
        let mut config = match device.capabilities().medium {
            Medium::Ethernet => panic!("Tun interface does not support Ethernet"),
            Medium::Ip => Config::new(smoltcp::wire::HardwareAddress::Ip),
            Medium::Ieee802154 => todo!(),
        };
        config.random_seed = rand::random();
        let mut iface = Interface::new(config, &mut device);

        utils::get_ip(&mut device, &mut iface);

        let mut socket = MyRawSocket::new(device, iface);
        server(&mut socket);
    } else {
        let brief = "Either --raw or --tun or --tap must be specified";
        panic!("{}", opts.usage(brief));
    };
}

#[derive(Debug)]
enum PxeStates {
    Discover,
    Request(u32),
    ArpRequest,
    Tftp(TftpStates),
    Done,
}

#[derive(Debug)]
pub enum TftpStates {
    Tsize,
    BlkSize,
    Data { blksize: usize },
    Error,
    Done,
}

pub trait GenericSocket<D>
where
    D: Device,
{
    type R<'a>: RxToken
    where
        Self: 'a;
    type T<'a>: TxToken
    where
        Self: 'a;

    fn send(&mut self, data: &[u8]) -> Result<usize>;
    fn wait(&mut self) -> Result<(Self::R<'_>, Self::T<'_>)>;
    fn hardware_addr(&self) -> HardwareAddress;
    fn ip_addr(&self) -> IpAddress;
}

pub struct MyRawSocket<DeviceT: AsRawFd + Device> {
    device: DeviceT,
    iface: Interface,
    time: Instant,
}

impl<DeviceT: AsRawFd + Device> MyRawSocket<DeviceT> {
    pub fn new(device: DeviceT, iface: Interface) -> Self {
        Self {
            device,
            iface,
            time: Instant::now(),
        }
    }
}

impl<DeviceT: AsRawFd + Device> GenericSocket<DeviceT> for MyRawSocket<DeviceT> {
    type R<'a> = DeviceT::RxToken<'a>
    where
        Self: 'a;
    type T<'a> = DeviceT::TxToken<'a>
    where
        Self: 'a;
    fn send(&mut self, data: &[u8]) -> Result<usize> {
        todo!()
    }

    fn wait(&mut self) -> Result<(Self::R<'_>, Self::T<'_>)> {
        let fd: i32 = self.device.as_raw_fd();
        phy_wait(fd, None).unwrap();
        let (rx_token, tx_token) = self.device.receive(self.time).unwrap();

        Ok((rx_token, tx_token))
    }

    fn hardware_addr(&self) -> HardwareAddress {
        self.iface.hardware_addr()
    }

    fn ip_addr(&self) -> IpAddress {
        self.iface.ipv4_addr().unwrap().into()
    }
}

pub fn server<DeviceT: Device, G>(socket: &mut G) -> !
where
    G: GenericSocket<DeviceT>,
{
    // Get interface mac and ip
    let server_mac = match socket.hardware_addr() {
        HardwareAddress::Ethernet(addr) => addr,
        _ => panic!("Currently we only support ethernet"),
    };
    let server_ip = socket.ip_addr();

    log::info!("Starting server with ip: {}", server_ip);

    // Find free tftp port in userspace range
    let tftp_endpoint = {
        let free_port = crate::udp_port_check::free_local_port_in_range(32768, 60999)
            .expect("No free UDP port found");

        IpListenEndpoint {
            addr: Some(server_ip),
            port: free_port,
        }
    };

    let server_ip = Ipv4Address::from_bytes(server_ip.as_bytes());

    // State machine
    let mut state = PxeStates::Discover;

    let mut transfers: HashMap<TftpConnection, Transfer<TestTftp>> = HashMap::new();

    loop {
        let time = Instant::now();

        let (rx_token, tx_token) = socket.wait().unwrap();

        match state {
            PxeStates::Discover => {
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

                let dhcp_repr = construct::pxe_offer(&info, &server_ip);
                let packet =
                    utils::dhcp_to_ether_brdcast(dhcp_repr.borrow_repr(), &server_ip, &server_mac);
                tx_token.consume(packet.len(), |buffer| {
                    buffer.copy_from_slice(&packet);
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
                state = PxeStates::Request(info.transaction_id);
            }
            PxeStates::Request(transaction_id) => {
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
                        crate::utils::uni_broad_ether_to_dhcp(buffer, &server_mac, &server_ip)?;

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
                let dhcp_repr = construct::pxe_ack(&info, &tftp_endpoint);
                let packet = utils::dhcp_to_ether_unicast(
                    dhcp_repr.borrow_repr(),
                    &ip,
                    &mac,
                    &server_ip,
                    &server_mac,
                );
                tx_token.consume(packet.len(), |buffer| {
                    buffer.copy_from_slice(&packet);
                });

                log::info!("Sent PXE ACK");

                /*
                Step 7. The client downloads the executable file using either standard TFTP (port69) or MTFTP
                (port assigned in Boot Server Ack packet). The file downloaded and the placement of the
                downloaded code in memory is dependent on the client’s CPU architecture.
                */
                //state = PxeStates::ArpRequest;
                log::info!("Changing to tftp tsize state");
                state = PxeStates::Tftp(TftpStates::Tsize);
            }
            PxeStates::ArpRequest => {
                match tftp_state::arp_respond(rx_token, tx_token, &server_mac, &server_ip) {
                    Ok(info) => {
                        state = PxeStates::Tftp(TftpStates::Tsize);
                    }
                    Err(Error::IgnoreNoLog(e)) => {
                        trace!("Ignoring packet. Reason: {}", e);
                        continue;
                    }
                    Err(Error::Ignore(e)) => {
                        debug!("Ignoring packet. Reason: {}", e);
                        continue;
                    }
                    Err(e) => panic!("Error: {}", e),
                }
            }
            PxeStates::Tftp(ref tftp_state) => {
                let (tftp_con, wrapper) =
                    match tftp_state::recv_tftp(rx_token, &server_mac, &server_ip) {
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

                match tftp_state {
                    TftpStates::Tsize => {
                        tftp_state::reply_tsize(tx_token, &wrapper, tftp_con, &mut transfers)
                            .unwrap();

                        log::info!("Changing to blksize state");
                        state = PxeStates::Tftp(TftpStates::BlkSize);
                    }
                    TftpStates::BlkSize => {
                        let blksize = match tftp_state::reply_blksize(
                            tx_token,
                            &wrapper,
                            tftp_con,
                            &mut transfers,
                        ) {
                            Ok(blksize) => blksize,
                            Err(Error::Ignore(e)) => {
                                debug!("Ignoring packet. Reason: {}", e);
                                continue;
                            }
                            Err(e) => panic!("Error: {}", e),
                        };

                        log::info!("Changing to tftp data state");
                        state = PxeStates::Tftp(TftpStates::Data { blksize })
                    }
                    TftpStates::Data { blksize } => {
                        let done = tftp_state::reply_data(
                            tx_token,
                            &wrapper,
                            tftp_con,
                            &mut transfers,
                            *blksize,
                        )
                        .unwrap();

                        if done {
                            log::info!("Changing to tftp done state");
                            state = PxeStates::Tftp(TftpStates::Done);
                        }
                    }
                    TftpStates::Error => todo!(),
                    TftpStates::Done => log::info!("TFTP Done"),
                }

                //state = States::Discover;
            }

            PxeStates::Done => todo!(),
        }
    }
}

#[cfg(test)]
mod test {
    use smoltcp::phy::Loopback;

    use super::*;

    fn create_ethernet<'a>() -> (Interface, SocketSet<'a>, Loopback) {
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

        (iface, SocketSet::new(vec![]), device)
    }

    #[test]
    pub fn test_pxe() {
        // let (mut iface, mut sockets, mut device) = create_ethernet();

        // server(&mut device, &mut iface);
    }
}

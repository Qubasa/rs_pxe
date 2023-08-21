#![allow(unused_imports)]

pub mod dhcp;
pub mod error;
pub mod prelude;

pub mod tftp;
pub mod udp_port_check;
mod utils;

#[cfg(test)]
mod tests;

use prelude::*;
use smoltcp::wire::ArpRepr;
use tftp::construct::TftpError;
use tftp::construct::TftpOptionEnum;
use tftp::parse::Repr;
use tftp::socket::{TftpPacketWrapper, TftpPacketWrapperBuilder, TftpSocket};

use log::*;
use tftp::construct::Handle;
use tftp::construct::TestTftp;
use tftp::construct::TftpConnection;
use tftp::construct::Transfer;
use utils::build_arp_announce;

use core::panic;
use ouroboros::self_referencing;
use rand::prelude::*;
use tftp::parse::TftpOption;
use tftp::parse::TftpOptsReader;

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
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::IpEndpoint;
use smoltcp::wire::IpListenEndpoint;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Cidr;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;
use smoltcp::{iface::Interface, phy::ChecksumCapabilities};
use std::borrow::BorrowMut;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use uuid::Uuid;

use crate::tftp::socket::TftpStates;

static ARP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum PxeStates {
    Dhcp,
    Tftp,
}

impl Display for PxeStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PxeStates::Dhcp => write!(f, "Dhcp"),
            PxeStates::Tftp => write!(f, "Tftp"),
        }
    }
}

#[derive(Debug)]
pub struct PxeSocket {
    _state: PxeStates,
    stage_one: PathBuf,
    stage_two: PathBuf,
    server_mac: EthernetAddress,
    server_ip: Ipv4Address,
    dhcp_socket: dhcp::socket::DhcpSocket,
    tftp_socket: Option<TftpSocket>,
    timeout: Instant,
}

impl PxeSocket {
    pub fn get_server_ip(&self) -> Ipv4Address {
        self.server_ip
    }
    pub fn get_server_mac(&self) -> EthernetAddress {
        self.server_mac
    }
    pub fn get_state(&self) -> &PxeStates {
        &self._state
    }
    pub fn get_stage_two(&self) -> &PathBuf {
        &self.stage_two
    }
    pub fn get_stage_one(&self) -> &PathBuf {
        &self.stage_one
    }
    fn set_state(&mut self, state: PxeStates) {
        debug!("Changing state to {}", state);
        self._state = state;
    }
    fn reset_state(&mut self) {
        self.tftp_socket = None;
        self.dhcp_socket =
            dhcp::socket::DhcpSocket::new(self.server_ip, self.server_mac, self.get_stage_one());
        self.set_state(PxeStates::Dhcp);
    }

    pub fn process_timeout(&mut self) -> Result<Vec<u8>> {
        if self.timeout < Instant::now() {
            self.timeout = Instant::now() + ARP_TIMEOUT;
            return Ok(build_arp_announce(self.server_mac, self.server_ip));
        }

        if let Some(tftp_socket) = &mut self.tftp_socket {
            return match tftp_socket.process_timeout() {
                Ok(packet) => Ok(packet),
                Err(tftp::error::Error::StopTftpConnection(packet)) => {
                    self.reset_state();
                    Ok(packet)
                }
                Err(tftp::error::Error::Ignore(e)) => Err(Error::Ignore(e)),
                Err(tftp::error::Error::IgnoreNoLog(e)) => Err(Error::IgnoreNoLog(e)),
                Err(e) => panic!("{}", e),
            };
        }
        Err(Error::IgnoreNoLog("Nothing todo".to_string()))
    }

    pub fn new(
        server_ip: Ipv4Address,
        server_mac: EthernetAddress,
        stage_one: &Path,
        stage_two: &Path,
    ) -> Self {
        log::info!(
            "Creating PXE socket with ip: {} and mac {}",
            server_ip,
            server_mac
        );

        let server_ip = Ipv4Address::from_bytes(server_ip.as_bytes());

        // State machine
        let state = PxeStates::Dhcp;

        let dhcp_socket = dhcp::socket::DhcpSocket::new(server_ip, server_mac, stage_one);

        Self {
            _state: state,
            timeout: Instant::now(),
            tftp_socket: None,
            server_mac,
            server_ip,
            stage_two: stage_two.to_path_buf(),
            stage_one: stage_one.to_path_buf(),
            dhcp_socket,
        }
    }

    pub fn process(&mut self, rx_buffer: &[u8]) -> Result<Vec<u8>> {
        match self.get_state() {
            PxeStates::Dhcp => match self.dhcp_socket.process(rx_buffer) {
                Ok(packet) => Ok(packet),
                Err(dhcp::error::Error::DhcpProtocolFinished) => {
                    self.set_state(PxeStates::Tftp);
                    self.process(rx_buffer)
                }

                Err(dhcp::error::Error::IgnoreNoLog(e)) => Err(Error::IgnoreNoLog(e)),
                Err(dhcp::error::Error::Ignore(e)) => Err(Error::Ignore(e)),
                Err(dhcp::error::Error::MissingDhcpOption(opt)) => {
                    Err(Error::Ignore(f!("Missing DHCP option: {opt}")))
                }
                Err(dhcp::error::Error::WaitForDhcpAck) => Err(Error::Ignore(
                    "Waiting for DHCP Ack packet of router".to_string(),
                )),
                Err(e) => panic!("{}", e),
            },
            PxeStates::Tftp => {
                if self.tftp_socket.is_none() {
                    match self.dhcp_socket.get_firmware_type().unwrap() {
                        dhcp::parse::FirmwareType::Unknown => {
                            self.tftp_socket = Some(TftpSocket::new(
                                self.server_mac,
                                self.server_ip,
                                self.get_stage_one(),
                            ));
                        }
                        dhcp::parse::FirmwareType::IPxe => {
                            self.tftp_socket = Some(TftpSocket::new(
                                self.server_mac,
                                self.server_ip,
                                self.get_stage_two(),
                            ));
                        }
                    }
                }

                match self.tftp_socket.as_mut().unwrap().process(rx_buffer) {
                    Err(tftp::error::Error::TftpEndOfFile) => {
                        self.reset_state();
                        self.process(rx_buffer)
                    }
                    Err(tftp::error::Error::Ignore(e)) => Err(Error::Ignore(e)),
                    Err(tftp::error::Error::IgnoreNoLog(e)) => Err(Error::IgnoreNoLog(e)),
                    Ok(packet) => Ok(packet),
                    Err(e) => panic!("{}", e),
                }
            }
        }
    }
}

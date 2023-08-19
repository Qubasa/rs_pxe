use crate::{
    prelude::Error, tests::test_utils::cmp_impl_responses, utils, PxeSocket, PxeStates, TftpStates,
};
use env_logger::fmt::Color;
use log::*;
use pcap_file::pcapng::{
    blocks::{
        enhanced_packet::EnhancedPacketBlock, interface_description::InterfaceDescriptionBlock,
    },
    PcapNgBlock, PcapNgReader, PcapNgWriter,
};
use smoltcp::wire::{EthernetAddress, EthernetFrame, Ipv4Address};
use std::{borrow::Cow, fs::File, path::Path, str::FromStr, time::Duration, vec};
use std::{io::Write, sync::Once};

use super::test_utils::{setup, verify_responses};

#[test]
pub fn intel_pxe() {
    setup();

    let server_ip = Ipv4Address::new(192, 168, 178, 97);
    let server_mac = EthernetAddress::from_bytes(&[0x98, 0xfa, 0x9b, 0x4b, 0xb2, 0xc4]);
    let pxe_image = std::path::PathBuf::from_str("./assets/ipxe.pxe").unwrap();
    let kernel_image = std::path::PathBuf::from_str("./assets/kernel.elf").unwrap();
    let mut pxe_socket = PxeSocket::new(server_ip, server_mac, &pxe_image, &kernel_image);

    // Emulate the DHCP Discover phase
    let res = cmp_impl_responses(
        &mut pxe_socket,
        Path::new("./assets/intel_dhcp.pcapng"),
        |e| panic!("{}", e),
    );
    verify_responses(&res);

    // Emulate the TFTP phase
    let res = cmp_impl_responses(
        &mut pxe_socket,
        Path::new("./assets/intel_tftp.pcapng"),
        |e| panic!("{}", e),
    );
    verify_responses(&res);
}

#[test]
pub fn ipxe() {
    setup();

    let server_ip = Ipv4Address::new(192, 168, 178, 97);
    let server_mac = EthernetAddress::from_bytes(&[0x98, 0xfa, 0x9b, 0x4b, 0xb2, 0xc4]);
    let pxe_image = std::path::PathBuf::from_str("./assets/ipxe.pxe").unwrap();
    let kernel_image = std::path::PathBuf::from_str("./assets/kernel.elf").unwrap();
    let mut pxe_socket = PxeSocket::new(server_ip, server_mac, &pxe_image, &kernel_image);

    // Emulate the DHCP Discover phase
    let res = cmp_impl_responses(
        &mut pxe_socket,
        Path::new("./assets/ipxe_dhcp.pcapng"),
        |e| panic!("{}", e),
    );
    verify_responses(&res);

    assert_eq!(pxe_socket.get_state(), &PxeStates::Tftp);

    let res = cmp_impl_responses(
        &mut pxe_socket,
        Path::new("./assets/ipxe_tftp.pcapng"),
        |e| panic!("{}", e),
    );
    verify_responses(&res);
}

#[test]
pub fn amd_efi() {
    setup();

    let server_ip = Ipv4Address::new(151, 216, 192, 203);
    let server_mac = EthernetAddress::from_bytes(&[0x98, 0xfa, 0x9b, 0x4b, 0xb2, 0xc4]);
    let pxe_image = std::path::PathBuf::from_str("./assets/ipxe.pxe").unwrap();
    let kernel_image = std::path::PathBuf::from_str("./assets/kernel.elf").unwrap();
    let mut pxe_socket = PxeSocket::new(server_ip, server_mac, &pxe_image, &kernel_image);

    // Emulate the DHCP Discover phase
    let _res = cmp_impl_responses(
        &mut pxe_socket,
        Path::new("./assets/amd_efi_dhcp.pcapng"),
        |e| panic!("{}", e),
    );
    //verify_responses(&res);

    // assert_eq!(pxe_socket.get_state(), &PxeStates::Tftp);
}

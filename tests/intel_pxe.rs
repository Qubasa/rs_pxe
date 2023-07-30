use log::*;
use rs_pxe::{prelude::Error, *};
use smoltcp::wire::{EthernetAddress, EthernetFrame, Ipv4Address};
use std::{fs::File, vec};

use pcap_file::pcapng::PcapNgReader;

pub fn setup() {
    println!("Running setup...");

    // setup code specific to your library's tests would go here
}

#[test]
pub fn test_pxe() {
    let file_in = File::open("./assets/intel_dhcp.pcapng").expect("Error opening file");
    let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();

    let server_ip = Ipv4Address::new(192, 168, 178, 97);
    let server_mac = EthernetAddress::from_bytes(&[0x98, 0xfa, 0x9b, 0x4b, 0xb2, 0xc4]);
    let pxe_image = std::path::PathBuf::new();
    let mut pxe_socket = PxeSocket::new(server_ip, server_mac, &pxe_image);

    let mut orig_send: Vec<Vec<u8>> = vec![];
    let mut impl_send: Vec<Vec<u8>> = vec![];

    // Read test.pcapng
    while let Some(block) = pcapng_reader.next_block() {
        //Check if there is no error
        let block = block.unwrap();

        // Get the data from the block
        let block = match block.clone().into_enhanced_packet() {
            Some(block) => block,
            None => {
                println!("Not an enhanced packet block: {:?}", block);
                continue;
            }
        };

        // Check if the packet is from the server and ignore it
        let ether = EthernetFrame::new_checked(&block.data).unwrap();
        if ether.src_addr() == server_mac {
            orig_send.push(block.data.to_vec());
            continue;
        }

        // Process the packet
        let response = pxe_socket.process(&block.data);
        match response {
            Ok(resp) => impl_send.push(resp.to_vec()),
            Err(Error::IgnoreNoLog(e)) => println!("IgnoreNoLog: {}", e),
            Err(Error::Ignore(e)) => println!("Ignore: {}", e),
            Err(e) => panic!("Error: {:?}", e),
        }
    }

    assert_eq!(orig_send, impl_send);
}

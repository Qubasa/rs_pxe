use pcap_file::pcapng::PcapNgReader;
use rs_pxe::{prelude::Error, *};
use smoltcp::wire::{EthernetAddress, EthernetFrame, Ipv4Address};
use std::{fs::File, path::Path, vec};

struct Responses {
    pub orig_send: Vec<Vec<u8>>,
    pub impl_send: Vec<Vec<u8>>,
}
fn cmp_impl_responses(pxe_socket: &mut PxeSocket, pcap_path: &Path) -> Responses {
    let file_in = File::open(pcap_path).expect("Error opening file");
    let mut pcapng_reader = PcapNgReader::new(file_in).unwrap();

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
        if ether.src_addr() == pxe_socket.get_server_mac() {
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

    Responses {
        orig_send,
        impl_send,
    }
}

#[test]
pub fn intel_pxe() {
    let server_ip = Ipv4Address::new(192, 168, 178, 97);
    let server_mac = EthernetAddress::from_bytes(&[0x98, 0xfa, 0x9b, 0x4b, 0xb2, 0xc4]);
    let pxe_image = std::path::PathBuf::new();
    let mut pxe_socket = PxeSocket::new(server_ip, server_mac, &pxe_image);

    // Emulate the DHCP Discover phase
    let res = cmp_impl_responses(&mut pxe_socket, Path::new("./assets/intel_dhcp.pcapng"));
    assert_eq!(res.orig_send, res.impl_send);

    // Emulate the TFTP phase
    let res = cmp_impl_responses(&mut pxe_socket, Path::new("./assets/intel_tftp.pcapng"));
    assert_eq!(res.orig_send, res.impl_send);
}

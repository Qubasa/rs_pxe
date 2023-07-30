use env_logger::fmt::Color;
use log::*;
use pcap_file::pcapng::{
    blocks::{
        enhanced_packet::EnhancedPacketBlock, interface_description::InterfaceDescriptionBlock,
    },
    PcapNgBlock, PcapNgReader, PcapNgWriter,
};
use rs_pxe::{prelude::Error, *};
use smoltcp::wire::{EthernetAddress, EthernetFrame, Ipv4Address};
use std::io::Write;
use std::{
    borrow::Cow,
    fs::File,
    path::{Iter, Path},
    str::FromStr,
    time::Duration,
    vec,
};

pub fn setup_logging(level: LevelFilter) {
    env_logger::Builder::new()
        .format(|buf, record| {
            // Get the file name and line number from the record
            let file = record.file().unwrap_or("unknown");
            let line = record.line().unwrap_or(0);

            // Get the color for the log level
            let color = match record.level() {
                Level::Error => Color::Red,
                Level::Warn => Color::Yellow,
                Level::Info => Color::Green,
                Level::Debug => Color::Cyan,
                Level::Trace => Color::Black,
            };

            // Write the formatted output to the buffer
            writeln!(
                buf,
                "{}:{} [{}] {}",
                file,
                line,
                buf.style().set_color(color).value(record.level()),
                record.args()
            )
        })
        .filter(None, level)
        .is_test(true)
        .parse_env(&std::env::var("RUST_LOG").unwrap_or_else(|_| "".to_owned()))
        .init();
}

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
            Err(Error::IgnoreNoLog(e)) => trace!("IgnoreNoLog: {}", e),
            Err(Error::Ignore(e)) => debug!("Ignore: {}", e),
            Err(e) => panic!("Error: {:?}", e),
        }
    }

    assert_eq!(orig_send.len(), impl_send.len());
    Responses {
        orig_send,
        impl_send,
    }
}

fn vec_to_pcap(data: &[Vec<u8>], file_path: &Path) {
    let interface = InterfaceDescriptionBlock {
        linktype: pcap_file::DataLink::ETHERNET,
        snaplen: 0xFFFF,
        options: vec![],
    };

    let file = File::create(file_path).expect("Error creating file");
    let mut pcap_ng_writer = PcapNgWriter::new(file).unwrap();
    pcap_ng_writer.write_block(&interface.into_block()).unwrap();
    for data in data {
        let packet = EnhancedPacketBlock {
            interface_id: 0,
            timestamp: Duration::from_secs(0),
            original_len: data.len() as u32,
            data: Cow::Borrowed(data),
            options: vec![],
        };
        pcap_ng_writer.write_block(&packet.into_block()).unwrap();
    }
}

#[test]
pub fn intel_pxe() {
    setup_logging(LevelFilter::Debug);
    info!("Starting test");
    let server_ip = Ipv4Address::new(192, 168, 178, 97);
    let server_mac = EthernetAddress::from_bytes(&[0x98, 0xfa, 0x9b, 0x4b, 0xb2, 0xc4]);
    let pxe_image = std::path::PathBuf::from_str("./assets/ipxe.pxe").unwrap();
    let mut pxe_socket = PxeSocket::new(server_ip, server_mac, &pxe_image);

    // Emulate the DHCP Discover phase
    let res = cmp_impl_responses(&mut pxe_socket, Path::new("./assets/intel_dhcp.pcapng"));
    assert_eq!(res.orig_send, res.impl_send);

    // Emulate the TFTP phase
    let res = cmp_impl_responses(&mut pxe_socket, Path::new("./assets/intel_tftp.pcapng"));

    if res.orig_send != res.impl_send {
        vec_to_pcap(
            res.impl_send.as_slice(),
            Path::new("./target/tftp_failed.pcapng"),
        );
        vec_to_pcap(
            res.orig_send.as_slice(),
            Path::new("./target/tftp_orig.pcapng"),
        );
        panic!("TFTP failed");
    }
}

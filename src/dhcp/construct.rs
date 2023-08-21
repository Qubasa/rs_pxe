#![allow(unused_imports)]

use crate::dhcp::options::*;
use crate::dhcp::parse::PxeClientInfo;
use crate::prelude::*;

use crate::tftp::construct;
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
use smoltcp::wire::ArpRepr;
use smoltcp::wire::DhcpMessageType;
use smoltcp::wire::DhcpOption;
use smoltcp::wire::DhcpOptionWriter;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::HardwareAddress;

use crate::dhcp::options::DhcpOptionWrapper;
use ouroboros::self_referencing;
use rand::prelude::*;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;
use smoltcp::wire::UdpRepr;

use std::cell::RefCell;
use std::net::Ipv6Addr;
use std::rc::Rc;

#[self_referencing]
#[derive(Debug)]
pub struct DhcpReprWrapper {
    mdata: Vec<DhcpOptionWrapper>,
    boot_file: String,

    #[borrows(mdata)]
    #[covariant]
    options: Vec<DhcpOption<'this>>,

    #[borrows(options, boot_file)]
    #[covariant]
    pub repr: DhcpRepr<'this>,
}

pub fn pxe_ack(info: &PxeClientInfo, server_ip: Ipv4Address, boot_file: &str) -> DhcpReprWrapper {
    const IP_NULL: Ipv4Address = Ipv4Address([0, 0, 0, 0]);

    let client_addr = match info.client_identifier.hardware_type {
        HardwareType::Ethernet => {
            let mac = &info.client_identifier.hardware_address;
            EthernetAddress::from_bytes(mac)
        }
        t => panic!("Unsupported hardware type: {:#?}", t),
    };

    let options = vec![];

    DhcpReprWrapperBuilder {
        mdata: options,
        boot_file: boot_file.to_owned(),
        options_builder: |mdata: &Vec<DhcpOptionWrapper>| {
            let options: Vec<DhcpOption> = mdata.iter().map(|x| x.into()).collect();
            options
        },
        repr_builder: |options: &Vec<DhcpOption>, boot_file: &String| {
            DhcpRepr {
                sname: None,
                boot_file: Some(boot_file),
                message_type: DhcpMessageType::Ack,
                transaction_id: info.transaction_id,
                client_hardware_address: client_addr,
                secs: info.secs,
                client_ip: IP_NULL,
                your_ip: IP_NULL,
                server_ip,
                broadcast: false,
                relay_agent_ip: IP_NULL,

                // unimportant
                router: None,
                subnet_mask: None,
                requested_ip: None,
                client_identifier: None,
                server_identifier: None,
                parameter_request_list: None,
                dns_servers: None,
                max_size: None,
                lease_duration: None,
                renew_duration: None,
                rebind_duration: None,
                additional_options: options,
            }
        },
    }
    .build()
}

pub fn pxe_offer(
    info: &PxeClientInfo,
    server_ip: &Ipv4Address,
    boot_file: &str,
) -> DhcpReprWrapper {
    const IP_NULL: Ipv4Address = Ipv4Address([0, 0, 0, 0]);

    let client_addr = match info.client_identifier.hardware_type {
        HardwareType::Ethernet => {
            let mac = &info.client_identifier.hardware_address;
            EthernetAddress::from_bytes(mac)
        }
        t => panic!("Unsupported hardware type: {:#?}", t),
    };

    let vendor_id = VendorClassIdentifier::try_from("PXEClient".as_bytes()).unwrap();
    let server_id = PxeServerIdentifier::try_from(server_ip.clone().as_bytes()).unwrap();

    //TODO: If the ip is incorrect we get a difficult to debug error ARP timeout on the client
    // Maybe use vendor option to specify the correct IP?
    // let vendor_options: Vec<VendorOption> = {
    //     let pxe_discover_control = PxeDiscoverControl::new()
    //         .with_disable_broadcast(false)
    //         .with_disable_multicast(false)
    //         .with_direct_boot_file_download(true)
    //         .with_only_pxe_boot_servers(false);

    //     vec![pxe_discover_control.into()]
    // };

    let options: Vec<DhcpOptionWrapper> = vec![
        info.client_identifier.clone().into(),
        info.client_uuid.clone().into(),
        server_id.into(),
        vendor_id.into(),
        //     vendor_options.as_slice().into(),
    ];

    DhcpReprWrapperBuilder {
        mdata: options,
        boot_file: boot_file.to_owned(),
        options_builder: |mdata: &Vec<DhcpOptionWrapper>| {
            let options: Vec<DhcpOption> = mdata.iter().map(|x| x.into()).collect();
            options
        },
        repr_builder: |options: &Vec<DhcpOption>, boot_file: &String| {
            DhcpRepr {
                sname: None,
                boot_file: Some(boot_file),
                message_type: DhcpMessageType::Offer,
                transaction_id: info.transaction_id,
                client_hardware_address: client_addr,
                secs: info.secs,
                client_ip: IP_NULL,
                your_ip: IP_NULL,
                server_ip: server_ip.to_owned(),
                broadcast: true,
                relay_agent_ip: IP_NULL,

                // unimportant
                router: None,
                subnet_mask: None,
                requested_ip: None,
                client_identifier: None,
                server_identifier: None,
                parameter_request_list: None,
                dns_servers: None,
                max_size: None,
                lease_duration: None,
                renew_duration: None,
                rebind_duration: None,
                additional_options: options,
            }
        },
    }
    .build()
}

#[cfg(test)]
mod test {
    use super::*;
}

#![allow(unused_imports)]

use crate::dhcp_options::*;
use crate::parse::PxeClientInfo;
use crate::prelude::*;

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
use smoltcp::wire::DhcpOption;
use smoltcp::wire::DhcpOptionWriter;
use smoltcp::wire::DhcpPacket;
use smoltcp::wire::DhcpRepr;
use smoltcp::wire::EthernetAddress;
use smoltcp::wire::EthernetFrame;
use smoltcp::wire::HardwareAddress;

use crate::dhcp_options::DhcpOptionWrapper;
use ouroboros::self_referencing;
use rand::prelude::*;
use smoltcp::wire::IpAddress;
use smoltcp::wire::IpCidr;
use smoltcp::wire::Ipv4Address;
use smoltcp::wire::Ipv4Packet;
use smoltcp::wire::UdpPacket;
use smoltcp::wire::UdpRepr;

use std::cell::RefCell;
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

pub fn pxe_offer(info: &PxeClientInfo, server_ip: &Ipv4Address) -> DhcpReprWrapper {
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
    let mut options: Vec<DhcpOptionWrapper> = vec![
        info.client_identifier.clone().into(),
        info.client_uuid.clone().into(),
        server_id.into(),
        vendor_id.into(),
    ];

    if let Some(id) = info.vendor_id.clone() {
        options.push(id.into());
    }
    let boot_file: String = f!(
        "http://{}:7777/ipxe?client_id={}",
        server_ip,
        info.client_identifier
    );

    DhcpReprWrapperBuilder {
        mdata: options,
        boot_file,
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

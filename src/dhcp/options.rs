use std::fmt::{self, Display, Formatter};

use modular_bitfield::prelude::*;
use ouroboros::self_referencing;
use smoltcp::wire::{DhcpOption, EthernetAddress, Ipv4Address};
use uuid::Uuid;

use super::error::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PxeVendorOption {
    MtftpIp,
    MtftpCport,
    MtftpSport,
    MtftpTimeout,
    MtftpDelay,
    DiscoverControl(PxeDiscoverControl),
    DisoveryMcastAddr,
    BootServers,
    BootMenu,
    MenuPrompt,
    McastAddr,
    CredentailTypes,
    BootItems,
    End,
}

impl From<PxeVendorOption> for u8 {
    fn from(val: PxeVendorOption) -> Self {
        match val {
            PxeVendorOption::MtftpIp => 1,
            PxeVendorOption::MtftpCport => 2,
            PxeVendorOption::MtftpSport => 3,
            PxeVendorOption::MtftpTimeout => 4,
            PxeVendorOption::MtftpDelay => 5,
            PxeVendorOption::DiscoverControl(_) => 6,
            PxeVendorOption::DisoveryMcastAddr => 7,
            PxeVendorOption::BootServers => 8,
            PxeVendorOption::BootMenu => 9,
            PxeVendorOption::MenuPrompt => 10,
            PxeVendorOption::McastAddr => 11,
            PxeVendorOption::CredentailTypes => 12,
            PxeVendorOption::BootItems => 71,
            PxeVendorOption::End => 255,
        }
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SubsetDhcpOption {
    ClientUuid = 97,
    ClientIdentifier = 61,
    ClientNetworkInterfaceIdentifier = 94,
    ClientSystemArchitecture = 93,
    ParameterRequestList = 55,
    VendorClassIdentifier = 60,
    VendorOptions = 43,
    MessageType = 53,
    ServerIdentifier = 54,
    MaximumMessageSize = 57,
    UserClassInformation = 77,
    End = 255,
}

impl From<SubsetDhcpOption> for u8 {
    fn from(val: SubsetDhcpOption) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for SubsetDhcpOption {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            97 => Ok(SubsetDhcpOption::ClientUuid),
            61 => Ok(SubsetDhcpOption::ClientIdentifier),
            94 => Ok(SubsetDhcpOption::ClientNetworkInterfaceIdentifier),
            93 => Ok(SubsetDhcpOption::ClientSystemArchitecture),
            55 => Ok(SubsetDhcpOption::ParameterRequestList),
            60 => Ok(SubsetDhcpOption::VendorClassIdentifier),
            43 => Ok(SubsetDhcpOption::VendorOptions),
            53 => Ok(SubsetDhcpOption::MessageType),
            54 => Ok(SubsetDhcpOption::ServerIdentifier),
            57 => Ok(SubsetDhcpOption::MaximumMessageSize),
            77 => Ok(SubsetDhcpOption::UserClassInformation),
            255 => Ok(SubsetDhcpOption::End),
            e => Err(Error::UnknownDhcpValue(e.into())),
        }
    }
}

/// The possible system architecture types
#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[allow(unused)]
pub enum ClientArchType {
    X86Bios = 0,
    PC98 = 1,
    EfiItanium = 2,
    DecAlpha = 3,
    ArcX86 = 4,
    IntelLeanClient = 5,
    X86Uefi = 6,
    X64Uefi = 7,
    EfiXscale = 8,
    Ebc = 9,
    Arm32Uefi = 10,
    Arm64Uefi = 11,
    PowerPcOpenFimware = 12,
    PowerPcepapr = 13,
    PowerOpalv3 = 14,
    X86UefiHttp = 15,
    X64UefiHttp = 16,
    EbcFromHttp = 17,
    Arm32UefiHttp = 18,
    Arm64UefiHttp = 19,
    X86BiosHttp = 20,
    Arm32Uboot = 21,
    Arm64Uboot = 22,
    Arm32UbootHttp = 23,
    Arm64UbootHttp = 24,
    Riscv32Uefi = 25,
    Riscv32UefiHttp = 26,
    Riscv64Uefi = 27,
    Riscv64UefiHttp = 28,
    Riscv128Uefi = 29,
    Riscv128UefiHttp = 30,
    S390Basic = 31,
    S390Extended = 32,
    Mips32Uefi = 33,
    Mips64Uefi = 34,
    Sunway32Uefi = 35,
    Sunway64Uefi = 36,
    LoongArch32Uefi = 37,
    LoongArch32UefiHttp = 38,
    LoongArch64Uefi = 39,
    LoongArch64UefiHttp = 40,
    ArmRpiBoot = 41,
}

impl TryFrom<&[u8]> for ClientArchType {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        use ClientArchType::*;
        let array = <&[u8; 2]>::try_from(value)?;
        let value = u16::from_be_bytes(*array);
        let res = match value {
            0 => X86Bios,
            1 => PC98,
            2 => EfiItanium,
            3 => DecAlpha,
            4 => ArcX86,
            5 => IntelLeanClient,
            6 => X86Uefi,
            7 => X64Uefi,
            8 => EfiXscale,
            9 => Ebc,
            10 => Arm32Uefi,
            11 => Arm64Uefi,
            12 => PowerPcOpenFimware,
            13 => PowerPcepapr,
            14 => PowerOpalv3,
            15 => X86UefiHttp,
            16 => X64UefiHttp,
            17 => EbcFromHttp,
            18 => Arm32UefiHttp,
            19 => Arm64UefiHttp,
            20 => X86BiosHttp,
            21 => Arm32Uboot,
            22 => Arm64Uboot,
            23 => Arm32UbootHttp,
            24 => Arm64UbootHttp,
            25 => Riscv32Uefi,
            26 => Riscv32UefiHttp,
            27 => Riscv64Uefi,
            28 => Riscv64UefiHttp,
            29 => Riscv128Uefi,
            30 => Riscv128UefiHttp,
            31 => S390Basic,
            32 => S390Extended,
            33 => Mips32Uefi,
            34 => Mips64Uefi,
            35 => Sunway32Uefi,
            36 => Sunway64Uefi,
            37 => LoongArch32Uefi,
            38 => LoongArch32UefiHttp,
            39 => LoongArch64Uefi,
            40 => LoongArch64UefiHttp,
            41 => ArmRpiBoot,
            e => return Err(Error::UnknownDhcpValue(e.into())),
        };
        Ok(res)
    }
}

impl From<ClientArchType> for u16 {
    fn from(value: ClientArchType) -> Self {
        value as u16
    }
}

impl From<ClientArchType> for DhcpOptionWrapper {
    fn from(val: ClientArchType) -> Self {
        let val = u16::from(val).to_be_bytes();
        DhcpOptionWrapperBuilder {
            mdata: val.to_vec(),
            option_builder: |data| {
                let kind = SubsetDhcpOption::ClientSystemArchitecture.into();
                let data = data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkInterfaceType {
    /// Universal Network Device Interface
    Undi = 1,
}

impl TryFrom<u8> for NetworkInterfaceType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(NetworkInterfaceType::Undi),
            e => Err(Error::UnknownDhcpValue(e.into())),
        }
    }
}

impl From<NetworkInterfaceType> for u8 {
    fn from(value: NetworkInterfaceType) -> Self {
        value as u8
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NetworkInterfaceVersion {
    pub interface_type: NetworkInterfaceType,
    pub major: u8,
    pub minor: u8,
}

impl TryFrom<&[u8]> for NetworkInterfaceVersion {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let array = <&[u8; 3]>::try_from(value)?;
        let interface_type = NetworkInterfaceType::try_from(array[0])?;
        let minor = array[1];
        let major = array[2];

        Ok(NetworkInterfaceVersion {
            interface_type,
            major,
            minor,
        })
    }
}

impl From<NetworkInterfaceVersion> for DhcpOptionWrapper {
    fn from(val: NetworkInterfaceVersion) -> Self {
        let val: [u8; 3] = [val.interface_type.into(), val.minor, val.major];
        DhcpOptionWrapperBuilder {
            mdata: val.to_vec(),
            option_builder: |data| {
                let kind = SubsetDhcpOption::ClientNetworkInterfaceIdentifier.into();
                let data = data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HardwareType {
    DomainName = 0,
    Ethernet = 1,
}

impl TryFrom<u8> for HardwareType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(HardwareType::DomainName),
            1 => Ok(HardwareType::Ethernet),
            e => Err(Error::UnknownDhcpValue(e.into())),
        }
    }
}

impl From<HardwareType> for u8 {
    fn from(val: HardwareType) -> Self {
        val as u8
    }
}

// Identifiers SHOULD be treated as opaque objects by DHCP servers.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ClientIdentifier {
    pub hardware_type: HardwareType,
    pub hardware_address: Vec<u8>,
}

impl Display for ClientIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.hardware_type {
            HardwareType::DomainName => {
                let domain_name = String::from_utf8_lossy(&self.hardware_address);
                write!(f, "{}", domain_name)
            }
            HardwareType::Ethernet => {
                let mac = EthernetAddress::from_bytes(&self.hardware_address);
                write!(f, "{}", mac)
            }
        }
    }
}

impl TryFrom<&[u8]> for ClientIdentifier {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let hardware_type = HardwareType::try_from(value[0])?;
        let hardware_address = value[1..].to_vec();
        Ok(ClientIdentifier {
            hardware_type,
            hardware_address,
        })
    }
}

impl From<ClientIdentifier> for Vec<u8> {
    fn from(val: ClientIdentifier) -> Self {
        let mut res = Vec::new();
        res.push(val.hardware_type.into());
        res.extend_from_slice(&val.hardware_address);
        res
    }
}

#[self_referencing]
#[derive(Debug, PartialEq, Eq)]
pub struct DhcpOptionWrapper {
    mdata: Vec<u8>,

    #[borrows(mdata)]
    #[covariant]
    option: DhcpOption<'this>,
}

impl<'a> From<&'a DhcpOptionWrapper> for DhcpOption<'a> {
    fn from(val: &'a DhcpOptionWrapper) -> Self {
        *val.borrow_option()
    }
}

impl From<ClientIdentifier> for DhcpOptionWrapper {
    fn from(val: ClientIdentifier) -> Self {
        let mut res: Vec<u8> = Vec::new();
        res.push(val.hardware_type.into());
        res.extend_from_slice(&val.hardware_address);
        DhcpOptionWrapperBuilder {
            mdata: res,
            option_builder: |data| {
                let kind = SubsetDhcpOption::ClientIdentifier.into();
                let data = &data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PxeServerIdentifier {
    pub ip: Ipv4Address,
}

impl TryFrom<&[u8]> for PxeServerIdentifier {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != 4 {
            return Err(Error::Malformed(
                "PXE Server Identifier must be 4 bytes long".to_string(),
            ));
        }

        let ip = Ipv4Address::from_bytes(value);
        Ok(PxeServerIdentifier { ip })
    }
}

impl From<PxeServerIdentifier> for DhcpOptionWrapper {
    fn from(val: PxeServerIdentifier) -> Self {
        DhcpOptionWrapperBuilder {
            mdata: val.ip.as_bytes().to_vec(),
            option_builder: |data| {
                let kind = SubsetDhcpOption::ServerIdentifier.into();
                let data = data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PxeUuid {
    pub uuid: Uuid,
}

impl TryFrom<&[u8]> for PxeUuid {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value[0] != 0 {
            return Err(Error::Malformed("Type of UUID must be 0".to_string()));
        }

        let uuid = Uuid::from_slice(&value[1..])
            .map_err(|e| Error::Malformed(f!("UUID is malformed. Reason: {}", e)))?;
        Ok(PxeUuid { uuid })
    }
}

impl From<PxeUuid> for DhcpOptionWrapper {
    fn from(val: PxeUuid) -> Self {
        let mut data = val.uuid.as_bytes().to_vec();
        data.insert(0, 0); // Type ethernet
        DhcpOptionWrapperBuilder {
            mdata: data,
            option_builder: |data| {
                let kind = SubsetDhcpOption::ClientUuid.into();
                let data = &data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VendorClassIdentifier {
    pub data: String,
}

impl TryFrom<&[u8]> for VendorClassIdentifier {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let data = String::from_utf8_lossy(value);
        Ok(VendorClassIdentifier {
            data: data.to_string(),
        })
    }
}

impl From<VendorClassIdentifier> for DhcpOptionWrapper {
    fn from(val: VendorClassIdentifier) -> Self {
        DhcpOptionWrapperBuilder {
            mdata: val.data.as_bytes().to_vec(),
            option_builder: |data| {
                let kind = SubsetDhcpOption::VendorClassIdentifier.into();
                let data = data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

#[bitfield]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct PxeDiscoverControl {
    pub disable_broadcast: bool,
    pub disable_multicast: bool,
    pub only_pxe_boot_servers: bool,
    pub direct_boot_file_download: bool,
    #[skip]
    __: B4,
}

impl PxeDiscoverControl {
    pub fn kind(&self) -> u8 {
        PxeVendorOption::DiscoverControl(*self).into()
    }
}

impl TryFrom<&[u8]> for PxeDiscoverControl {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let bytes: [u8; 1] = value.try_into().map_err(|_| {
            Error::Malformed("PXE Discover Control must be 1 byte long".to_string())
        })?;
        let res = PxeDiscoverControl::from_bytes(bytes);
        Ok(res)
    }
}

impl From<PxeDiscoverControl> for VendorOption {
    fn from(val: PxeDiscoverControl) -> Self {
        let mut data = vec![];
        data.extend_from_slice(&val.bytes);
        let kind: u8 = val.kind();
        VendorOption { kind, data }
    }
}

pub struct VendorOption {
    pub kind: u8,
    pub data: Vec<u8>,
}

impl From<&[VendorOption]> for DhcpOptionWrapper {
    fn from(val: &[VendorOption]) -> Self {
        let mut data = Vec::new();
        for opt in val {
            data.push(opt.kind);
            data.push(opt.data.len().try_into().unwrap());
            data.extend_from_slice(&opt.data);
        }
        data.push(PxeVendorOption::End.into());
        DhcpOptionWrapperBuilder {
            mdata: data,
            option_builder: |data| {
                let kind = SubsetDhcpOption::VendorOptions.into();
                let data = &data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

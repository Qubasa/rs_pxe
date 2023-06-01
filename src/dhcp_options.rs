use std::fmt::{self, Display, Formatter};

use ouroboros::self_referencing;
use smoltcp::wire::{DhcpOption, EthernetAddress, Ipv4Address};
use uuid::Uuid;

use crate::error::Error;

use crate::prelude::*;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PxeDhcpOption {
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
    PxeMtftpIp = 1,
    PxeMtftpCport = 2,
    PxeMtftpSport = 3,
    PxeMtftpTimeout = 4,
    PxeMtftpDelay = 5,
    PxeDiscoverControl = 6,
    DisoveryMcastAddr = 7,
    PxeBootServers = 8,
    PxeBootMenu = 9,
    PxeMenuPrompt = 10,
    PxeMcastAddr = 11,
    PxeCredentailTypes = 12,
    PxeBootItems = 71,
    End = 255,
}
impl From<PxeDhcpOption> for u8 {
    fn from(val: PxeDhcpOption) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for PxeDhcpOption {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            97 => Ok(PxeDhcpOption::ClientUuid),
            61 => Ok(PxeDhcpOption::ClientIdentifier),
            94 => Ok(PxeDhcpOption::ClientNetworkInterfaceIdentifier),
            93 => Ok(PxeDhcpOption::ClientSystemArchitecture),
            55 => Ok(PxeDhcpOption::ParameterRequestList),
            60 => Ok(PxeDhcpOption::VendorClassIdentifier),
            43 => Ok(PxeDhcpOption::VendorOptions),
            53 => Ok(PxeDhcpOption::MessageType),
            54 => Ok(PxeDhcpOption::ServerIdentifier),
            57 => Ok(PxeDhcpOption::MaximumMessageSize),
            1 => Ok(PxeDhcpOption::PxeMtftpIp),
            2 => Ok(PxeDhcpOption::PxeMtftpCport),
            3 => Ok(PxeDhcpOption::PxeMtftpSport),
            4 => Ok(PxeDhcpOption::PxeMtftpTimeout),
            5 => Ok(PxeDhcpOption::PxeMtftpDelay),
            6 => Ok(PxeDhcpOption::PxeDiscoverControl),
            7 => Ok(PxeDhcpOption::DisoveryMcastAddr),
            8 => Ok(PxeDhcpOption::PxeBootServers),
            9 => Ok(PxeDhcpOption::PxeBootMenu),
            10 => Ok(PxeDhcpOption::PxeMenuPrompt),
            11 => Ok(PxeDhcpOption::PxeMcastAddr),
            12 => Ok(PxeDhcpOption::PxeCredentailTypes),
            71 => Ok(PxeDhcpOption::PxeBootItems),
            255 => Ok(PxeDhcpOption::End),
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
        let value = u16::from_le_bytes(*array);
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
        let interface_type = NetworkInterfaceType::try_from(array[2])?;
        let minor = array[0];
        let major = array[1];

        Ok(NetworkInterfaceVersion {
            interface_type,
            major,
            minor,
        })
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
                let kind = PxeDhcpOption::ClientIdentifier.into();
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
                let kind = PxeDhcpOption::ServerIdentifier.into();
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
                let kind = PxeDhcpOption::ClientUuid.into();
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
                let kind = PxeDhcpOption::VendorClassIdentifier.into();
                let data = data;
                DhcpOption { kind, data }
            },
        }
        .build()
    }
}

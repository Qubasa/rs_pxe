use crate::error::Error;

use crate::prelude::*;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DhcpOption {
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
impl TryFrom<u8> for DhcpOption {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            97 => Ok(DhcpOption::ClientUuid),
            61 => Ok(DhcpOption::ClientIdentifier),
            94 => Ok(DhcpOption::ClientNetworkInterfaceIdentifier),
            93 => Ok(DhcpOption::ClientSystemArchitecture),
            55 => Ok(DhcpOption::ParameterRequestList),
            60 => Ok(DhcpOption::VendorClassIdentifier),
            43 => Ok(DhcpOption::VendorOptions),
            53 => Ok(DhcpOption::MessageType),
            54 => Ok(DhcpOption::ServerIdentifier),
            57 => Ok(DhcpOption::MaximumMessageSize),
            1 => Ok(DhcpOption::PxeMtftpIp),
            2 => Ok(DhcpOption::PxeMtftpCport),
            3 => Ok(DhcpOption::PxeMtftpSport),
            4 => Ok(DhcpOption::PxeMtftpTimeout),
            5 => Ok(DhcpOption::PxeMtftpDelay),
            6 => Ok(DhcpOption::PxeDiscoverControl),
            7 => Ok(DhcpOption::DisoveryMcastAddr),
            8 => Ok(DhcpOption::PxeBootServers),
            9 => Ok(DhcpOption::PxeBootMenu),
            10 => Ok(DhcpOption::PxeMenuPrompt),
            11 => Ok(DhcpOption::PxeMcastAddr),
            12 => Ok(DhcpOption::PxeCredentailTypes),
            71 => Ok(DhcpOption::PxeBootItems),
            255 => Ok(DhcpOption::End),
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
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ClientIdentifier {
    pub hardware_type: HardwareType,
    pub hardware_address: Vec<u8>,
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

#![allow(dead_code)]

use smoltcp::wire::Error;

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

impl TryFrom<u16> for ClientArchType {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        use ClientArchType::*;
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
            _ => return Err(Error),
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

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(NetworkInterfaceType::Undi),
            _ => Err(Error),
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

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum MachineIdType {
    /// Globally Unique Identifier type
    Guid = 0,
}

impl TryFrom<u8> for MachineIdType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            0 => Ok(MachineIdType::Guid),
            _ => Err(Error),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct MachineId<'a> {
    pub id_type: MachineIdType,
    pub id: &'a [u8],
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum DhcpOption {
    Reserved = 0,
    CLIENTID = 1,
    SERVERID = 2,
    IA_NA = 3,
    IA_TA = 4,
    IAADDR = 5,
    ORO = 6,
    PREFERENCE = 7,
    ELAPSED_TIME = 8,
    RELAY_MSG = 9,
    Unassigned = 10,
    AUTH = 11,
    UNICAST = 12,
    STATUS_CODE = 13,
    RAPID_COMMIT = 14,
    USER_CLASS = 15,
    VENDOR_CLASS = 16,
    VENDOR_OPTS = 17,
    INTERFACE_ID = 18,
    RECONF_MSG = 19,
    RECONF_ACCEPT = 20,
    SIP_SERVER_D = 21,
    SIP_SERVER_A = 22,
    DNS_SERVERS = 23,
    DOMAIN_LIST = 24,
    IA_PD = 25,
    IAPREFIX = 26,
    NIS_SERVERS = 27,
    NISP_SERVERS = 28,
    NIS_DOMAIN_NAME = 29,
    NISP_DOMAIN_NAME = 30,
    SNTP_SERVERS = 31,
    INFORMATION_REFRESH_TIME = 32,
    BCMCS_SERVER_D = 33,
    BCMCS_SERVER_A = 34,
    Unassigned2 = 35,
    GEOCONF_CIVIC = 36,
    REMOTE_ID = 37,
    SUBSCRIBER_ID = 38,
    CLIENT_FQDN = 39,
    PANA_AGENT = 40,
    NEW_POSIX_TIMEZONE = 41,
    NEW_TZDB_TIMEZONE = 42,
    ERO = 43,
    LQ_QUERY = 44,
    CLIENT_DATA = 45,
    CLT_TIME = 46,
    LQ_RELAY_DATA = 47,
    LQ_CLIENT_LINK = 48,
    MIP6_HNIDF = 49,
    MIP6_VDINF = 50,
    V6_LOST = 51,
    CAPWAP_AC_V6 = 52,
    RELAY_ID = 53,
    IPv6_Address_MoS = 54,
    IPv6_FQDN_MoS = 55,
    NTP_SERVER = 56,
    V6_ACCESS_DOMAIN = 57,
    S = 58,
}

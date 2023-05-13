use crate::error::Error;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DhcpOption {
    ClientUuid = 97,
    ClientGuid = 61,
    ClientNetworkInterfaceIdentifier = 94,
    ClientSystemArchitecture = 93,
    ParameterRequestList = 55,
    ClassIdentifier = 60,
    VendorOptions = 43,
    MessageType = 53,
    ServerID = 54,
    MessageLength = 57,
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
    fn try_from(value: u8) -> Result<Self, Error> {
        match value {
            97 => Ok(DhcpOption::ClientUuid),
            61 => Ok(DhcpOption::ClientGuid),
            94 => Ok(DhcpOption::ClientNetworkInterfaceIdentifier),
            93 => Ok(DhcpOption::ClientSystemArchitecture),
            55 => Ok(DhcpOption::ParameterRequestList),
            60 => Ok(DhcpOption::ClassIdentifier),
            43 => Ok(DhcpOption::VendorOptions),
            53 => Ok(DhcpOption::MessageType),
            54 => Ok(DhcpOption::ServerID),
            57 => Ok(DhcpOption::MessageLength),
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

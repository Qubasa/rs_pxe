use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

/// Returns whether a port is available on the localhost
pub fn is_local_port_free(port: u16) -> bool {
    let ipv4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    UdpSocket::bind(ipv4).is_ok()
}

/// Returns an available localhost port within the specified range.
///
/// 'min' and 'max' values are included in the range
///
pub fn free_local_port_in_range(min: u16, max: u16) -> Option<u16> {
    (min..max).find(|port| is_local_port_free(*port))
}

/// Returns an available localhost port
pub fn free_local_port() -> Option<u16> {
    let socket = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    UdpSocket::bind(socket)
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .ok()
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_return_an_unused_port() {
        let result = free_local_port();
        assert!(result.is_some());
        assert!(is_local_port_free(result.unwrap()));
    }

    #[test]
    fn should_return_an_unused_port_in_range() {
        let free_port = free_local_port().unwrap();
        let min = free_port - 100;
        let max = free_port;
        let port_found = free_local_port_in_range(min, max).unwrap();
        assert!(port_found >= min);
        assert!(port_found <= max);
    }
}

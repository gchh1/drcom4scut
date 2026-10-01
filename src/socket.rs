use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use log::{error, info};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{
    LookupIpStrategy, NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};

use crate::settings::Settings;

pub fn resolve_dns(settings: &Settings, local_ip: IpAddr) -> Option<(IpAddr, SocketAddr)> {
    info!("DNS resolving...");
    let r = settings
        .dns
        .iter()
        .filter_map(|address| {
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig {
                socket_addr: *address,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: false,
                bind_addr: Some(SocketAddr::new(local_ip, 0)),
            });
            info!("Use DNS: {}:{}", address.ip(), address.port());
            let mut options = ResolverOpts::default();
            options.ip_strategy = LookupIpStrategy::Ipv4Only;
            options.timeout = std::time::Duration::from_secs(3);
            options.attempts = 2;
            let resolver = match Resolver::new(config, options) {
                Ok(r) => r,
                Err(_) => {
                    error!("Failed to connect resolver.");
                    return None;
                }
            };
            let lookup = match resolver.lookup_ip(&settings.host) {
                Ok(r) => r,
                Err(_) => {
                    error!("Failed to lookup.");
                    return None;
                }
            };
            if let Some(ip) = lookup.iter().next() {
                Some((ip, *address))
            } else {
                error!("No addresses returned!");
                None
            }
        })
        .next();
    info!("Resolve result:");
    if let Some(r1) = r {
        info!("IP: {}", r1.0);
    } else {
        error!("Resolve failed.");
    }
    r
}

pub fn socket_bind(server_ip: IpAddr, local_ip: IpAddr) -> io::Result<UdpSocket> {
    if !server_ip.is_ipv4() || !local_ip.is_ipv4() || local_ip.is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP authentication requires the selected adapter's IPv4 address",
        ));
    }
    let address = SocketAddr::new(server_ip, 61440);
    for port in 36144..=u16::MAX {
        match UdpSocket::bind(SocketAddr::new(local_ip, port)) {
            Ok(socket) => {
                socket.connect(address)?;
                return Ok(socket);
            }
            Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "No available UDP authentication port",
    ))
}

pub struct Socket {
    socket: UdpSocket,
}

impl Socket {
    pub fn new(socket: UdpSocket) -> Socket {
        Socket { socket }
    }

    pub fn send(&self, data: Vec<u8>) -> io::Result<()> {
        let l = data.len();
        let mut n = 0;
        while n < l {
            n += self.socket.send(&data[n..l])?;
        }
        Ok(())
    }

    pub fn receive(&self) -> io::Result<Vec<u8>> {
        let mut buffer = [0u8; 2048];
        let size = self.socket.recv(&mut buffer)?;
        let v = buffer[..size].to_vec();
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    #[test]
    fn udp_uses_selected_source_address_and_skips_occupied_port() {
        let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let _occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 36144));
        let socket = socket_bind(local, local).unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), local);
        assert!(socket.local_addr().unwrap().port() > 36144);
        assert_eq!(socket.peer_addr().unwrap(), SocketAddr::new(local, 61440));
    }
    #[test]
    fn udp_rejects_unspecified_source_instead_of_using_default_route() {
        assert_eq!(
            socket_bind(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

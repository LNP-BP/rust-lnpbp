// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

//! Network addresses uniform encoding (LNPBP-??)

use std::convert::TryFrom;
use std::io;
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};

use crate::{strategies, Error, Strategy, StrictDecode, StrictEncode};

pub const ADDR_LEN: usize = 33; // Maximum Tor public key size
pub const UNIFORM_LEN: usize = ADDR_LEN
    + 1  // Prefix byte for specifying address format (IP, Onion, etc)
    + 2  // Suffix byte for specifying port number
    + 1; // Suffix byte for specifying transport-level protocol (TCP, UDP, ...)

pub type RawAddr = [u8; ADDR_LEN];
pub type RawUniformAddr = [u8; UNIFORM_LEN];

#[derive(
    Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error,
)]
#[display(doc_comments)]
#[non_exhaustive]
pub enum DecodeError {
    /// Unknown network address format
    UnknownAddrFormat,

    /// Unknown network transport protocol
    UnknownTransport,

    /// Used address format is not supported by the software
    UnsupportedAddrFormat,

    /// Used transport protocol is not supported by the software
    UnsupportedTransport,

    /// Network address raw data are corrupted and do not correspond to the
    /// encoding specification
    InvalidAddr,

    /// Public key identifying network address is invalid
    InvalidPubkey,

    /// Data provided by the uniform-encoded network address does not fit
    /// target address structure
    ExcessiveData,

    /// Data provided by the uniform-encoded network address does not
    /// sufficient for target address structure
    InsufficientData,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[repr(u8)]
#[non_exhaustive]
pub enum AddrFormat {
    #[display("ipv4")]
    IpV4 = 0,

    #[display("ipv6")]
    IpV6 = 1,

    #[display("onion(v2)")]
    OnionV2 = 2,

    #[display("onion(v3)")]
    OnionV3 = 3,

    #[display("lightning")]
    Lightning = 4,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[repr(u8)]
#[non_exhaustive]
pub enum Transport {
    /// Normal TCP
    #[display("tcp")]
    Tcp = 1,

    /// Normal UDP
    #[display("udp")]
    Udp = 2,

    /// Multipath TCP version
    #[display("mtcp")]
    Mtcp = 3,

    /// More efficient UDP version under development by Google and consortium
    /// of other internet companies
    #[display("quic")]
    Quic = 4,
}

#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct UniformAddr {
    pub addr_format: AddrFormat,
    pub addr: RawAddr,
    pub port: Option<u16>,
    pub transport: Option<Transport>,
}

pub trait Uniform {
    fn addr_format(&self) -> AddrFormat;
    fn addr(&self) -> RawAddr;
    fn port(&self) -> Option<u16>;
    fn transport(&self) -> Option<Transport>;

    #[inline]
    fn to_uniform_addr(&self) -> UniformAddr {
        UniformAddr {
            addr_format: self.addr_format(),
            addr: self.addr(),
            port: self.port(),
            transport: self.transport(),
        }
    }

    #[inline]
    fn to_raw_uniform(&self) -> RawUniformAddr {
        self.to_uniform_addr().into()
    }

    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized;

    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized;

    fn from_raw_uniform_addr(
        uniform: RawUniformAddr,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Self::from_uniform_addr(UniformAddr::try_from(uniform)?)
    }

    fn from_raw_uniform_addr_lossy(
        uniform: RawUniformAddr,
    ) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Self::from_uniform_addr_lossy(UniformAddr::try_from(uniform)?)
    }
}

impl Uniform for UniformAddr {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        self.addr_format
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        self.addr
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        self.port
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        self.transport
    }

    #[inline]
    fn to_uniform_addr(&self) -> UniformAddr {
        self.clone()
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Ok(addr.clone())
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        UniformAddr::from_uniform_addr(addr)
    }
}

impl From<UniformAddr> for RawUniformAddr {
    fn from(addr: UniformAddr) -> Self {
        let mut raw = [0u8; UNIFORM_LEN];
        raw[0] = addr.addr_format as u8;
        raw[1..ADDR_LEN + 1].copy_from_slice(&addr.addr);
        if let Some(port) = addr.port {
            raw[ADDR_LEN + 1] = (port >> 8) as u8;
            raw[ADDR_LEN + 2] = (port & 0xFF) as u8;
        }
        if let Some(transport) = addr.transport {
            raw[UNIFORM_LEN - 1] = transport as u8;
        }
        raw
    }
}

impl TryFrom<RawUniformAddr> for UniformAddr {
    type Error = DecodeError;

    fn try_from(raw: RawUniformAddr) -> Result<Self, DecodeError> {
        let addr_format = match raw[0] {
            a if a == AddrFormat::IpV4 as u8 => AddrFormat::IpV4,
            a if a == AddrFormat::IpV6 as u8 => AddrFormat::IpV6,
            a if a == AddrFormat::OnionV2 as u8 => AddrFormat::OnionV2,
            a if a == AddrFormat::OnionV3 as u8 => AddrFormat::OnionV3,
            a if a == AddrFormat::Lightning as u8 => AddrFormat::Lightning,
            _ => return Err(DecodeError::UnknownAddrFormat),
        };
        let mut addr = [0u8; ADDR_LEN];
        addr.copy_from_slice(&raw[1..ADDR_LEN + 1]);
        if match addr_format {
            AddrFormat::IpV4 => &addr[..29],
            AddrFormat::IpV6 => &addr[..17],
            AddrFormat::OnionV2 => &addr[..23],
            AddrFormat::OnionV3 => &addr[..1],
            AddrFormat::Lightning => &[][..],
        }
        .iter()
        .filter(|byte| **byte != 0)
        .count()
            != 0
        {
            return Err(DecodeError::InvalidAddr);
        }
        let port = (((raw[ADDR_LEN + 1] as u16) & 0x00FF) << 8)
            + raw[ADDR_LEN + 2] as u16;
        let port = if port == 0 { None } else { Some(port) };
        let transport = match raw[UNIFORM_LEN - 1] {
            0 => None,
            t if t == Transport::Tcp as u8 => Some(Transport::Tcp),
            t if t == Transport::Udp as u8 => Some(Transport::Udp),
            t if t == Transport::Mtcp as u8 => Some(Transport::Mtcp),
            t if t == Transport::Quic as u8 => Some(Transport::Quic),
            _ => return Err(DecodeError::UnknownTransport),
        };
        Ok(UniformAddr {
            addr_format,
            addr,
            port,
            transport,
        })
    }
}

impl Uniform for IpAddr {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        match self {
            IpAddr::V4(_) => AddrFormat::IpV4,
            IpAddr::V6(_) => AddrFormat::IpV6,
        }
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        match self {
            IpAddr::V4(ip) => ip.addr(),
            IpAddr::V6(ip) => ip.addr(),
        }
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        None
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Ok(match addr.addr_format {
            AddrFormat::IpV4 => IpAddr::V4(Ipv4Addr::from_uniform_addr(addr)?),
            AddrFormat::IpV6 => IpAddr::V6(Ipv6Addr::from_uniform_addr(addr)?),
            _ => Err(DecodeError::UnsupportedAddrFormat)?,
        })
    }

    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Ok(match addr.addr_format {
            AddrFormat::IpV4 => {
                IpAddr::V4(Ipv4Addr::from_uniform_addr_lossy(addr)?)
            }
            AddrFormat::IpV6 => {
                IpAddr::V6(Ipv6Addr::from_uniform_addr_lossy(addr)?)
            }
            _ => Err(DecodeError::UnsupportedAddrFormat)?,
        })
    }
}

impl Uniform for Ipv4Addr {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        AddrFormat::IpV4
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        let mut ip = [0u8; ADDR_LEN];
        ip[29..].copy_from_slice(&self.octets());
        ip
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        None
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if addr.port.is_some() || addr.transport.is_some() {
            return Err(DecodeError::ExcessiveData);
        }
        Ipv4Addr::from_uniform_addr_lossy(addr)
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&addr.addr[29..]);
        Ok(Ipv4Addr::from(ip))
    }
}

impl Uniform for Ipv6Addr {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        AddrFormat::IpV6
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        let mut ip = [0u8; ADDR_LEN];
        ip[17..].copy_from_slice(&self.octets());
        ip
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        None
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if addr.port.is_some() || addr.transport.is_some() {
            return Err(DecodeError::ExcessiveData);
        }
        Ipv6Addr::from_uniform_addr_lossy(addr)
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&addr.addr[17..]);
        Ok(Ipv6Addr::from(ip))
    }
}

impl Uniform for SocketAddr {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        match self {
            SocketAddr::V4(_) => AddrFormat::IpV4,
            SocketAddr::V6(_) => AddrFormat::IpV6,
        }
    }

    #[inline]
    fn addr(&self) -> [u8; 33] {
        match self {
            SocketAddr::V4(socket) => socket.addr(),
            SocketAddr::V6(socket) => socket.addr(),
        }
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        Some(self.port())
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Ok(match addr.addr_format {
            AddrFormat::IpV4 => {
                SocketAddr::V4(SocketAddrV4::from_uniform_addr(addr)?)
            }
            AddrFormat::IpV6 => {
                SocketAddr::V6(SocketAddrV6::from_uniform_addr(addr)?)
            }
            _ => Err(DecodeError::UnsupportedAddrFormat)?,
        })
    }

    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        Ok(match addr.addr_format {
            AddrFormat::IpV4 => {
                SocketAddr::V4(SocketAddrV4::from_uniform_addr_lossy(addr)?)
            }
            AddrFormat::IpV6 => {
                SocketAddr::V6(SocketAddrV6::from_uniform_addr_lossy(addr)?)
            }
            _ => Err(DecodeError::UnsupportedAddrFormat)?,
        })
    }
}

impl Uniform for SocketAddrV4 {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        AddrFormat::IpV4
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        let mut ip = [0u8; ADDR_LEN];
        ip[29..].copy_from_slice(&self.ip().octets());
        ip
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        Some(self.port())
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if addr.transport.is_some() {
            return Err(DecodeError::ExcessiveData);
        }
        SocketAddrV4::from_uniform_addr_lossy(addr)
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let mut ip = [0u8; 4];
        ip.copy_from_slice(&addr.addr[29..]);
        if let Some(port) = addr.port() {
            Ok(SocketAddrV4::new(Ipv4Addr::from(ip), port))
        } else {
            Err(DecodeError::InsufficientData)
        }
    }
}

impl Uniform for SocketAddrV6 {
    #[inline]
    fn addr_format(&self) -> AddrFormat {
        AddrFormat::IpV6
    }

    #[inline]
    fn addr(&self) -> RawAddr {
        let mut ip = [0u8; ADDR_LEN];
        ip[17..].copy_from_slice(&self.ip().octets());
        ip
    }

    #[inline]
    fn port(&self) -> Option<u16> {
        Some(self.port())
    }

    #[inline]
    fn transport(&self) -> Option<Transport> {
        None
    }

    #[inline]
    fn from_uniform_addr(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        if addr.transport.is_some() {
            return Err(DecodeError::ExcessiveData);
        }
        SocketAddrV6::from_uniform_addr_lossy(addr)
    }

    #[inline]
    fn from_uniform_addr_lossy(addr: UniformAddr) -> Result<Self, DecodeError>
    where
        Self: Sized,
    {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&addr.addr[17..]);
        if let Some(port) = addr.port() {
            Ok(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
        } else {
            Err(DecodeError::InsufficientData)
        }
    }
}

impl StrictEncode for RawAddr {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(self)?;
        Ok(self.len())
    }
}

impl StrictDecode for RawAddr {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut ret = [0u8; ADDR_LEN];
        d.read_exact(&mut ret)?;
        Ok(ret)
    }
}

impl StrictEncode for RawUniformAddr {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(self)?;
        Ok(self.len())
    }
}

impl StrictDecode for RawUniformAddr {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut ret = [0u8; UNIFORM_LEN];
        d.read_exact(&mut ret)?;
        Ok(ret)
    }
}

impl Strategy for UniformAddr {
    type Strategy = strategies::UsingUniformAddr;
}

impl Strategy for IpAddr {
    type Strategy = strategies::UsingUniformAddr;
}

impl Strategy for Ipv4Addr {
    type Strategy = strategies::UsingUniformAddr;
}

impl Strategy for Ipv6Addr {
    type Strategy = strategies::UsingUniformAddr;
}

impl Strategy for SocketAddr {
    type Strategy = strategies::UsingUniformAddr;
}

impl Strategy for SocketAddrV4 {
    type Strategy = strategies::UsingUniformAddr;
}

impl Strategy for SocketAddrV6 {
    type Strategy = strategies::UsingUniformAddr;
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryInto;

    fn gen_ipv4_addrs() -> Vec<Ipv4Addr> {
        let vars = [0u8, 1, 32, 48, 64, 127, 168, 192, 254, 255];
        let mut addrs = Vec::<Ipv4Addr>::with_capacity(vars.len().pow(4));
        for v1 in &vars {
            for v2 in &vars {
                for v3 in &vars {
                    for v4 in &vars {
                        addrs.push(Ipv4Addr::new(*v1, *v2, *v3, *v4));
                    }
                }
            }
        }
        addrs
    }

    fn gen_ipv6_addrs() -> Vec<Ipv6Addr> {
        let vars = [0u16, 1, 127, 256, std::u16::MAX];
        let ipv4 = gen_ipv4_addrs();
        let mut addrs = Vec::<Ipv6Addr>::with_capacity(
            vars.len().pow(5) * 4 + ipv4.len() * 2,
        );
        addrs.extend(ipv4.iter().map(|ip| ip.to_ipv6_compatible()));
        addrs.extend(ipv4.iter().map(|ip| ip.to_ipv6_mapped()));
        for v1 in &vars {
            for v2 in &vars {
                for v3 in &vars {
                    for v4 in &vars {
                        for v5 in &vars {
                            addrs.push(Ipv6Addr::new(
                                *v1, 0, 0, 0, *v2, *v3, *v4, *v5,
                            ));
                            addrs.push(Ipv6Addr::new(
                                *v1, 0, 0, *v2, 0, *v3, *v4, *v5,
                            ));
                            addrs.push(Ipv6Addr::new(
                                *v1, *v2, *v3, 0, 0, 0, *v4, *v5,
                            ));
                            addrs.push(Ipv6Addr::new(
                                0x2001, *v1, 0xff0e, 0x890a, *v2, *v3, *v4, *v5,
                            ));
                        }
                    }
                }
            }
        }
        addrs
    }

    #[test]
    fn uniform_raw_roundtrip_ipv4() {
        for ip in gen_ipv4_addrs() {
            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV4,
                addr: ip.addr(),
                port: None,
                transport: None,
            };
            println!("{}", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());

            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV4,
                addr: ip.addr(),
                port: Some(6432),
                transport: None,
            };
            println!("{}:6432", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());

            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV4,
                addr: ip.addr(),
                port: None,
                transport: Some(Transport::Tcp),
            };
            println!("tcp://{}", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());

            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV4,
                addr: ip.addr(),
                port: Some(32),
                transport: Some(Transport::Udp),
            };
            println!("udp://{}:32", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());
        }
    }

    #[test]
    fn uniform_raw_roundtrip_ipv6() {
        for ip in gen_ipv6_addrs() {
            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV6,
                addr: ip.addr(),
                port: None,
                transport: None,
            };
            println!("{}", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());

            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV6,
                addr: ip.addr(),
                port: Some(6432),
                transport: None,
            };
            println!("{}:6432", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());

            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV6,
                addr: ip.addr(),
                port: None,
                transport: Some(Transport::Tcp),
            };
            println!("tcp://{}", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());

            let uniform = UniformAddr {
                addr_format: AddrFormat::IpV6,
                addr: ip.addr(),
                port: Some(32),
                transport: Some(Transport::Udp),
            };
            println!("udp://{}:32", ip);
            let raw = uniform.to_raw_uniform();
            assert_eq!(uniform, raw.try_into().unwrap());
        }
    }

    #[test]
    fn uniform_raw_conversion() {
        use bitcoin::hashes::hex::ToHex;
        use std::str::FromStr;

        let ips = vec![
            "0.0.0.0",
            "8.8.8.8",
            "127.0.0.1",
            "192.168.0.1",
            "255.255.255.255",
        ]
        .into_iter()
        .map(Ipv4Addr::from_str)
        .map(Result::unwrap);

        for ip in ips {
            for port in vec![None, Some(32), Some(6432), Some(50001)] {
                for transport in vec![
                    None,
                    Some(Transport::Tcp),
                    Some(Transport::Udp),
                    Some(Transport::Quic),
                ] {
                    let uniform = UniformAddr {
                        addr_format: AddrFormat::IpV4,
                        addr: ip.addr(),
                        port,
                        transport,
                    };

                    let hex = format!(
                        "00{:066x}{:04x}{:02x}",
                        u32::from_be_bytes(ip.octets()),
                        port.unwrap_or_default(),
                        transport.map(|t| t as u8).unwrap_or_default()
                    );
                    assert_eq!(uniform.to_raw_uniform().to_hex(), hex);
                }
            }
        }
    }
}

// LNP/BP lLibraries implementing LNPBP specifications & standards
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

#[macro_use]
extern crate amplify;

use std::fmt::{self, Debug, Display, Formatter};
use std::io::{Read, Write};
use std::str::FromStr;
use std::string::FromUtf8Error;

use amplify::hex::ToHex;
use bech32::{FromBase32, ToBase32};
use bitcoin_hashes::{sha256, sha256d};
use secp256k1::{Message, SECP256K1};
use strict_encoding::{StrictDecode, StrictEncode};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error)]
#[display("unknown algorithm {0}")]
pub struct UnrecognizedAlgo(pub String);

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
pub enum CertError {
    #[display("incorrect bech32(m) string due to {0}")]
    #[from]
    Bech32(bech32::Error),

    #[display("unrecognized certificate of `{0}` type; only `{1}1...` strings are supported")]
    InvalidHrp(String, &'static str),

    #[display("certificates require bech32m encoding")]
    InvalidVariant,

    #[display("mnemonic guard does not match certificate nym {0}")]
    InvalidMnemonic(String),

    #[display("provided certificate contains incomplete data")]
    #[from(strict_encoding::Error)]
    IncompleteData,

    #[display("certificate uses unknown cryptographic algorithm; try to update the tool version")]
    UnknownAlgo,

    #[display(inner)]
    #[from]
    Utf8(FromUtf8Error),
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value, repr = u8)]
#[repr(u8)]
pub enum HashAlgo {
    #[display("sha256d")]
    Sha256d = 2,
}

impl HashAlgo {
    pub fn len(self) -> u8 {
        match self {
            Self::Sha256d => 32,
        }
    }
}

impl FromStr for HashAlgo {
    type Err = UnrecognizedAlgo;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            s if s == Self::Sha256d.to_string() => Ok(Self::Sha256d),
            wrong => Err(UnrecognizedAlgo(wrong.to_owned())),
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value, repr = u8)]
#[repr(u8)]
pub enum EcAlgo {
    #[display("bip340")]
    Bip340 = 1,

    #[display("ed25519")]
    Ed25519 = 2,
}

impl EcAlgo {
    pub fn cert_len(self) -> usize {
        1 + self.pub_len() + self.sig_len()
    }

    pub fn prv_len(self) -> usize {
        match self {
            Self::Bip340 => 32,
            Self::Ed25519 => 32,
        }
    }

    pub fn pub_len(self) -> usize {
        match self {
            Self::Bip340 => 32,
            Self::Ed25519 => 32,
        }
    }

    pub fn sig_len(self) -> usize {
        match self {
            Self::Bip340 => 64,
            Self::Ed25519 => 64,
        }
    }

    pub fn decode(code: u8) -> Option<Self> {
        Some(match code {
            x if x == Self::Bip340 as u8 => Self::Bip340,
            x if x == Self::Ed25519 as u8 => Self::Ed25519,
            _ => return None,
        })
    }

    pub fn encode(self) -> u8 {
        self as u8
    }
}

impl FromStr for EcAlgo {
    type Err = UnrecognizedAlgo;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bip340" => Ok(Self::Bip340),
            "ed25519" => Ok(Self::Ed25519),
            wrong => Err(UnrecognizedAlgo(wrong.to_owned())),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct IdentityCert {
    algo: EcAlgo,
    pubkey: Box<[u8]>,
    sig: Box<[u8]>,
}

impl IdentityCert {
    pub fn nym(&self) -> String {
        let mut mnemonic = Vec::with_capacity(64);
        let mut crc32data = Vec::with_capacity(self.algo.cert_len() as usize);
        crc32data.push(self.algo.encode());
        crc32data.extend(&*self.pubkey);
        let crc32 = crc32fast::hash(&crc32data);
        mnemonic::encode(crc32.to_be_bytes(), &mut mnemonic)
            .expect("mnemonic encoding");

        String::from_utf8(mnemonic)
            .expect("mnemonic library error")
            .replace('-', "_")
    }

    pub fn fingerprint(&self) -> String {
        let mut s = format!("{:#}", self);
        let _ = s.split_off(6);
        s
    }
}

impl StrictEncode for IdentityCert {
    fn strict_encode<E: Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        self.algo.strict_encode(&mut e)?;
        e.write_all(&self.pubkey)?;
        e.write_all(&self.sig)?;
        Ok(self.algo.cert_len() as usize)
    }
}

impl StrictDecode for IdentityCert {
    fn strict_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let algo = EcAlgo::strict_decode(&mut d)?;

        let mut pubkey = vec![0u8; algo.pub_len()];
        let mut sig = vec![0u8; algo.sig_len()];
        d.read_exact(&mut pubkey)?;
        d.read_exact(&mut sig)?;

        Ok(Self {
            algo,
            pubkey: Box::from(pubkey),
            sig: Box::from(sig),
        })
    }
}

impl Debug for IdentityCert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "nym   {}", self.nym())?;
        writeln!(f, "fgp   {}", self.fingerprint())?;
        writeln!(f, "crv   {}", self.algo)?;
        writeln!(f, "idk   {}", bin_fmt(&self.pubkey))?;
        writeln!(f, "sig   {}", bin_fmt(&self.sig))?;

        Ok(())
    }
}

impl Display for IdentityCert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let data = self
            .strict_serialize()
            .expect("strict encoding of certificate");
        let s =
            bech32::encode("crt", data.to_base32(), bech32::Variant::Bech32m)
                .expect("bech32 encoding of certificate");

        if f.alternate() {
            f.write_str(&s[s.len() - 6..])?;
        } else {
            f.write_str(&s)?;
        }
        f.write_str("_")?;
        f.write_str(&self.nym())
    }
}

impl FromStr for IdentityCert {
    type Err = CertError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (b32, mnem) = s.split_once('_').unwrap_or((s, ""));
        let (hrp, encoded, variant) = bech32::decode(b32)?;

        if hrp != "crt" {
            return Err(CertError::InvalidHrp(hrp, "crt"));
        }

        if variant != bech32::Variant::Bech32m {
            return Err(CertError::InvalidVariant);
        }

        let data = Vec::<u8>::from_base32(&encoded)?;

        let cert = Self::strict_deserialize(data)?;

        let nym = cert.nym();
        if !mnem.is_empty() && cert.nym() != mnem {
            return Err(CertError::InvalidMnemonic(nym));
        }

        Ok(cert)
    }
}

impl From<secp256k1::KeyPair> for IdentityCert {
    fn from(pair: secp256k1::KeyPair) -> Self {
        let pubkey = pair.x_only_public_key().0.serialize();
        let msg = secp256k1::Message::from_hashed_data::<sha256::Hash>(&pubkey);
        let sig = pair.sign_schnorr(msg);
        IdentityCert {
            algo: EcAlgo::Bip340,
            pubkey: Box::from(&pubkey[..]),
            sig: Box::from(&sig[..]),
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct SigCert {
    hash: HashAlgo,
    curve: EcAlgo,
    sig: Box<[u8]>,
}

impl SigCert {
    pub fn bip340_sha256d(
        sk: secp256k1::SecretKey,
        msg: impl AsRef<[u8]>,
    ) -> Self {
        let pair = secp256k1::KeyPair::from_secret_key(&SECP256K1, &sk);
        let sig = pair.sign_schnorr(
            Message::from_hashed_data::<sha256d::Hash>(msg.as_ref()),
        );
        SigCert {
            hash: HashAlgo::Sha256d,
            curve: EcAlgo::Bip340,
            sig: Box::from(&sig[..]),
        }
    }
}

impl StrictEncode for SigCert {
    fn strict_encode<E: Write>(
        &self,
        mut e: E,
    ) -> Result<usize, strict_encoding::Error> {
        let mut len = self.hash.strict_encode(&mut e)?;
        len += self.curve.strict_encode(&mut e)?;
        e.write_all(&self.sig)?;
        Ok(len + self.curve.sig_len())
    }
}

impl StrictDecode for SigCert {
    fn strict_decode<D: Read>(
        mut d: D,
    ) -> Result<Self, strict_encoding::Error> {
        let hash = HashAlgo::strict_decode(&mut d)?;
        let curve = EcAlgo::strict_decode(&mut d)?;

        let mut sig = vec![0u8; curve.sig_len()];
        d.read_exact(&mut sig)?;

        Ok(Self {
            hash,
            curve,
            sig: Box::from(sig),
        })
    }
}

impl Debug for SigCert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        writeln!(f, "dig   {}", self.hash)?;
        writeln!(f, "crv   {}", self.curve)?;
        writeln!(f, "sig   {}", bin_fmt(&self.sig))?;

        Ok(())
    }
}

impl Display for SigCert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let data = self
            .strict_serialize()
            .expect("strict encoding of signature");
        let s =
            bech32::encode("sig", data.to_base32(), bech32::Variant::Bech32m)
                .expect("bech32 encoding of signature");

        f.write_str(&s)
    }
}

impl FromStr for SigCert {
    type Err = CertError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (hrp, encoded, variant) = bech32::decode(s)?;

        if hrp != "sig" {
            return Err(CertError::InvalidHrp(hrp, "sig"));
        }

        if variant != bech32::Variant::Bech32m {
            return Err(CertError::InvalidVariant);
        }

        let data = Vec::<u8>::from_base32(&encoded)?;
        Self::strict_deserialize(data).map_err(CertError::from)
    }
}

fn bin_fmt(v: &[u8]) -> String {
    v.to_hex()
        .chars()
        .enumerate()
        .flat_map(|(i, c)| {
            match i {
                0 => None,
                i if i % (4 * 16) == 0 => Some('\n'),
                i if i % 4 == 0 => Some(' '),
                _ => None,
            }
            .into_iter()
            .chain(std::iter::once(c))
        })
        .collect::<String>()
        .replace('\n', "\n      ")
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use secp256k1::SECP256K1;

    use crate::{IdentityCert, SigCert};

    fn cert() -> IdentityCert {
        IdentityCert::from_str("crt1q9umuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqte3fc3pu8qq6p0qx48fjttj7ecfcemry5r7yqlnfna6qhf4s46r2aw68wqc9spn4a465x54zy03gleun58fcz3tpxhqcg5nv4ssgyeysxq8t50zt_venice_vega_balloon").unwrap()
    }

    fn sig() -> SigCert {
        SigCert::from_str("sig1qgqm0d5l8sjas4v2vk3tzqc5m2ltpkv208uf2chyh3fqmhwq3rdnu3ve0gkytrl7wl68075zxxukq9ff6gmd38w7hmtdas089jefkf2rsyasksse").unwrap()
    }

    #[test]
    fn cert_create() {
        let pair = secp256k1::KeyPair::from_seckey_slice(
            &SECP256K1,
            &secp256k1::ONE_KEY[..],
        )
        .unwrap();
        let _ = IdentityCert::from(pair);
    }

    #[test]
    fn cert_display() {
        let cert = cert();

        assert_eq!(cert.nym(), "venice_vega_balloon");
        assert_eq!(cert.fingerprint(), "8t50zt");

        assert_eq!(format!("{}", cert), "crt1q9umuen7l8wthtz45p3ftn58pvrs9xlumvkuu2xet8egzkcklqte3fc3pu8qq6p0qx48fjttj7ecfcemry5r7yqlnfna6qhf4s46r2aw68wqc9spn4a465x54zy03gleun58fcz3tpxhqcg5nv4ssgyeysxq8t50zt_venice_vega_balloon");
        assert_eq!(format!("{:#}", cert), "8t50zt_venice_vega_balloon");
        assert_eq!(format!("{:?}", cert), "\
nym   venice_vega_balloon
fgp   8t50zt
crv   bip340
idk   79be 667e f9dc bbac 55a0 6295 ce87 0b07 029b fcdb 2dce 28d9 59f2 815b 16f8 1798
sig   a711 0f0e 0068 2f01 aa74 c96b 97b3 84e3 3b19 283f 101f 9a67 dd02 e9ac 2ba1 abae
      d1dc 0c16 019d 7b5d 50d4 a888 f8a3 f9e4 e874 e051 584d 7061 149b 2b08 2099 240c
");
    }

    #[test]
    fn sig_create() {
        let pair = secp256k1::KeyPair::from_seckey_slice(
            &SECP256K1,
            &secp256k1::ONE_KEY[..],
        )
        .unwrap();
        SigCert::bip340_sha256d(pair.secret_key(), "");
    }

    #[test]
    fn sig_display() {
        let sig = sig();
        assert_eq!(format!("{}", sig), "sig1qgqm0d5l8sjas4v2vk3tzqc5m2ltpkv208uf2chyh3fqmhwq3rdnu3ve0gkytrl7wl68075zxxukq9ff6gmd38w7hmtdas089jefkf2rsyasksse");
        assert_eq!(format!("{:#}", sig), "sig1qgqm0d5l8sjas4v2vk3tzqc5m2ltpkv208uf2chyh3fqmhwq3rdnu3ve0gkytrl7wl68075zxxukq9ff6gmd38w7hmtdas089jefkf2rsyasksse");
        assert_eq!(format!("{:?}", sig), "\
dig   sha256d
crv   bip340
sig   b7b6 9f3c 25d8 558a 65a2 b103 14da beb0 d98a 79f8 9562 e4bc 520d ddc0 88db 3e45
      997a 2c45 8ffe 77f4 77fa 8231 b960 1529 d236 d89d debe d6de c1e7 2cb2 9b25 4381
");
    }
}

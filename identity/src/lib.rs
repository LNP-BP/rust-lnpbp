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

use std::fmt::{self, Display, Formatter};
use std::io::Write;
use bech32::ToBase32;
use bitcoin_hashes::sha256;
use strict_encoding::{Error, StrictEncode};

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum Algo {
    #[display("secp256k1-{0}")]
    Secp256k1(EcSigs),

    #[display("edwards25519-{0}")]
    Edwards25519(TwistedSigs),
}

impl Algo {
    pub fn len(self) -> u8 {
        let inner_len = match self {
            Self::Secp256k1(inner) => inner.len(),
            Self::Edwards25519(inner) => inner.len(),
        };
        inner_len + 1
    }

    pub fn encode(self) -> [u8; 2] {
        match self {
            Self::Secp256k1(inner) => [1, inner.encode()],
            Self::Edwards25519(inner) => [2, inner.encode()],
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum EcSigs {
    #[display("bip340-{0}")]
    Bip340(Bip340Comp)
}

impl EcSigs {
    pub fn len(self) -> u8 {
        let inner_len = match self {
            Self::Bip340(inner) => inner.len(),
        };
        inner_len + 1
    }

    pub fn encode(self) -> u8 {
        match self {
            Self::Bip340(inner) => 0x1 << 4 | inner.encode(),
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum TwistedSigs {
    #[display("ed-{0}")]
    Ed(EdComp)
}

impl TwistedSigs {
    pub fn len(self) -> u8 {
        let inner_len = match self {
            Self::Ed(inner) => inner.len(),
        };
        inner_len + 1
    }

    pub fn encode(self) -> u8 {
        match self {
            Self::Ed(inner) => 0x1 << 4 | inner.encode(),
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum Bip340Comp {
    #[display("xonly")]
    XOnly
}

impl Bip340Comp {
    pub fn len(self) -> u8 {
        match self {
            Self::XOnly => 32 + 64,
        }
    }

    pub fn encode(self) -> u8 {
        match self {
            Self::XOnly => 0x1,
        }
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
pub enum EdComp {
    #[display("uncomp")]
    Uncompressed
}

impl EdComp {
    pub fn len(self) -> u8 {
        match self {
            Self::Uncompressed => 32 + 64,
        }
    }

    pub fn encode(self) -> u8 {
        match self {
            Self::Uncompressed => 0x1,
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Certificate {
    algo: Algo,
    pubkey: Box<[u8]>,
    sig: Box<[u8]>
}

impl StrictEncode for Certificate {
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.algo.encode())?;
        e.write_all(&self.pubkey)?;
        e.write_all(&self.sig)?;
        Ok(self.algo.len() as usize)
    }
}

impl Display for Certificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let data = self.strict_serialize()
            .expect("strict encoding of certificate");
        let s = bech32::encode("crt", data.to_base32(), bech32::Variant::Bech32m)
            .expect("bech32 encoding of certificate");
        f.write_str(&s)?;
        f.write_str("_")?;

        let mut mnemonic = Vec::with_capacity(64);
        let mut crc32data = Vec::with_capacity(self.algo.len() as usize);
        crc32data.extend(self.algo.encode());
        crc32data.extend(&*self.pubkey);
        let crc32 = crc32fast::hash(&crc32data);
        mnemonic::encode(crc32.to_be_bytes(), &mut mnemonic).expect("mnemonic encoding");
        let mnemonic = String::from_utf8(mnemonic).expect("mnemonic library error");
        f.write_str(&mnemonic.replace('-', "_"))
    }
}

impl From<secp256k1::KeyPair> for Certificate {
    fn from(pair: secp256k1::KeyPair) -> Self {
        let pubkey = pair.x_only_public_key().0.serialize();
        let msg = secp256k1::Message::from_hashed_data::<sha256::Hash>(&pubkey);
        let sig = pair.sign_schnorr(msg);
        Certificate {
            algo: Algo::Secp256k1(EcSigs::Bip340(Bip340Comp::XOnly)),
            pubkey: Box::from(&pubkey[..]),
            sig: Box::from(&sig[..])
        }
    }
}

#[cfg(test)]
mod test {
    use secp256k1::{rand, SECP256K1};
    use crate::Certificate;

    #[test]
    fn test() {
        let pair = secp256k1::KeyPair::new(&SECP256K1, &mut rand::thread_rng());
        let cert = Certificate::from(pair);
        println!("{}", cert);
    }
}

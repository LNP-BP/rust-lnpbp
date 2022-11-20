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
use std::io::Write;
use amplify::hex::ToHex;
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

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct Certificate {
    algo: Algo,
    pubkey: Box<[u8]>,
    sig: Box<[u8]>
}

impl Certificate {
    pub fn fingerprint(&self) -> String {
        format!("{:#}", self)
    }
}

impl StrictEncode for Certificate {
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.algo.encode())?;
        e.write_all(&self.pubkey)?;
        e.write_all(&self.sig)?;
        Ok(self.algo.len() as usize)
    }
}

impl Debug for Certificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        fn char4ws(v: &[u8]) -> String {
            v.to_hex()
                .chars()
                .enumerate()
                .flat_map(|(i, c)| {
                    if i != 0 && i % 4 == 0 {
                        Some(' ')
                    } else {
                        None
                    }
                        .into_iter()
                        .chain(std::iter::once(c))
                })
                .collect::<String>()
        }

        writeln!(f, "fgp   {}", self.fingerprint())?;
        writeln!(f, "alg   {}", self.algo)?;
        writeln!(f, "idk   {}", char4ws(&self.pubkey))?;
        writeln!(f, "sig   {}", char4ws(&self.sig))?;

        Ok(())
    }
}

impl Display for Certificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let data = self.strict_serialize()
            .expect("strict encoding of certificate");
        let s = bech32::encode("crt", data.to_base32(), bech32::Variant::Bech32m)
            .expect("bech32 encoding of certificate");

        if f.alternate() {
            f.write_str(&s[s.len() - 6..])?;
        } else {
            f.write_str(&s)?;
        }
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
    use secp256k1::{SECP256K1};
    use crate::Certificate;

    #[test]
    fn test() {
        let pair = secp256k1::KeyPair::from_seckey_slice(&SECP256K1, &secp256k1::ONE_KEY[..]).unwrap();
        let cert = Certificate::from(pair);
        /*
        assert_eq!(format!("{}", cert), "crt1qyghn0nx0muaewav2ksx99wwsu9swq5mlndjmn3gm9vl9q2mzmup0xrdgswg9ate53t5hvppkl2xjem0y2sg5r738s7jqdlk4jd49v72c4t0f7e3a2yup6xhldv4c35hf5ncvas3r8ulwf4xx3ynqy3vwsc37avgyrl_game_accent_candle");
        assert_eq!(format!("{:#}", cert), "8wdwat_game_accent_candle");
        assert_eq!(format!("{:?}", cert), "\
        fgp   gsjc3l_game_accent_candle
        alg   secp256k1-bip340-xonly
        idk   79be 667e f9dc bbac 55a0 6295 ce87 0b07 029b fcdb 2dce 28d9 59f2 815b 16f8 1798
        sig   e4b4 1a37 317e 1de6 bd00 ec17 fcb6 940a cda0 5a21 586c 3134 b793 c0c2 d89f 8e09 2efc c7af 9829 78a0 9f19 8040 e680 66e2 859c 4a8e 8036 2d4e e659 5333 388e 6949
        ");
         */
    }
}

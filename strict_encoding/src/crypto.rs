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

use std::io;

#[cfg(feature = "ed25519-dalek")]
use ed25519_dalek::ed25519::signature::Signature;

use crate::{Error, StrictDecode, StrictEncode};

#[cfg(feature = "ed25519-dalek")]
impl StrictEncode for ed25519_dalek::PublicKey {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.as_bytes()[..])?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictDecode for ed25519_dalek::PublicKey {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        d.read_exact(&mut buf)?;
        Ok(Self::from_bytes(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "invalid Curve25519 public key data".to_string(),
            )
        })?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictEncode for ed25519_dalek::Signature {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.as_bytes())?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictDecode for ed25519_dalek::Signature {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        d.read_exact(&mut buf)?;
        Ok(Self::from_bytes(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "invalid Ed25519 signature data".to_string(),
            )
        })?)
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictEncode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self[..])?)
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictDecode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1zkp::constants::PEDERSEN_COMMITMENT_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_vec(buf.to_vec()))
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictEncode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.proof[..self.plen].as_ref().strict_encode(e)
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictDecode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        use secp256k1zkp::constants::MAX_PROOF_SIZE;
        let data = Vec::<u8>::strict_decode(d)?;
        match data.len() {
            len if len < MAX_PROOF_SIZE => {
                let mut buf = [0; MAX_PROOF_SIZE];
                buf[..len].copy_from_slice(&data);
                Ok(Self {
                    proof: buf,
                    plen: len,
                })
            }
            invalid_len => Err(Error::DataIntegrityError(format!(
                "Wrong bulletproof data size: expected no more than {}, got {}",
                MAX_PROOF_SIZE, invalid_len
            ))),
        }
    }
}

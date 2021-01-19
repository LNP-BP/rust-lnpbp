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

//! Taking implementation of little-endian integer encoding

use bitcoin::util::uint::{Uint128, Uint256};
#[cfg(feature = "chrono")]
use chrono::NaiveDateTime;
use core::time::Duration;
use std::io;

use super::{strategies, Error, Strategy, StrictDecode, StrictEncode};

impl Strategy for u8 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for u16 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for u32 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for u64 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for Uint128 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for Uint256 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for i8 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for i16 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for i32 {
    type Strategy = strategies::BitcoinConsensus;
}
impl Strategy for i64 {
    type Strategy = strategies::BitcoinConsensus;
}

impl StrictEncode for bool {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        (*self as u8).strict_encode(&mut e)
    }
}

impl StrictDecode for bool {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        match u8::strict_decode(&mut d)? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(Error::ValueOutOfRange("boolean", 0..1, v as u128)),
        }
    }
}

/*
impl StrictEncode for u128 {
    type Error = Error;
    #[inline]
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, Error> {
        e.write_u128(*self)?;
        Ok(core::mem::size_of::<u128>())
    }
}

impl StrictDecode for u128 {
    type Error = Error;
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
        Ok(d.read_u128()?)
    }
}

impl StrictEncode for i128 {
    type Error = Error;
    #[inline]
    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, Error> {
        e.write_i128(*self)?;
        Ok(core::mem::size_of::<i128>())
    }
}

impl StrictDecode for i128 {
    type Error = Error;
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Self::Error> {
        Ok(d.read_i128()?)
    }
}*/

impl StrictEncode for usize {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        if *self > core::u16::MAX as usize {
            Err(Error::ExceedMaxItems(*self))?;
        }
        let size = *self as u16;
        size.strict_encode(&mut e)
    }
}

impl StrictDecode for usize {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        u16::strict_decode(&mut d).map(|val| val as usize)
    }
}

impl StrictEncode for f32 {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_le_bytes())?;
        Ok(4)
    }
}

impl StrictDecode for f32 {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf: [u8; 4] = [0; 4];
        d.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl StrictEncode for f64 {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_le_bytes())?;
        Ok(8)
    }
}

impl StrictDecode for f64 {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf: [u8; 8] = [0; 8];
        d.read_exact(&mut buf)?;
        Ok(Self::from_le_bytes(buf))
    }
}

impl StrictEncode for Duration {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        (self.as_secs(), self.subsec_nanos()).strict_encode(e)
    }
}

impl StrictDecode for Duration {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self::new(
            u64::strict_decode(&mut d)?,
            u32::strict_decode(&mut d)?,
        ))
    }
}

#[cfg(feature = "chrono")]
impl StrictEncode for NaiveDateTime {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.timestamp().strict_encode(e)
    }
}

#[cfg(feature = "chrono")]
impl StrictDecode for NaiveDateTime {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_timestamp(i64::strict_decode(d)?, 0))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::strict_serialize;

    /// Checking that byte encoding and decoding works correctly for the most
    /// common marginal and middle-probability cases
    #[test]
    fn test_u8_encode() {
        let zero: u8 = 0;
        let one: u8 = 1;
        let thirteen: u8 = 13;
        let confusing: u8 = 0xEF;
        let nearly_full: u8 = 0xFE;
        let full: u8 = 0xFF;

        let byte_0 = &[0u8][..];
        let byte_1 = &[1u8][..];
        let byte_13 = &[13u8][..];
        let byte_ef = &[0xEFu8][..];
        let byte_fe = &[0xFEu8][..];
        let byte_ff = &[0xFFu8][..];

        assert_eq!(strict_serialize(&zero).unwrap(), byte_0);
        assert_eq!(strict_serialize(&one).unwrap(), byte_1);
        assert_eq!(strict_serialize(&thirteen).unwrap(), byte_13);
        assert_eq!(strict_serialize(&confusing).unwrap(), byte_ef);
        assert_eq!(strict_serialize(&nearly_full).unwrap(), byte_fe);
        assert_eq!(strict_serialize(&full).unwrap(), byte_ff);

        assert_eq!(u8::strict_decode(byte_0).unwrap(), zero);
        assert_eq!(u8::strict_decode(byte_1).unwrap(), one);
        assert_eq!(u8::strict_decode(byte_13).unwrap(), thirteen);
        assert_eq!(u8::strict_decode(byte_ef).unwrap(), confusing);
        assert_eq!(u8::strict_decode(byte_fe).unwrap(), nearly_full);
        assert_eq!(u8::strict_decode(byte_ff).unwrap(), full);
    }
}

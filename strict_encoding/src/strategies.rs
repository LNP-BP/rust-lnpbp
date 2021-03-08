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

//! Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>

use amplify::Wrapper;
use std::io;

use super::net;
use super::{Error, StrictDecode, StrictEncode};

// Defining strategies:

pub struct HashFixedBytes;
pub struct BitcoinConsensus;
pub struct Wrapped;
pub struct UsingUniformAddr;

pub trait Strategy {
    type Strategy;
}

impl<T> StrictEncode for T
where
    T: Strategy + Clone,
    amplify::Holder<T, <T as Strategy>::Strategy>: StrictEncode,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        amplify::Holder::new(self.clone()).strict_encode(e)
    }
}

impl<T> StrictDecode for T
where
    T: Strategy,
    amplify::Holder<T, <T as Strategy>::Strategy>: StrictDecode,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(amplify::Holder::strict_decode(d)?.into_inner())
    }
}

impl<T> StrictEncode for amplify::Holder<T, Wrapped>
where
    T: Wrapper,
    T::Inner: StrictEncode,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        Ok(self.as_inner().as_inner().strict_encode(e)?)
    }
}

impl<T> StrictDecode for amplify::Holder<T, Wrapped>
where
    T: Wrapper,
    T::Inner: StrictDecode,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(T::from_inner(T::Inner::strict_decode(d)?)))
    }
}

impl<T> StrictEncode for amplify::Holder<T, HashFixedBytes>
where
    T: bitcoin::hashes::Hash,
{
    // TODO: Verify byte order for hash encodings
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.as_inner()[..])?;
        Ok(T::LEN)
    }
}

impl<T> StrictDecode for amplify::Holder<T, HashFixedBytes>
where
    T: bitcoin::hashes::Hash,
{
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = vec![0u8; T::LEN];
        d.read_exact(&mut buf)?;
        Ok(Self::new(T::from_slice(&buf)?))
    }
}

impl<T> StrictEncode for amplify::Holder<T, BitcoinConsensus>
where
    T: bitcoin::consensus::Encodable,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().consensus_encode(e).map_err(Error::from)
    }
}

impl<T> StrictDecode for amplify::Holder<T, BitcoinConsensus>
where
    T: bitcoin::consensus::Decodable,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(T::consensus_decode(d).map_err(Error::from)?))
    }
}

impl<T> StrictEncode for amplify::Holder<T, UsingUniformAddr>
where
    T: net::Uniform,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().to_raw_uniform().strict_encode(e)
    }
}

impl<T> StrictDecode for amplify::Holder<T, UsingUniformAddr>
where
    T: net::Uniform,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(
            T::from_raw_uniform_addr(net::RawUniformAddr::strict_decode(d)?)
                .map_err(|err| Error::DataIntegrityError(err.to_string()))?,
        ))
    }
}

impl From<bitcoin::hashes::Error> for Error {
    #[inline]
    fn from(_: bitcoin::hashes::Error) -> Self {
        Error::DataIntegrityError("Incorrect hash length".to_string())
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    #[inline]
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        if let bitcoin::consensus::encode::Error::Io(err) = e {
            err.into()
        } else {
            Error::DataIntegrityError(e.to_string())
        }
    }
}

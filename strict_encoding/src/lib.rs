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

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
)]

#[cfg(feature = "derive")]
#[allow(unused_imports)]
#[macro_use]
extern crate strict_encoding_derive as derive;
pub use derive::{StrictDecode, StrictEncode};

#[allow(unused_imports)]
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_derive;

#[macro_use]
mod macros;
#[macro_use]
pub mod test_helpers;

mod bitcoin;
mod byte_str;
mod collections;
#[cfg(feature = "crypto")]
mod crypto;
#[cfg(feature = "miniscript")]
mod miniscript;
mod primitives;
pub mod strategies;

pub use strategies::Strategy;

/// Re-exporting extended read and write functions from bitcoin consensus
/// module so others may use semantic convenience
/// `strict_encode::ReadExt`
pub use ::bitcoin::consensus::encode::{ReadExt, WriteExt};

use amplify::IoError;
use core::ops::Range;
use std::fmt;
use std::io;

/// Binary encoding according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications;
/// in some circumstances may be used for commitment procedures; however it must
/// be kept in mind that sometime commitment may follow "fold" scheme
/// (Merklization or nested commitments) and in such cases this trait can't be
/// applied. It is generally recommended for consensus-related commitments to
/// utilize [CommitVerify], [TryCommitVerify] and [EmbedCommitVerify] traits  
/// from [paradigms::commit_verify] module.
pub trait StrictEncode {
    /// Encode with the given [std::io::Writer] instance; must return result
    /// with either amount of bytes encoded – or implementation-specific
    /// error type.
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error>;

    /// Serializes data as a byte array using [`strict_encode()`] function
    fn strict_serialize(&self) -> Result<Vec<u8>, Error> {
        let mut e = vec![];
        let _ = self.strict_encode(&mut e)?;
        Ok(e)
    }
}

/// Binary decoding according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications.
/// MUST NOT be used for commitment verification: even if the commit procedure
/// uses [StrictEncode], the actual commit verification MUST be done with
/// [CommitVerify], [TryCommitVerify] and [EmbedCommitVerify] traits, which,
/// instead of deserializing (nonce operation for commitments) repeat the
/// commitment procedure for the revealed message and verify it against the
/// provided commitment.
pub trait StrictDecode: Sized {
    /// Decode with the given [std::io::Reader] instance; must either
    /// construct an instance or return implementation-specific error type.
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error>;

    /// Tries to deserialize byte array into the current type using
    /// [`strict_decode()`]
    fn strict_deserialize(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::strict_decode(data.as_ref())
    }
}

/// Convenience method for strict encoding of data structures implementing
/// [StrictEncode] into a byte vector.
pub fn strict_serialize<T>(data: &T) -> Result<Vec<u8>, Error>
where
    T: StrictEncode,
{
    let mut encoder = io::Cursor::new(vec![]);
    data.strict_encode(&mut encoder)?;
    Ok(encoder.into_inner())
}

/// Convenience method for strict decoding of data structures implementing
/// [StrictDecode] from any byt data source.
pub fn strict_deserialize<T>(data: &impl AsRef<[u8]>) -> Result<T, Error>
where
    T: StrictDecode,
{
    let mut decoder = io::Cursor::new(data);
    let rv = T::strict_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.as_ref().len() {
        Ok(rv)
    } else {
        Err(Error::DataNotEntirelyConsumed)?
    }
}

/// Possible errors during strict encoding and decoding process
#[derive(Clone, PartialEq, Eq, Hash, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// I/O error during data strict encoding: {0}
    #[from(io::Error)]
    #[from(io::ErrorKind)]
    Io(IoError),

    /// String data are not in valid UTF-8 encoding
    #[from(std::str::Utf8Error)]
    #[from(std::string::FromUtf8Error)]
    Utf8Conversion,

    /// A collection (slice, vector or other type) has more items ({0}) than
    /// 2^16 (i.e. maximum value which may be held by `u16` `size`
    /// representation according to the LNPBP-6 spec)
    ExceedMaxItems(usize),

    /// In terms of strict encoding, we interpret `Option` as a zero-length
    /// `Vec` (for `Optional::None`) or single-item `Vec` (for
    /// `Optional::Some`). For decoding an attempt to read `Option` from a
    /// encoded non-0 or non-1 length Vec will result in
    /// `Error::WrongOptionalEncoding`.
    #[display(
        "Invalid value {0} met as an optional type byte, which must be \
               equal to either 0 (no value) or 1"
    )]
    WrongOptionalEncoding(u8),

    /// Enums are encoded as a `u8`-based values; the provided enum `{0}` has
    /// underlying primitive type that does not fit into `u8` value
    EnumValueOverflow(String),

    /// An unsupported value `{0}` for enum `{0}` encountered during decode
    /// operation
    EnumValueNotKnown(String, u8),

    /// The data are correct, however their structure indicate that they were
    /// created with the future software version which has functional absent in
    /// the current implementation.
    /// More details from error source: {0}
    UnsupportedDataStructure(&'static str),

    /// Decoding resulted in value `{2}` for type `{0}` that exceeds the
    /// supported range {1:#?}
    ValueOutOfRange(&'static str, Range<u128>, u128),

    /// A repeated value for `{0}` found during set collection deserialization
    RepeatedValue(String),

    /// Returned by the convenience method [`strict_decode()`] if not all
    /// provided data were consumed during decoding process
    #[display(
        "Data were not consumed entirely during strict decoding procedure"
    )]
    DataNotEntirelyConsumed,

    /// Data integrity problem during strict decoding operation: {0}
    DataIntegrityError(String),
}

impl From<Error> for fmt::Error {
    #[inline]
    fn from(_: Error) -> Self {
        fmt::Error
    }
}

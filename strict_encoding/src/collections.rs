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

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;
use std::io;

use crate::{Error, StrictDecode, StrictEncode};

/// In terms of strict encoding, `Option` (optional values) are  
/// represented by a *significator byte*, which MUST be either `0` (for no
/// value present) or `1`, followed by the value strict encoding.
impl<T> StrictEncode for Option<T>
where
    T: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            None => strict_encode_list!(e; 0u8),
            Some(val) => strict_encode_list!(e; 1u8, val),
        })
    }
}

/// In terms of strict encoding, `Option` (optional values) are  
/// represented by a *significator byte*, which MUST be either `0` (for no
/// value present) or `1`, followed by the value strict encoding.
/// For decoding an attempt to read `Option` from a encoded non-0
/// or non-1 length Vec will result in `Error::WrongOptionalEncoding`.
impl<T> StrictDecode for Option<T>
where
    T: StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = u8::strict_decode(&mut d)?;
        match len {
            0 => Ok(None),
            1 => Ok(Some(T::strict_decode(&mut d)?)),
            invalid => Err(Error::WrongOptionalEncoding(invalid))?,
        }
    }
}

/// In terms of strict encoding, `Vec` is stored in form of
/// usize-encoded length (see `StrictEncode` implementation for `usize`
/// type for encoding platform-independent constant-length
/// encoding rules) followed by a consequently-encoded vec items,
/// according to their type.
impl<T> StrictEncode for Vec<T>
where
    T: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let mut encoded = len.strict_encode(&mut e)?;
        for item in self {
            encoded += item.strict_encode(&mut e)?;
        }
        Ok(encoded)
    }
}

/// In terms of strict encoding, `Vec` is stored in form of
/// usize-encoded length (see `StrictEncode` implementation for `usize`
/// type for encoding platform-independent constant-length
/// encoding rules) followed by a consequently-encoded vec items,
/// according to their type.
///
/// An attempt to encode `Vec` with more items than can fit in `usize`
/// encoding rules will result in `Error::ExceedMaxItems`.
impl<T> StrictDecode for Vec<T>
where
    T: StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::strict_decode(&mut d)?;
        let mut data = Vec::<T>::with_capacity(len as usize);
        for _ in 0..len {
            data.push(T::strict_decode(&mut d)?);
        }
        Ok(data)
    }
}

/// Strict encoding for a unique value collection represented by a rust
/// `HashSet` type is performed in the same way as `Vec` encoding.
/// NB: Array members must are ordered with the sort operation, so type
/// `T` must implement `Ord` trait in such a way that it produces
/// deterministically-sorted result
impl<T> StrictEncode for HashSet<T>
where
    T: StrictEncode + Eq + Ord + Hash + Debug,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let mut encoded = len.strict_encode(&mut e)?;
        let mut vec: Vec<&T> = self.iter().collect();
        vec.sort();
        for item in vec {
            encoded += item.strict_encode(&mut e)?;
        }
        Ok(encoded)
    }
}

/// Strict decoding of a unique value collection represented by a rust
/// `HashSet` type is performed alike `Vec` decoding with the only
/// exception: if the repeated value met a [Error::RepeatedValue] is
/// returned.
impl<T> StrictDecode for HashSet<T>
where
    T: StrictDecode + Eq + Ord + Hash + Debug,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::strict_decode(&mut d)?;
        let mut data = HashSet::<T>::with_capacity(len as usize);
        for _ in 0..len {
            let val = T::strict_decode(&mut d)?;
            if data.contains(&val) {
                Err(Error::RepeatedValue(format!("{:?}", val)))?;
            } else {
                data.insert(val);
            }
        }
        Ok(data)
    }
}

/// Strict encoding for a unique value collection represented by a rust
/// `BTreeSet` type is performed in the same way as `Vec` encoding.
/// NB: Array members must are ordered with the sort operation, so type
/// `T` must implement `Ord` trait in such a way that it produces
/// deterministically-sorted result
impl<T> StrictEncode for BTreeSet<T>
where
    T: StrictEncode + Eq + Ord + Debug,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let mut encoded = len.strict_encode(&mut e)?;
        let mut vec: Vec<&T> = self.iter().collect();
        vec.sort();
        for item in vec {
            encoded += item.strict_encode(&mut e)?;
        }
        Ok(encoded)
    }
}

/// Strict decoding of a unique value collection represented by a rust
/// `BTreeSet` type is performed alike `Vec` decoding with the only
/// exception: if the repeated value met a [Error::RepeatedValue] is
/// returned.
impl<T> StrictDecode for BTreeSet<T>
where
    T: StrictDecode + Eq + Ord + Debug,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::strict_decode(&mut d)?;
        let mut data = BTreeSet::<T>::new();
        for _ in 0..len {
            let val = T::strict_decode(&mut d)?;
            if data.contains(&val) {
                Err(Error::RepeatedValue(format!("{:?}", val)))?;
            } else {
                data.insert(val);
            }
        }
        Ok(data)
    }
}

/// LNP/BP library uses `HashMap<usize, T: StrictEncode>`s to encode
/// ordered lists, where the position of the list item must be fixed, since
/// the item is referenced from elsewhere by its index. Thus, the library
/// does not supports and recommends not to support strict encoding
/// of any other `HashMap` variants.
///
/// Strict encoding of the `HashMap<usize, T>` type is performed by
/// converting into a fixed-order `Vec<T>` and serializing it according to
/// the `Vec` strict encoding rules. This operation is internally
/// performed via conversion into `BTreeMap<usize, T: StrictEncode>`.
impl<T> StrictEncode for HashMap<usize, T>
where
    T: StrictEncode + Clone,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let ordered: BTreeMap<usize, T> =
            self.iter().map(|(key, val)| (*key, val.clone())).collect();
        ordered.strict_encode(&mut e)
    }
}

/// LNP/BP library uses `HashMap<usize, T: StrictEncode>`s to encode
/// ordered lists, where the position of the list item must be fixed, since
/// the item is referenced from elsewhere by its index. Thus, the library
/// does not supports and recommends not to support strict encoding
/// of any other `HashMap` variants.
///
/// Strict encoding of the `HashMap<usize, T>` type is performed by
/// converting into a fixed-order `Vec<T>` and serializing it according to
/// the `Vec` strict encoding rules. This operation is internally
/// performed via conversion into `BTreeMap<usize, T: StrictEncode>`.
impl<T> StrictDecode for HashMap<usize, T>
where
    T: StrictDecode + Clone,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let map: HashMap<usize, T> =
            BTreeMap::<usize, T>::strict_decode(&mut d)?
                .iter()
                .map(|(key, val)| (*key, val.clone()))
                .collect();
        Ok(map)
    }
}

/// LNP/BP library uses `BTreeMap<usize, T: StrictEncode>`s to encode
/// ordered lists, where the position of the list item must be fixed, since
/// the item is referenced from elsewhere by its index. Thus, the library
/// does not supports and recommends not to support strict encoding
/// of any other `BTreeMap` variants.
///
/// Strict encoding of the `BTreeMap<usize, T>` type is performed
/// by converting into a fixed-order `Vec<T>` and serializing it according
/// to the `Vec` strict encoding rules.
impl<K, V> StrictEncode for BTreeMap<K, V>
where
    K: StrictEncode + Ord + Clone,
    V: StrictEncode + Clone,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let len = self.len() as usize;
        let encoded = len.strict_encode(&mut e)?;

        self.iter().try_fold(encoded, |mut acc, (key, val)| {
            acc += key.strict_encode(&mut e)?;
            acc += val.strict_encode(&mut e)?;
            Ok(acc)
        })
    }
}

/// LNP/BP library uses `BTreeMap<usize, T: StrictEncode>`s to encode
/// ordered lists, where the position of the list item must be fixed, since
/// the item is referenced from elsewhere by its index. Thus, the library
/// does not supports and recommends not to support strict encoding
/// of any other `BTreeMap` variants.
///
/// Strict encoding of the `BTreeMap<usize, T>` type is performed
/// by converting into a fixed-order `Vec<T>` and serializing it according
/// to the `Vec` strict encoding rules.
impl<K, V> StrictDecode for BTreeMap<K, V>
where
    K: StrictDecode + Ord + Clone,
    V: StrictDecode + Clone,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::strict_decode(&mut d)?;
        let mut map = BTreeMap::<K, V>::new();
        for _ in 0..len {
            let key = K::strict_decode(&mut d)?;
            let val = V::strict_decode(&mut d)?;
            map.insert(key, val);
        }
        Ok(map)
    }
}

/// Two-component tuples are encoded as they were fields in the parent
/// data structure
impl<K, V> StrictEncode for (K, V)
where
    K: StrictEncode + Clone,
    V: StrictEncode + Clone,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(self.0.strict_encode(&mut e)? + self.1.strict_encode(&mut e)?)
    }
}

/// Two-component tuples are decoded as they were fields in the parent
/// data structure
impl<K, V> StrictDecode for (K, V)
where
    K: StrictDecode + Clone,
    V: StrictDecode + Clone,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let a = K::strict_decode(&mut d)?;
        let b = V::strict_decode(&mut d)?;
        Ok((a, b))
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::strict_serialize;

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::None` value MUST
    /// encode as two zero bytes and it MUST be possible to decode optional
    /// of any type from two zero bytes which MUST result in `Option::None`
    /// value.
    #[test]
    fn test_option_encode_none() {
        let o1: Option<u8> = None;
        let o2: Option<u64> = None;

        let two_zero_bytes = &vec![0u8][..];

        assert_eq!(strict_serialize(&o1).unwrap(), two_zero_bytes);
        assert_eq!(strict_serialize(&o2).unwrap(), two_zero_bytes);

        assert_eq!(Option::<u8>::strict_decode(two_zero_bytes).unwrap(), None);
        assert_eq!(Option::<u64>::strict_decode(two_zero_bytes).unwrap(), None);
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::Some<T>` value MUST
    /// encode as a `Vec<T>` structure containing a single item equal to the
    /// `Option::unwrap()` value.
    #[test]
    fn test_option_encode_some() {
        let o1: Option<u8> = Some(0);
        let o2: Option<u8> = Some(13);
        let o3: Option<u8> = Some(0xFF);
        let o4: Option<u64> = Some(13);
        let o5: Option<u64> = Some(0x1FF);
        let o6: Option<u64> = Some(0xFFFFFFFFFFFFFFFF);
        let o7: Option<usize> = Some(13);
        let o8: Option<usize> = Some(0xFFFFFFFFFFFFFFFF);

        let byte_0 = &[1u8, 0u8][..];
        let byte_13 = &[1u8, 13u8][..];
        let byte_255 = &[1u8, 0xFFu8][..];
        let word_13 = &[1u8, 13u8, 0u8][..];
        let qword_13 = &[1u8, 13u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8][..];
        let qword_256 =
            &[1u8, 0xFFu8, 0x01u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8][..];
        let qword_max = &[
            1u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
        ][..];

        assert_eq!(strict_serialize(&o1).unwrap(), byte_0);
        assert_eq!(strict_serialize(&o2).unwrap(), byte_13);
        assert_eq!(strict_serialize(&o3).unwrap(), byte_255);
        assert_eq!(strict_serialize(&o4).unwrap(), qword_13);
        assert_eq!(strict_serialize(&o5).unwrap(), qword_256);
        assert_eq!(strict_serialize(&o6).unwrap(), qword_max);
        assert_eq!(strict_serialize(&o7).unwrap(), word_13);
        assert!(strict_serialize(&o8).err().is_some());

        assert_eq!(Option::<u8>::strict_decode(byte_0).unwrap(), Some(0));
        assert_eq!(Option::<u8>::strict_decode(byte_13).unwrap(), Some(13));
        assert_eq!(Option::<u8>::strict_decode(byte_255).unwrap(), Some(0xFF));
        assert_eq!(Option::<u64>::strict_decode(qword_13).unwrap(), Some(13));
        assert_eq!(
            Option::<u64>::strict_decode(qword_256).unwrap(),
            Some(0x1FF)
        );
        assert_eq!(
            Option::<u64>::strict_decode(qword_max).unwrap(),
            Some(0xFFFFFFFFFFFFFFFF)
        );
        assert_eq!(Option::<usize>::strict_decode(word_13).unwrap(), Some(13));
        assert_eq!(
            Option::<usize>::strict_decode(qword_max).unwrap(),
            Some(0xFFFF)
        );
    }

    /// Test trying decoding of non-zero and non-single item vector structures,
    /// which MUST fail with a specific error.
    #[test]
    fn test_option_decode_vec() {
        assert!(Option::<u8>::strict_decode(&[2u8, 0u8, 0u8, 0u8][..])
            .err()
            .is_some());
        assert!(Option::<u8>::strict_decode(&[3u8, 0u8, 0u8, 0u8][..])
            .err()
            .is_some());
        assert!(Option::<u8>::strict_decode(&[0xFFu8, 0u8, 0u8, 0u8][..])
            .err()
            .is_some());
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// Array of any commitment-serializable type T MUST contain strictly less
    /// than `0x10000` items and must encode as 16-bit little-endian value
    /// corresponding to the number of items followed by a direct encoding
    /// of each of the items.
    #[test]
    fn test_vec_encode() {
        let v1: Vec<u8> = vec![0, 13, 0xFF];
        let v2: Vec<u8> = vec![13];
        let v3: Vec<u64> = vec![0, 13, 13, 0x1FF, 0xFFFFFFFFFFFFFFFF];
        let v4: Vec<u8> =
            (0..0x1FFFF).map(|item| (item % 0xFF) as u8).collect();

        let s1 = &[3u8, 0u8, 0u8, 13u8, 0xFFu8][..];
        let s2 = &[1u8, 0u8, 13u8][..];
        let s3 = &[
            5u8, 0u8, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 13, 0,
            0, 0, 0, 0, 0, 0, 0xFF, 1, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        ][..];

        assert_eq!(strict_serialize(&v1).unwrap(), s1);
        assert_eq!(strict_serialize(&v2).unwrap(), s2);
        assert_eq!(strict_serialize(&v3).unwrap(), s3);
        assert!(strict_serialize(&v4).err().is_some());

        assert_eq!(Vec::<u8>::strict_decode(s1).unwrap(), v1);
        assert_eq!(Vec::<u8>::strict_decode(s2).unwrap(), v2);
        assert_eq!(Vec::<u64>::strict_decode(s3).unwrap(), v3);
    }
}

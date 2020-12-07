// Bitcoin Pro: Professional bitcoin accounts & assets management
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the AGPL License
// along with this software.
// If not, see <https://www.gnu.org/licenses/agpl-3.0-standalone.html>.

use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::iter::FromIterator;
use std::ops::RangeInclusive;

use amplify::Wrapper;
use lnpbp::bitcoin::util::base58;
use lnpbp::bitcoin::util::bip32::{
    self, ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey,
};
use lnpbp::bp::bip32::Decode;
use lnpbp::strict_encoding::{self, StrictDecode, StrictEncode};
use lnpbp::{bitcoin, secp256k1};

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display(TrackingKey::details)]
pub enum TrackingKey {
    SingleKey(secp256k1::PublicKey),
    HdKeySet(DerivationComponents),
}

impl TrackingKey {
    pub fn details(&self) -> String {
        match self {
            TrackingKey::SingleKey(ref pubkey) => pubkey.to_string(),
            TrackingKey::HdKeySet(ref keyset) => keyset.to_string(),
        }
    }

    pub fn count(&self) -> u32 {
        match self {
            TrackingKey::SingleKey(_) => 1,
            TrackingKey::HdKeySet(ref keyset) => keyset.count(),
        }
    }

    pub fn public_key(&self, index: u32) -> bitcoin::PublicKey {
        match self {
            TrackingKey::SingleKey(pk) => bitcoin::PublicKey {
                compressed: true,
                key: *pk,
            },
            TrackingKey::HdKeySet(keyset) => keyset.public_key(index),
        }
    }
}

// TODO: Consider moving the rest of the file to LNP/BP Core library

/// Extended public and private key processing errors
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// Error in BASE58 key encoding
    #[from(base58::Error)]
    Base58,

    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,

    /// A child number was provided ({0}) that was out of range
    InvalidChildNumber(u32),

    /// Invalid child number format.
    InvalidChildNumberFormat,

    /// Invalid derivation path format.
    InvalidDerivationPathFormat,

    /// Unrecognized or unsupported extended key prefix (please check SLIP 32
    /// for possible values)
    UnknownSlip32Prefix,

    /// Failure in tust bitcoin library
    InteralFailure,
}

impl From<bip32::Error> for Error {
    fn from(err: bip32::Error) -> Self {
        match err {
            bip32::Error::CannotDeriveFromHardenedKey => {
                Error::CannotDeriveFromHardenedKey
            }
            bip32::Error::InvalidChildNumber(no) => {
                Error::InvalidChildNumber(no)
            }
            bip32::Error::InvalidChildNumberFormat => {
                Error::InvalidChildNumberFormat
            }
            bip32::Error::InvalidDerivationPathFormat => {
                Error::InvalidDerivationPathFormat
            }
            bip32::Error::Ecdsa(_) | bip32::Error::RngError(_) => {
                Error::InteralFailure
            }
        }
    }
}

pub trait FromSlip32 {
    fn from_slip32_str(s: &str) -> Result<Self, Error>
    where
        Self: Sized;
}

impl FromSlip32 for ExtendedPubKey {
    fn from_slip32_str(s: &str) -> Result<Self, Error> {
        const VERSION_MAGIC_XPUB: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
        const VERSION_MAGIC_YPUB: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];
        const VERSION_MAGIC_ZPUB: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
        const VERSION_MAGIC_YPUB_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb4, 0x3f];
        const VERSION_MAGIC_ZPUB_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7e, 0xd3];

        const VERSION_MAGIC_TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
        const VERSION_MAGIC_UPUB: [u8; 4] = [0x04, 0x4A, 0x52, 0x62];
        const VERSION_MAGIC_VPUB: [u8; 4] = [0x04, 0x5F, 0x1C, 0xF6];
        const VERSION_MAGIC_UPUB_MULTISIG: [u8; 4] = [0x02, 0x42, 0x89, 0xef];
        const VERSION_MAGIC_VPUB_MULTISIG: [u8; 4] = [0x02, 0x57, 0x54, 0x83];

        let mut data = base58::from_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPUB
            | VERSION_MAGIC_YPUB
            | VERSION_MAGIC_ZPUB
            | VERSION_MAGIC_YPUB_MULTISIG
            | VERSION_MAGIC_ZPUB_MULTISIG => VERSION_MAGIC_XPUB,

            VERSION_MAGIC_TPUB
            | VERSION_MAGIC_UPUB
            | VERSION_MAGIC_VPUB
            | VERSION_MAGIC_UPUB_MULTISIG
            | VERSION_MAGIC_VPUB_MULTISIG => VERSION_MAGIC_TPUB,

            _ => Err(Error::UnknownSlip32Prefix)?,
        };
        data[0..4].copy_from_slice(&slice);

        let xpub = ExtendedPubKey::decode(&data)?;

        Ok(xpub)
    }
}

impl FromSlip32 for ExtendedPrivKey {
    fn from_slip32_str(s: &str) -> Result<Self, Error> {
        const VERSION_MAGIC_XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
        const VERSION_MAGIC_YPRV: [u8; 4] = [0x04, 0x9D, 0x78, 0x78];
        const VERSION_MAGIC_ZPRV: [u8; 4] = [0x04, 0xB2, 0x43, 0x0C];
        const VERSION_MAGIC_YPRV_MULTISIG: [u8; 4] = [0x02, 0x95, 0xb0, 0x05];
        const VERSION_MAGIC_ZPRV_MULTISIG: [u8; 4] = [0x02, 0xaa, 0x7a, 0x99];

        const VERSION_MAGIC_TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
        const VERSION_MAGIC_UPRV: [u8; 4] = [0x04, 0x4A, 0x4E, 0x28];
        const VERSION_MAGIC_VPRV: [u8; 4] = [0x04, 0x5F, 0x18, 0xBC];
        const VERSION_MAGIC_UPRV_MULTISIG: [u8; 4] = [0x02, 0x42, 0x85, 0xb5];
        const VERSION_MAGIC_VPRV_MULTISIG: [u8; 4] = [0x02, 0x57, 0x50, 0x48];

        let mut data = base58::from_check(s)?;

        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&data[0..4]);
        let slice = match prefix {
            VERSION_MAGIC_XPRV
            | VERSION_MAGIC_YPRV
            | VERSION_MAGIC_ZPRV
            | VERSION_MAGIC_YPRV_MULTISIG
            | VERSION_MAGIC_ZPRV_MULTISIG => VERSION_MAGIC_XPRV,

            VERSION_MAGIC_TPRV
            | VERSION_MAGIC_UPRV
            | VERSION_MAGIC_VPRV
            | VERSION_MAGIC_UPRV_MULTISIG
            | VERSION_MAGIC_VPRV_MULTISIG => VERSION_MAGIC_TPRV,

            _ => Err(Error::UnknownSlip32Prefix)?,
        };
        data[0..4].copy_from_slice(&slice);

        let xprv = ExtendedPrivKey::decode(&data)?;

        Ok(xprv)
    }
}

pub trait HardenedNormalSplit {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>);
}

impl HardenedNormalSplit for DerivationPath {
    fn hardened_normal_split(&self) -> (DerivationPath, Vec<u32>) {
        let mut terminal_path = vec![];
        let branch_path = self
            .into_iter()
            .rev()
            .by_ref()
            .skip_while(|child| {
                if let ChildNumber::Normal { index } = child {
                    terminal_path.push(index);
                    true
                } else {
                    false
                }
            })
            .cloned()
            .collect::<DerivationPath>();
        let branch_path = branch_path.into_iter().rev().cloned().collect();
        let terminal_path = terminal_path.into_iter().rev().cloned().collect();
        (branch_path, terminal_path)
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    StrictEncode,
    StrictDecode,
)]
// master_xpub/branch_path=branch_xpub/terminal_path/index_ranges
pub struct DerivationComponents {
    pub master_xpub: ExtendedPubKey,
    pub branch_path: DerivationPath,
    pub branch_xpub: ExtendedPubKey,
    pub terminal_path: Vec<u32>,
    pub index_ranges: Option<Vec<DerivationRange>>,
}

impl DerivationComponents {
    pub fn count(&self) -> u32 {
        match self.index_ranges {
            None => u32::MAX,
            Some(ref ranges) => {
                ranges.iter().fold(0u32, |sum, range| sum + range.count())
            }
        }
    }

    pub fn derivation_path(&self) -> DerivationPath {
        self.branch_path.extend(self.terminal_path())
    }

    pub fn terminal_path(&self) -> DerivationPath {
        DerivationPath::from_iter(
            self.terminal_path
                .iter()
                .map(|i| ChildNumber::Normal { index: *i }),
        )
    }

    pub fn index_ranges_string(&self) -> String {
        self.index_ranges
            .as_ref()
            .map(|ranges| {
                ranges
                    .iter()
                    .map(DerivationRange::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default()
    }

    pub fn child(&self, child: u32) -> ExtendedPubKey {
        let derivation = self
            .terminal_path()
            .into_child(ChildNumber::Normal { index: child });
        self.branch_xpub
            .derive_pub(&lnpbp::SECP256K1, &derivation)
            .expect("Non-hardened derivation does not fail")
    }

    pub fn public_key(&self, index: u32) -> bitcoin::PublicKey {
        self.child(index).public_key
    }
}

impl Display for DerivationComponents {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}]{}/",
            self.master_xpub.fingerprint(),
            self.derivation_path()
                .to_string()
                .strip_prefix("m")
                .unwrap_or(&self.derivation_path().to_string())
        )?;
        if let Some(_) = self.index_ranges {
            f.write_str(&self.index_ranges_string())
        } else {
            f.write_str("*")
        }
    }
}

#[derive(Wrapper, Clone, PartialEq, Eq, Hash, Debug, From)]
pub struct DerivationRange(RangeInclusive<u32>);

impl PartialOrd for DerivationRange {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.start().partial_cmp(&other.start()) {
            Some(Ordering::Equal) => self.end().partial_cmp(&other.end()),
            other => other,
        }
    }
}

impl Ord for DerivationRange {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.start().cmp(&other.start()) {
            Ordering::Equal => self.end().cmp(&other.end()),
            other => other,
        }
    }
}

impl DerivationRange {
    pub fn count(&self) -> u32 {
        let inner = self.as_inner();
        inner.end() - inner.start() + 1
    }

    pub fn start(&self) -> u32 {
        *self.as_inner().start()
    }

    pub fn end(&self) -> u32 {
        *self.as_inner().end()
    }
}

impl Display for DerivationRange {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let inner = self.as_inner();
        if inner.start() == inner.end() {
            write!(f, "{}", inner.start())
        } else {
            write!(f, "{}-{}", inner.start(), inner.end())
        }
    }
}

impl StrictEncode for DerivationRange {
    type Error = strict_encoding::Error;

    fn strict_encode<E: io::Write>(
        &self,
        mut e: E,
    ) -> Result<usize, Self::Error> {
        Ok(strict_encode_list!(e; self.start(), self.end()))
    }
}

impl StrictDecode for DerivationRange {
    type Error = strict_encoding::Error;

    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Self::Error> {
        Ok(Self::from_inner(RangeInclusive::new(
            u32::strict_decode(&mut d)?,
            u32::strict_decode(&mut d)?,
        )))
    }
}

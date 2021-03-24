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

use bitcoin::{BlockHash, Txid};
use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
};

/// Short ID derivation errors
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display(Debug)]
pub enum Error {
    /// Invalid block height
    BlockHeightOutOfRange,
    /// Invalid input index
    InputIndexOutOfRange,
    /// Invalid output index
    OutputIndexOutOfRange,
    /// Invalid checksum
    ChecksumOutOfRange,
    /// Require Dimension for this operation
    DimensionRequired,
    /// No Dimension possible for this operation
    NoDimensionIsPossible,
    /// Upgrade not possible
    UpgradeImpossible,
    /// Downgrade not possible
    DowngradeImpossible,
}

/// Checksum for block id data used by the LNPBP-5
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Debug,
    Display,
    From,
)]
#[display("{0}", alt = "block_checksum:{_0:#}")]
#[wrapper(FromStr, LowerHex, UpperHex, Octal)]
pub struct BlockChecksum(u8);

impl From<BlockHash> for BlockChecksum {
    fn from(block_hash: BlockHash) -> Self {
        let mut xor: u8 = 0;
        for byte in block_hash.to_vec() {
            xor ^= byte;
        }
        Self::from(xor)
    }
}

/// Checksum for transaction id data used by the LNPBP-5
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    Debug,
    Display,
    From,
)]
#[display("{0}", alt = "tx_checksum:{_0:#}")]
#[wrapper(FromStr, LowerHex, UpperHex, Octal)]
pub struct TxChecksum(u64);

impl From<Txid> for TxChecksum {
    fn from(txid: Txid) -> Self {
        let mut checksum: u64 = 0;
        for (shift, byte) in txid.to_vec()[0..5].iter().enumerate() {
            checksum ^= (*byte as u64) << (shift * 8);
        }
        Self::from(checksum)
    }
}

/// A Short ID descriptor structure for different items in the Blockchain
/// Not to be confused with transaction output descriptors
#[derive(Copy, Clone, Debug, Display)]
#[display(Debug)]
pub enum Descriptor {
    /// Describes a block
    OnchainBlock {
        /// Block height
        block_height: u32,
        /// Block checksum
        block_checksum: BlockChecksum,
    },
    /// Describes a transaction
    OnchainTransaction {
        /// Block height
        block_height: u32,
        /// Block checksum
        block_checksum: BlockChecksum,
        /// transaction index
        tx_index: u16,
    },
    /// Describes a transaction input
    OnchainTxInput {
        /// Blokc height
        block_height: u32,
        /// Block checksum
        block_checksum: BlockChecksum,
        /// Transaction index
        tx_index: u16,
        /// TxIn index
        input_index: u16,
    },
    /// Describes a transaction output
    OnchainTxOutput {
        /// Block height
        block_height: u32,
        /// Block checksum
        block_checksum: BlockChecksum,
        /// Transaction index
        tx_index: u16,
        /// TxOut index
        output_index: u16,
    },
    /// Describes a off-chain transaction
    OffchainTransaction {
        /// Transaction checksum
        tx_checksum: TxChecksum,
    },

    /// Describes a off-chain transaction input
    OffchainTxInput {
        /// Transaction checksum
        tx_checksum: TxChecksum,
        /// TxIn index
        input_index: u16,
    },

    /// Describes a off-chain transaction output
    OffchainTxOutput {
        /// Transaction checksum
        tx_checksum: TxChecksum,
        /// TxOut index
        output_index: u16,
    },
}

/// Dimensions (Input/Output) for upgrade/downgrade operation of Descriptors
#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display(Debug)]
pub enum Dimension {
    /// Operation towards input
    Input,
    /// Operation towards output
    Output,
}

impl Default for Descriptor {
    fn default() -> Self {
        Descriptor::OnchainBlock {
            block_height: 0,
            block_checksum: BlockChecksum::default(),
        }
    }
}

impl Descriptor {
    /// Check weather a descriptor is valid
    pub fn try_validity(&self) -> Result<(), Error> {
        use Descriptor::*;
        use Error::*;

        match *self {
            OnchainTransaction { block_height, .. }
            | OnchainTxInput { block_height, .. }
            | OnchainTxOutput { block_height, .. }
                if block_height >= (2u32 << 22) =>
            {
                Err(BlockHeightOutOfRange)
            }
            OnchainTxInput { input_index, .. }
            | OffchainTxInput { input_index, .. }
                if input_index + 1 >= (2u16 << 14) =>
            {
                Err(InputIndexOutOfRange)
            }
            OnchainTxOutput { output_index, .. }
            | OffchainTxOutput { output_index, .. }
                if output_index + 1 >= (2u16 << 14) =>
            {
                Err(OutputIndexOutOfRange)
            }
            OffchainTransaction { tx_checksum, .. }
            | OffchainTxInput { tx_checksum, .. }
            | OffchainTxOutput { tx_checksum, .. }
                if *tx_checksum >= (2u64 << 46) =>
            {
                Err(ChecksumOutOfRange)
            }
            _ => Ok(()),
        }
    }

    /// Check if its an onchain descriptor
    pub fn is_onchain(&self) -> bool {
        use Descriptor::*;
        match self {
            OnchainBlock { .. }
            | OnchainTransaction { .. }
            | OnchainTxInput { .. }
            | OnchainTxOutput { .. } => true,
            _ => false,
        }
    }

    /// Check if its an offchain descriptor
    pub fn is_offchain(&self) -> bool {
        !self.is_onchain()
    }

    /// Upgrade Descriptor by given Dimension
    pub fn upgraded(
        &self,
        index: u16,
        dimension: Option<Dimension>,
    ) -> Result<Self, Error> {
        use Descriptor::*;
        use Dimension::*;
        use Error::*;

        match (*self, dimension) {
            (
                OnchainBlock {
                    block_height,
                    block_checksum,
                },
                None,
            ) => Ok(OnchainTransaction {
                block_height,
                block_checksum,
                tx_index: index,
            }),
            (
                OnchainTransaction {
                    block_height,
                    block_checksum,
                    tx_index,
                },
                Some(dim),
            ) if dim == Input => Ok(OnchainTxInput {
                block_height,
                block_checksum,
                tx_index,
                input_index: index,
            }),
            (
                OnchainTransaction {
                    block_height,
                    block_checksum,
                    tx_index,
                },
                Some(dim),
            ) if dim == Output => Ok(OnchainTxOutput {
                block_height,
                block_checksum,
                tx_index,
                output_index: index,
            }),
            (OffchainTransaction { tx_checksum }, Some(dim))
                if dim == Input =>
            {
                Ok(OffchainTxInput {
                    tx_checksum,
                    input_index: index,
                })
            }
            (OffchainTransaction { tx_checksum }, Some(dim))
                if dim == Output =>
            {
                Ok(OffchainTxOutput {
                    tx_checksum,
                    output_index: index,
                })
            }
            (OnchainTransaction { .. }, None)
            | (OffchainTransaction { .. }, None) => Err(DimensionRequired),
            _ => Err(UpgradeImpossible),
        }
    }

    /// Downgrade Descriptor by given Dimension
    pub fn downgraded(self) -> Result<Self, Error> {
        use Descriptor::*;
        use Error::*;

        match self {
            OnchainTransaction {
                block_height,
                block_checksum,
                ..
            } => Ok(OnchainBlock {
                block_height,
                block_checksum,
            }),
            OnchainTxInput {
                block_height,
                block_checksum,
                tx_index,
                ..
            }
            | OnchainTxOutput {
                block_height,
                block_checksum,
                tx_index,
                ..
            } => Ok(OnchainTransaction {
                block_height,
                block_checksum,
                tx_index,
            }),
            OffchainTxInput { tx_checksum, .. }
            | OffchainTxOutput { tx_checksum, .. } => {
                Ok(OffchainTransaction { tx_checksum })
            }
            _ => Err(DowngradeImpossible),
        }
    }

    /// Extract block height from Descriptor
    /// Returns `None` if not applicable
    pub fn get_block_height(&self) -> Option<u32> {
        use Descriptor::*;

        match self {
            OnchainBlock { block_height, .. }
            | OnchainTransaction { block_height, .. }
            | OnchainTxInput { block_height, .. }
            | OnchainTxOutput { block_height, .. } => Some(*block_height),
            _ => None,
        }
    }

    /// Extract Block checksum from descriptor
    /// Returns `None` if not applicable
    pub fn get_block_checksum(&self) -> Option<u8> {
        use Descriptor::*;

        match self {
            OnchainBlock { block_checksum, .. }
            | OnchainTransaction { block_checksum, .. }
            | OnchainTxInput { block_checksum, .. }
            | OnchainTxOutput { block_checksum, .. } => Some(**block_checksum),
            _ => None,
        }
    }

    /// Extract transaction checksum from Descriptor
    /// Returns `None` if not applicable
    pub fn get_tx_checksum(&self) -> Option<u64> {
        use Descriptor::*;

        match self {
            OffchainTransaction { tx_checksum, .. }
            | OffchainTxInput { tx_checksum, .. }
            | OffchainTxOutput { tx_checksum, .. } => Some(**tx_checksum),
            _ => None,
        }
    }

    /// Extract transaction index from descriptor
    /// Returns `None` if not applicable
    pub fn get_tx_index(&self) -> Option<u16> {
        use Descriptor::*;

        match self {
            OnchainTransaction { tx_index, .. }
            | OnchainTxInput { tx_index, .. }
            | OnchainTxOutput { tx_index, .. } => Some(*tx_index),
            _ => None,
        }
    }

    /// Extract Transaction Input index from descriptor
    /// Returns `None` if not applicable
    pub fn get_input_index(&self) -> Option<u16> {
        use Descriptor::*;

        match self {
            OnchainTxInput { input_index, .. }
            | OffchainTxInput { input_index, .. } => Some(*input_index),
            _ => None,
        }
    }

    /// Extract Transaction Output index from Descriptor
    /// Returns `None` if not applicable
    pub fn get_output_index(&self) -> Option<u16> {
        use Descriptor::*;

        match self {
            OnchainTxOutput { output_index, .. }
            | OffchainTxOutput { output_index, .. } => Some(*output_index),
            _ => None,
        }
    }

    /// Convert Descriptor into ShortId
    pub fn try_into_u64(self) -> Result<u64, Error> {
        ShortId::try_from(self).map(ShortId::into_u64)
    }
}

/// ShortId for identifying blockchain items as per LNPBP5
/// https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0005.md
#[derive(
    Copy,
    Clone,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    StrictEncode,
    StrictDecode,
)]
#[display(Debug)]
pub struct ShortId(u64);

impl ShortId {
    /// Offchain ID Flag
    pub const FLAG_OFFCHAIN: u64 = 0x8000_0000_0000_0000;
    /// Mask for Block ID
    pub const MASK_BLOCK: u64 = 0x7FFF_FF00_0000_0000;
    /// Mask for Block Checksum
    pub const MASK_BLOCKCHECK: u64 = 0x0000_00FF_0000_0000;
    /// Mask for TxId
    pub const MASK_TXIDX: u64 = 0x0000_0000_FFFF_0000;
    /// Mask for Tx checksum
    pub const MASK_TXCHECK: u64 = 0x7FFF_FFFF_FFFF_0000;
    /// Input/Output flag
    pub const FLAG_INOUT: u64 = 0x0000_0000_0000_8000;
    /// Mask for Input/Output ID
    pub const MASK_INOUT: u64 = 0x0000_0000_0000_7FFF;

    /// Shift for Blokc ID
    pub const SHIFT_BLOCK: u64 = 40;
    /// Shift for block checksum
    pub const SHIFT_BLOCKCHECK: u64 = 32;
    /// Shift for TxID
    pub const SHIFT_TXIDX: u64 = 16;

    /// Check if ID is onchain
    pub fn is_onchain(&self) -> bool {
        self.0 & Self::FLAG_OFFCHAIN != Self::FLAG_OFFCHAIN
    }

    /// Check if ID is offchain
    pub fn is_offchain(&self) -> bool {
        self.0 & Self::FLAG_OFFCHAIN == Self::FLAG_OFFCHAIN
    }

    /// Get Descriptor from ID
    pub fn get_descriptor(&self) -> Descriptor {
        #[inline]
        fn iconv<T>(val: u64) -> T
        where
            T: TryFrom<u64>,
            <T as TryFrom<u64>>::Error: Debug,
        {
            val.try_into()
                .expect("Conversion from existing ShortId can't fail")
        }

        let index: u16 = iconv(self.0 & Self::MASK_INOUT);

        if self.is_onchain() {
            let block_height: u32 =
                iconv((self.0 & Self::MASK_BLOCK) >> Self::SHIFT_BLOCK);
            let block_checksum = BlockChecksum::from(iconv::<u8>(
                (self.0 & Self::MASK_BLOCKCHECK) >> Self::SHIFT_BLOCKCHECK,
            ));
            if (self.0 & (!Self::MASK_BLOCK)) == 0 {
                return Descriptor::OnchainBlock {
                    block_height,
                    block_checksum,
                };
            }
            let tx_index: u16 =
                iconv((self.0 & Self::MASK_TXIDX) >> Self::SHIFT_TXIDX);
            if (self.0 & (!Self::MASK_INOUT)) == 0 {
                return Descriptor::OnchainTransaction {
                    block_height,
                    block_checksum,
                    tx_index,
                };
            }
            if (self.0 & Self::FLAG_INOUT) == 0 {
                Descriptor::OnchainTxInput {
                    block_height,
                    block_checksum,
                    tx_index,
                    input_index: index - 1,
                }
            } else {
                Descriptor::OnchainTxOutput {
                    block_height,
                    block_checksum,
                    tx_index,
                    output_index: index - 1,
                }
            }
        } else {
            let tx_checksum = TxChecksum::from(
                (self.0 & Self::MASK_TXCHECK) >> Self::SHIFT_TXIDX,
            );
            if (self.0 & (!Self::MASK_INOUT)) == 0 {
                return Descriptor::OffchainTransaction { tx_checksum };
            }
            if (self.0 & Self::FLAG_INOUT) == 0 {
                Descriptor::OffchainTxInput {
                    tx_checksum,
                    input_index: index - 1,
                }
            } else {
                Descriptor::OffchainTxOutput {
                    tx_checksum,
                    output_index: index - 1,
                }
            }
        }
    }

    /// Convert ID to u64
    pub fn into_u64(self) -> u64 {
        self.into()
    }
}

impl From<ShortId> for Descriptor {
    fn from(short_id: ShortId) -> Self {
        short_id.get_descriptor()
    }
}

impl TryFrom<Descriptor> for ShortId {
    type Error = self::Error;

    fn try_from(descriptor: Descriptor) -> Result<Self, Self::Error> {
        use Descriptor::*;

        descriptor.try_validity()?;

        let block_height: u64 = match descriptor {
            OnchainBlock { block_height, .. }
            | OnchainTransaction { block_height, .. }
            | OnchainTxInput { block_height, .. }
            | OnchainTxOutput { block_height, .. } => block_height,
            _ => 0,
        } as u64;
        let block_checksum = *match descriptor {
            OnchainBlock { block_checksum, .. }
            | OnchainTransaction { block_checksum, .. }
            | OnchainTxInput { block_checksum, .. }
            | OnchainTxOutput { block_checksum, .. } => block_checksum,
            _ => BlockChecksum::default(),
        } as u64;
        let tx_index = match descriptor {
            OnchainTransaction { tx_index, .. }
            | OnchainTxInput { tx_index, .. }
            | OnchainTxOutput { tx_index, .. } => tx_index,
            _ => 0,
        } as u64;
        let tx_checksum = match descriptor {
            OffchainTransaction { tx_checksum }
            | OffchainTxInput { tx_checksum, .. }
            | OffchainTxOutput { tx_checksum, .. } => tx_checksum,
            _ => TxChecksum::default(),
        };
        let inout_index: u64 = match descriptor {
            OnchainTxInput { input_index, .. }
            | OffchainTxInput { input_index, .. } => input_index + 1,
            OnchainTxOutput { output_index, .. }
            | OffchainTxOutput { output_index, .. } => output_index + 1,
            _ => 0,
        } as u64;

        let mut short_id = 0u64;
        short_id |= inout_index;
        if descriptor.is_offchain() {
            short_id |= Self::FLAG_OFFCHAIN;
            short_id |=
                (*tx_checksum << Self::SHIFT_TXIDX) & Self::MASK_TXCHECK;
        } else {
            short_id |= (block_height << 40) & Self::MASK_BLOCK;
            short_id |= (block_checksum << Self::SHIFT_BLOCKCHECK)
                & Self::MASK_BLOCKCHECK;
            short_id |= (tx_index << 16) & Self::MASK_TXIDX;
        }

        match descriptor {
            OnchainTxOutput { .. } | OffchainTxOutput { .. } => {
                short_id |= Self::FLAG_INOUT << Self::SHIFT_TXIDX
            }
            _ => (),
        }

        Ok(Self(short_id))
    }
}

impl From<u64> for ShortId {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<ShortId> for u64 {
    fn from(short_id: ShortId) -> Self {
        short_id.0
    }
}

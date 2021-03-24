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

use bitcoin::{OutPoint, Transaction, Txid};

/// Transaction spending status
pub enum SpendingStatus {
    /// Status Unknown
    Unknown,
    /// Status Invalid
    Invalid,
    /// Status Unspent
    Unspent,
    /// Status Spent
    Spent(Option<u32>),
}

/// Trait defining transaction graph related functionalities
pub trait TxGraph {
    /// Error type
    type AccessError: std::error::Error;

    /// Fetch spending status of a transaction
    fn spending_status(
        &self,
        outpoint: &OutPoint,
    ) -> Result<SpendingStatus, Self::AccessError>;

    /// Fetch the spending transaction
    fn fetch_spending_tx(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Transaction, Self::AccessError>;

    /// Create a spending transaction
    fn create_spending_tx(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Transaction, Self::AccessError>;

    /// Fetch the transaction with given TxId
    fn fetch_tx(&self, txid: Txid) -> Result<Transaction, Self::AccessError>;

    /// Apply a transaction as spending
    fn apply_tx(
        &self,
        signed_tx: &Transaction,
    ) -> Result<Transaction, Self::AccessError>;
}

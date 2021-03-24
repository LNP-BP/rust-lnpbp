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

/// Revealed and Concealed Outpoint definition
mod blind;
/// Outpoint related errors
mod error;
/// LNPBP1 structures
pub mod lnpbp1;
/// LNPBP2 structures
pub mod lnpbp2;
/// LNPBP3 structures
pub mod lnpbp3;
/// LNPBP4 structures
pub mod lnpbp4;
/// Transaction graph trait definition
mod tx_graph;
/// Seal definition as TxOut
mod txout_seal;
/// TxOut witness structures
mod txout_witness;

pub use blind::{OutpointHash, OutpointReveal};
pub use error::Error;
pub use tx_graph::{SpendingStatus, TxGraph};
pub use txout_seal::{TxResolve, TxoutSeal};
pub use txout_witness::{InnerWitness, OuterWitness, Witness};

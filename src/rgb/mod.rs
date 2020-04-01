// LNP/BP Rust Library
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


pub mod schema;
pub mod schemata;

pub mod metadata;
pub mod data;
pub mod seal;
pub mod state;
pub mod script;
pub mod transition;

pub mod serialize;
pub mod commit;

pub mod invoice;


pub use schemata::*;

pub use data::Data;
pub use state::State;
pub use metadata::Metadata;
pub use script::Script;
pub use seal::Seal;
pub use transition::Transition;

pub use invoice::Invoice;


hash_newtype!(GenesisId, sha256d::Hash, 32, doc="Hash of genesis state");
hash_newtype!(UTXOSecret, sha256d::Hash, 32, doc="Hash of UTXO pointer mixed with some entropy data");

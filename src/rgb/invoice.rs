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

use crate::bp;

#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display_from(Debug)]
pub struct Invoice {
    pub genesis: GenesisId,
    pub amount: u64,
    pub receiver: Receiver
}


#[derive(Copy, Clone, Debug, Display, PartialEq, Eq)]
#[display_from(Debug)]
pub enum Receiver {
    NewTransaction(bp::invoice::Receiver),
    ExistingUTXO(UTXOSecret),
}

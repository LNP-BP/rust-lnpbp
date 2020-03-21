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

use std::collections::HashMap;
use std::sync::Once;

use bitcoin::secp256k1::PublicKey;
use bitcoin::hashes::sha256;
use bitcoin::Transaction;

pub struct OracleInfo {
    pub pubkey: PublicKey,
    pub r_value: PublicKey,
}

pub struct Offer {
    pub oracle: OracleInfo,
    pub contracts: HashMap<sha256::Hash, bitcoin::Amount>,
    pub total_collateral: bitcoin::Amount,
    pub funding_inputs: Vec<bitcoin::OutPoint>,
}

pub struct Contract {
}

impl Contract {
    pub fn compose_funding_tx(&self) -> Transaction {
        let template = tx_template!{
            version: 1,
            lock_time: 0,
            inputs: [
                (self.funding_inputs => {

                })+
            ]
        };
    }
}

pub struct DLC();

impl DLC {
    fn get_funding_tx() -> &'static Transaction {
        static ONCE: Once = Once::new();
        let mut tx: &'static Option<Transaction> = &None;

        ONCE.call_once(|| {
            tx = Box::leak(Box::new(Some(Transaction {
                version: 1,
                lock_time: 0, // TODO
                input: inputs.iter().map().collect(),
                output: vec![]
            })));
        });
        
        tx.as_ref().expect("This must be always initialized")
    }
}


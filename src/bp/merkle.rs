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

use bitcoin::{
    hashes::{Hash, HashEngine, sha256, sha256d}
};
use crate::csv::Commitment;

hash_newtype!(MerkleNode, sha256d::Hash, 32, doc="A hash of a arbitrary Merkle tree branch or root");
impl_hashencode!(MerkleNode);


pub fn merklize(prefix: &str, data: &[MerkleNode], depth: u16) -> MerkleNode {
    let len = data.len();

    let mut engine = MerkleNode::engine();
    let tag = format!("{}:merkle:{}", prefix, depth);
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    match len {
        0 => {
            0u8.commitment_serialize(&mut engine).unwrap();
        }
        1 => {
            data.first().expect("We know that we have one element").commitment_serialize(&mut engine).unwrap();
            0u8.commitment_serialize(&mut engine).unwrap();
        }
        2 => {
            data.first().expect("We know that we have at least two elements").commitment_serialize(&mut engine).unwrap();
            data.last().expect("We know that we have at least two elements").commitment_serialize(&mut engine).unwrap();
        }
        _ => {
            let div = len / 2;
            merklize(prefix, &data[0..div], depth + 1).commitment_serialize(&mut engine).unwrap();
            merklize(prefix, &data[div..], depth + 1).commitment_serialize(&mut engine).unwrap();
        }
    }
    MerkleNode::from_engine(engine)
}

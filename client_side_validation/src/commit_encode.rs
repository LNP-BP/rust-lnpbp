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

use std::io;

use bitcoin_hashes::{sha256, sha256d, Hash, HashEngine};

use super::commit_verify::{self, CommitVerify};

pub trait CommitEncode {
    fn commit_encode<E: io::Write>(&self, e: E) -> usize;
    fn commit_serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        self.commit_encode(&mut vec);
        vec
    }
}

pub trait CommitEncodeWithStrategy {
    type Strategy;
}

/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod commit_strategy {
    use super::*;
    use bitcoin_hashes::Hash;
    use std::collections::{BTreeMap, BTreeSet};

    // Defining strategies:
    pub struct UsingStrict;
    pub struct UsingConceal;
    pub struct UsingHash<H>(std::marker::PhantomData<H>)
    where
        H: Hash + strict_encoding::StrictEncode;
    pub struct Merklization;

    impl<T> CommitEncode for amplify::Holder<T, UsingStrict>
    where
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            self.as_inner().strict_encode(e).expect(
                "Strict encoding must not fail for types implementing \
                      ConsensusCommit via marker trait ConsensusCommitFromStrictEncoding",
            )
        }
    }

    impl<T> CommitEncode for amplify::Holder<T, UsingConceal>
    where
        T: CommitConceal,
        <T as CommitConceal>::ConcealedCommitment: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            self.as_inner().commit_conceal().commit_encode(e)
        }
    }

    impl<T, H> CommitEncode for amplify::Holder<T, UsingHash<H>>
    where
        H: Hash + strict_encoding::StrictEncode,
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            let mut engine = H::engine();
            engine
                .input(&strict_encoding::strict_serialize(self.as_inner()).expect(
                    "Strict encoding of hash strategy-based commitment data must not fail",
                ));
            let hash = H::from_engine(engine);
            hash.strict_encode(e).expect(
                "Strict encoding must not fail for types implementing \
                      ConsensusCommit via marker trait ConsensusCommitFromStrictEncoding",
            )
        }
    }

    impl<T> CommitEncode for amplify::Holder<T, Merklization>
    where
        T: IntoIterator + Clone,
        <T as IntoIterator>::Item: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            merklize(
                "",
                &self
                    .as_inner()
                    .clone()
                    .into_iter()
                    .map(|item| {
                        let mut encoder = io::Cursor::new(vec![]);
                        item.commit_encode(&mut encoder);
                        MerkleNode::hash(&encoder.into_inner())
                    })
                    .collect::<Vec<MerkleNode>>(),
                0,
            )
            .commit_encode(e)
        }
    }

    impl<K, V> CommitEncode for &(K, V)
    where
        K: CommitEncode,
        V: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e) + self.1.commit_encode(&mut e)
        }
    }

    impl<K, V> CommitEncode for (K, V)
    where
        K: CommitEncode,
        V: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e) + self.1.commit_encode(&mut e)
        }
    }

    impl<T> CommitEncode for T
    where
        T: CommitEncodeWithStrategy + Clone,
        amplify::Holder<T, <T as CommitEncodeWithStrategy>::Strategy>:
            CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            amplify::Holder::new(self.clone()).commit_encode(e)
        }
    }

    impl CommitEncodeWithStrategy for usize {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u8 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u16 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u32 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for u64 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i8 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i16 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i32 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for i64 {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for String {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for &str {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for &[u8] {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for MerkleNode {
        type Strategy = UsingStrict;
    }

    #[cfg(feature = "grin_secp256k1zkp")]
    impl CommitEncodeWithStrategy for secp256k1zkp::pedersen::Commitment {
        type Strategy = commit_strategy::UsingStrict;
    }

    #[cfg(feature = "grin_secp256k1zkp")]
    impl CommitEncodeWithStrategy for secp256k1zkp::pedersen::RangeProof {
        type Strategy = commit_strategy::UsingHash<sha256::Hash>;
    }

    impl<K, V> CommitEncodeWithStrategy for BTreeMap<K, V> {
        type Strategy = Merklization;
    }
    impl<T> CommitEncodeWithStrategy for BTreeSet<T> {
        type Strategy = Merklization;
    }
    impl<T> CommitEncodeWithStrategy for Vec<T> {
        type Strategy = Merklization;
    }

    impl<T> CommitEncodeWithStrategy for &T
    where
        T: CommitEncodeWithStrategy,
    {
        type Strategy = T::Strategy;
    }
}

pub trait CommitConceal {
    type ConcealedCommitment;
    fn commit_conceal(&self) -> Self::ConcealedCommitment;
}

pub trait ConsensusCommit: Sized + CommitEncode {
    type Commitment: commit_verify::CommitVerify<Vec<u8>>;

    #[inline]
    fn consensus_commit(&self) -> Self::Commitment {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        Self::Commitment::commit(&encoder.into_inner())
    }

    #[inline]
    fn consensus_verify(&self, commitment: &Self::Commitment) -> bool {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        commitment.verify(&encoder.into_inner())
    }
}

#[macro_export]
macro_rules! commit_encode_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.commit_encode(&mut $encoder);
            )+
            len
        }
    }
}

hash_newtype!(
    MerkleNode,
    sha256d::Hash,
    32,
    doc = "A hash of a arbitrary Merkle tree branch or root"
);

impl strict_encoding::Strategy for MerkleNode {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

impl<MSG> CommitVerify<MSG> for MerkleNode
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> MerkleNode {
        MerkleNode::hash(msg.as_ref())
    }
}

/// Merklization procedure that uses tagged hashes with depth commitments
pub fn merklize(prefix: &str, data: &[MerkleNode], depth: u16) -> MerkleNode {
    let len = data.len();

    let mut engine = MerkleNode::engine();
    let tag = format!("{}:merkle:{}", prefix, depth);
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    match len {
        0 => {
            0u8.commit_encode(&mut engine);
            0u8.commit_encode(&mut engine);
        }
        1 => {
            data.first()
                .expect("We know that we have one element")
                .commit_encode(&mut engine);
            0u8.commit_encode(&mut engine);
        }
        2 => {
            data.first()
                .expect("We know that we have at least two elements")
                .commit_encode(&mut engine);
            data.last()
                .expect("We know that we have at least two elements")
                .commit_encode(&mut engine);
        }
        _ => {
            let div = len / 2;
            merklize(prefix, &data[0..div], depth + 1)
                .commit_encode(&mut engine);
            merklize(prefix, &data[div..], depth + 1)
                .commit_encode(&mut engine);
        }
    }
    MerkleNode::from_engine(engine)
}

#[cfg(test)]
mod test {
    use super::*;
    use amplify::{bmap, s};
    use bitcoin_hashes::hex::ToHex;
    use std::collections::BTreeMap;
    use strict_encoding::StrictEncode;

    #[test]
    fn collections() {
        // First, we define a data type
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
        struct Item(pub String);
        // Next, we say that it should be concealed using some function
        // (double SHA256 hash in this case)
        impl CommitConceal for Item {
            type ConcealedCommitment = sha256d::Hash;
            fn commit_conceal(&self) -> Self::ConcealedCommitment {
                sha256d::Hash::hash(self.0.as_bytes())
            }
        }
        // Next, we need to specify how the concealed data should be
        // commit-encoded: this time we strict-serialize the hash
        impl CommitEncodeWithStrategy for sha256d::Hash {
            type Strategy = commit_strategy::UsingStrict;
        }
        // Now, we define commitment encoding for our concealable type: it
        // should conceal the data
        impl CommitEncodeWithStrategy for Item {
            type Strategy = commit_strategy::UsingConceal;
        }
        // Now, we need to say that consensus commit procedure should produce
        // a final commitment from commit-encoded data (equal to the
        // strict encoding of the conceal result) using `CommitVerify` type.
        // Here, we use another round of hashing, producing merkle node hash
        // from the concealed data.
        impl ConsensusCommit for Item {
            type Commitment = MerkleNode;
        }
        // When we put such items into a collection, we need to explicitly
        // specify which type of the final commitment will be produced from
        // the merkle tree (which is automatically used for any collection type)
        impl ConsensusCommit for BTreeMap<usize, Item> {
            type Commitment = MerkleNode;
        }
        impl ConsensusCommit for Vec<Item> {
            type Commitment = MerkleNode;
        }

        let item = Item(s!("Some text"));
        assert_eq!(&b"\x09\x00Some text"[..], item.strict_serialize().unwrap());
        assert_eq!(
            "6680bbec0d05d3eaac9c8b658c40f28d2f0cb0f245c7b1cabf5a61c35bd03d8e",
            item.commit_serialize().to_hex()
        );
        assert_eq!(
            "df08dc157bbd5676d5aeb1b437fa0cded8d3e21699adee2fcbbadef131a9e895",
            item.consensus_commit().to_hex()
        );
        assert_ne!(item.commit_serialize(), item.strict_serialize().unwrap());
        assert_eq!(
            MerkleNode::hash(&item.commit_serialize()),
            item.consensus_commit()
        );

        let collection: BTreeMap<usize, Item> = bmap! {
            0 => Item(s!("My first case")),
            1 => Item(s!("My second case with a very long string")),
            3 => Item(s!("My third case to make the Merkle tree two layered"))
        };
        assert_eq!(
            &b"\x03\x00\
             \x00\x00\
             \x0d\x00\
             My first case\
             \x01\x00\
             \x26\x00\
             My second case with a very long string\
             \x03\x00\
             \x31\x00\
             My third case to make the Merkle tree two layered"[..],
            collection.strict_serialize().unwrap()
        );
        assert_eq!(
            "d88abaa2e8d2222c98a3596abbe99bf40aef7b95db93552a1fd9e1610fb2c6cb",
            collection.commit_serialize().to_hex()
        );
        assert_eq!(
            "c10a53779cb10d64268deb4b16d0ddcc02fa81143755d84c40725b4345a2f2e8",
            collection.consensus_commit().to_hex()
        );
        assert_ne!(
            collection.commit_serialize(),
            collection.strict_serialize().unwrap()
        );
        assert_eq!(
            MerkleNode::hash(&collection.commit_serialize()),
            collection.consensus_commit()
        );

        let vec: Vec<Item> = vec![
            Item(s!("My first case")),
            Item(s!("My second case with a very long string")),
            Item(s!("My third case to make the Merkle tree two layered")),
        ];
        assert_eq!(
            &b"\x03\x00\
             \x0d\x00\
             My first case\
             \x26\x00\
             My second case with a very long string\
             \x31\x00\
             My third case to make the Merkle tree two layered"[..],
            vec.strict_serialize().unwrap()
        );
        assert_eq!(
            "bb929db2825f7a9a8f98dd8bc9b919a402db6c3803a45c9632108e9616cb9da5",
            vec.commit_serialize().to_hex()
        );
        assert_eq!(
            "2a5dd4bff32d99ff57da825288bbe240645816ea53501d19fab2c53cdc56d574",
            vec.consensus_commit().to_hex()
        );
        assert_ne!(vec.commit_serialize(), vec.strict_serialize().unwrap());
        assert_eq!(
            MerkleNode::hash(&vec.commit_serialize()),
            vec.consensus_commit()
        );
        assert_ne!(vec.consensus_commit(), collection.consensus_commit());
    }
}

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

// TODO: Refactor all `CommitEncode`s into not requiring cloning
pub trait CommitEncode {
    fn commit_encode<E: io::Write>(self, e: E) -> usize;
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
        fn commit_encode<E: io::Write>(self, e: E) -> usize {
            self.into_inner().strict_encode(e).expect(
                "Strict encoding must not fail for types implementing \
                      ConsensusCommit via marker trait ConsensusCommitFromStrictEncoding",
            )
        }
    }

    impl<T> CommitEncode for amplify::Holder<T, UsingConceal>
    where
        T: Conceal,
        <T as Conceal>::Confidential: CommitEncode,
    {
        fn commit_encode<E: io::Write>(self, e: E) -> usize {
            self.into_inner().conceal().commit_encode(e)
        }
    }

    impl<T, H> CommitEncode for amplify::Holder<T, UsingHash<H>>
    where
        H: Hash + strict_encoding::StrictEncode,
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode<E: io::Write>(self, e: E) -> usize {
            let mut engine = H::engine();
            engine
                .input(&strict_encoding::strict_serialize(&self.into_inner()).expect(
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
        T: IntoIterator,
        <T as IntoIterator>::Item: CommitEncode,
    {
        fn commit_encode<E: io::Write>(self, e: E) -> usize {
            merklize(
                "",
                &self
                    .into_inner()
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

    impl<K, V> CommitEncode for (K, V)
    where
        K: CommitEncode,
        V: CommitEncode,
    {
        fn commit_encode<E: io::Write>(self, mut e: E) -> usize {
            self.0.commit_encode(&mut e) + self.1.commit_encode(&mut e)
        }
    }

    impl<T> CommitEncode for T
    where
        T: CommitEncodeWithStrategy,
        amplify::Holder<T, <T as CommitEncodeWithStrategy>::Strategy>:
            CommitEncode,
    {
        fn commit_encode<E: io::Write>(self, e: E) -> usize {
            amplify::Holder::new(self).commit_encode(e)
        }
    }

    // Marker trait for automatically implementing the CommitEncode trait
    //  (with Merklization strategy) for a vector of that given type
    pub trait VectorCommitEncode {}

    impl<T> CommitEncodeWithStrategy for Vec<T>
    where
        T: VectorCommitEncode
    {
        type Strategy = commit_strategy::Merklization;
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
    impl CommitEncodeWithStrategy for Vec<u8> {
        type Strategy = UsingStrict;
    }
    impl CommitEncodeWithStrategy for Vec<u16> {
        type Strategy = Merklization;
    }
    impl CommitEncodeWithStrategy for Vec<u32> {
        type Strategy = Merklization;
    }
    impl CommitEncodeWithStrategy for Vec<u64> {
        type Strategy = Merklization;
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

    impl<T> CommitEncodeWithStrategy for &T
    where
        T: CommitEncodeWithStrategy,
    {
        type Strategy = T::Strategy;
    }
}

pub trait Conceal {
    type Confidential;
    fn conceal(&self) -> Self::Confidential;
}

pub trait ConsensusCommit: Sized + CommitEncode {
    type Commitment: commit_verify::CommitVerify<Vec<u8>>;

    #[inline]
    fn consensus_commit(self) -> Self::Commitment {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        Self::Commitment::commit(&encoder.into_inner())
    }

    #[inline]
    fn consensus_verify(self, commitment: &Self::Commitment) -> bool {
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

/*
/// This simple trait MUST be used by all parties implementing client-side
/// validation paradigm. The core concept of this paradigm is that a client
/// must have a complete and uniform set of data, which can be represented
/// or accessed through a single structure; and MUST be able to deterministically
/// validate this set giving an external validation function, that is able to
/// provide validator with
pub trait ClientSideValidate<TR> where TR: TrustResolver {
    type ClientData: ClientData;
    type ValidationError: FromTrustProblem<TR> + FromInternalInconsistency<TR>;

    fn new() -> Self;

    fn client_side_validate(client_data: Self::ClientData, trust_resolver: TR) -> Result<(), Self::ValidationError> {
        let validator = Self::new();
        client_data.validate_internal_consistency()?;
        client_data.validation_iter().try_for_each(|item| {
            trust_resolver.resolve_trust(item, validator.get_context_for_atom(item))?;
            item.client_side_validate()
        })
    }

    fn get_context_for_item<C: TrustContext>(&self, data_item: Self::ClientData::ValidationItem) -> C;
}


pub trait ClientData {
    type ValidationItem: ClientData;
}

pub trait TrustContext {

}

/// Trust resolver for a given client data type MUST work with a single type
/// of `TrustContext`, defined by an associated type. Trust resolution MUST
/// always produce a singular success type (defined by `()`) or fail with a
/// well-defined type of `TrustProblem`.
///
/// Trust resolved may have an internal state (represented by `self` reference)
/// and it does not require to produce a deterministic result for the same
/// given data piece and context: the trust resolver may depend on previous
/// operation history and depend on type and other external parameters.
pub trait TrustResolver<T: ClientData> {
    type TrustProblem: std::error::Error;
    type Context: TrustContext;
    fn resolve_trust(&self, data_piece: &T, context: &Self::Context) -> Result<(), Self::TrustProblem>;
}



mod test {
    struct BlockchainValidator;
    impl ClientSideValidate for BlockchainValidator {
        type ClientData = Blockchain;
        fn new() -> Self { Self }
        fn get_context_for_item(&self, data_item: Block) -> Difficulty { }
    }



    fn test() {

    }
}
*/

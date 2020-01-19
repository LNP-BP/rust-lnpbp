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


use core::marker::PhantomData;
use bitcoin::{
    hash_types::*,
    blockdata::script::*,
    secp256k1
};
use miniscript::{Miniscript, Terminal::*, MiniscriptKey};
use crate::Wrapper;


//
// PubkeyScript -+====> LockScript <----+
//               |                      |
//               +----> RedeemScript ---+
//               |
//               +----> TapScript
//

pub struct _LockScriptPhantom;
pub struct _PubkeyScriptPhantom;
pub struct _RedeemScriptPhantom;
pub struct _TapScriptPhantom;
pub type LockScript = Wrapper<Script, PhantomData<_LockScriptPhantom>>;
pub type PubkeyScript = Wrapper<Script, PhantomData<_PubkeyScriptPhantom>>;
pub type RedeemScript = Wrapper<Script, PhantomData<_RedeemScriptPhantom>>;
pub type TapScript = Wrapper<Script, PhantomData<_TapScriptPhantom>>;

#[derive(Debug)]
pub enum LockScriptParseError<Pk: MiniscriptKey> {
    PubkeyHash(Pk::Hash),
    Miniscript(miniscript::Error)
}

impl<Pk: MiniscriptKey> From<miniscript::Error> for LockScriptParseError<Pk> {
    fn from(miniscript_error: miniscript::Error) -> Self {
        Self::Miniscript(miniscript_error)
    }
}


fn collect_pubkeys(
    miniscript: &Miniscript<miniscript::bitcoin::PublicKey>
) -> Result<Vec<bitcoin::PublicKey>, LockScriptParseError<bitcoin::PublicKey>> {
    Ok(match &miniscript.node {
        Pk(key) => vec![key.clone()],
        PkH(pkh) => Err(LockScriptParseError::PubkeyHash(pkh.clone()))?,
        ThreshM(_, keys) =>
            keys.iter().map(|key| key.clone()).collect(),

        Alt(node) |
        Swap(node) |
        Check(node) |
        DupIf(node) |
        Verify(node) |
        NonZero(node) |
        ZeroNotEqual(node) =>
            collect_pubkeys(&node)?,
        AndV(node1, node2) |
        AndB(node1, node2) |
        OrB(node1, node2) |
        OrD(node1, node2) |
        OrC(node1, node2) |
        OrI(node1, node2) =>
            collect_pubkeys(&node1)?.into_iter()
                .chain(collect_pubkeys(&node2)?.into_iter()).collect(),
        AndOr(node1, node2, node3) =>
            collect_pubkeys(&node1)?.into_iter()
                .chain(collect_pubkeys(&node2)?.into_iter())
                .chain(collect_pubkeys(&node3)?.into_iter()).collect(),
        Thresh(_, node_vec) => {
            let mut vec= vec![];
            for node in node_vec {
                vec.append(&mut collect_pubkeys(&node)?);
            }
            vec
        }

        _ => vec![],
    })
}


fn for_each_pubkey<E: Into<LockScriptParseError<bitcoin::PublicKey>>>(
    miniscript: &mut Miniscript<bitcoin::PublicKey>,
    f: fn(&mut bitcoin::PublicKey) -> Result<(), E>
) -> Result<usize, LockScriptParseError<bitcoin::PublicKey>> {
    Ok(match &mut miniscript.node {
        Pk(key) => f(key).map_err(|err| err.into()).map(|_| 1)?,
        PkH(pkh) =>
            Err(LockScriptParseError::PubkeyHash(pkh.clone()))?,
        ThreshM(_, keys) =>
            keys.into_iter()
                .try_for_each(|mut key| f(&mut key).map_err(|err| err.into()))
                .map(|_| keys.len())?,

        Alt(node) |
        Swap(node) |
        Check(node) |
        DupIf(node) |
        Verify(node) |
        NonZero(node) |
        ZeroNotEqual(node) =>
            for_each_pubkey(node, f)?,
        AndV(node1, node2) |
        AndB(node1, node2) |
        OrB(node1, node2) |
        OrD(node1, node2) |
        OrC(node1, node2) |
        OrI(node1, node2) =>
            for_each_pubkey(node1, f)? +
            for_each_pubkey(node2, f)?,
        AndOr(node1, node2, node3) =>
            for_each_pubkey(node1, f)? +
            for_each_pubkey(node2, f)? +
            for_each_pubkey(node3, f)?,
        Thresh(_, node_vec) =>
            node_vec.into_iter()
                .try_fold(0, |acc, node|
                    for_each_pubkey(node, f)
                )?,

        _ => 0,
    })
}


impl LockScript {
    pub fn extract_pubkeys(&self) -> Result<Vec<secp256k1::PublicKey>, LockScriptParseError<bitcoin::PublicKey>> {
        let miniscript = Miniscript::parse(&self.clone().into_inner())?;
        Ok(collect_pubkeys(&miniscript)?.iter().map(|bpk| bpk.key).collect())
    }

    pub fn replace_pubkeys<E: Into<LockScriptParseError<bitcoin::PublicKey>>>(&mut self, f: fn(&mut bitcoin::PublicKey) -> Result<(), E>) -> Result<usize, LockScriptParseError<bitcoin::PublicKey>> {
        let mut miniscript = Miniscript::parse(&self.clone().into_inner())?;
        for_each_pubkey(&mut miniscript, f)
    }
}


pub enum ScriptPubkeyType {
    P2S(Script),
    P2PK(secp256k1::PublicKey),
    P2PKH(PubkeyHash),
    P2SH(ScriptHash),
    P2OR(Vec<u8>),
    P2WPKH(WPubkeyHash),
    P2WSH(WScriptHash),
    P2TR(secp256k1::PublicKey),
}
use ScriptPubkeyType::*;

impl From<Script> for ScriptPubkeyType {
    fn from(script_pubkey: Script) -> Self {
        Self::P2S(script_pubkey)
    }
}

impl From<ScriptPubkeyType> for PubkeyScript {
    fn from(spkt: ScriptPubkeyType) -> PubkeyScript {
        PubkeyScript::from_inner(match spkt {
            P2S(script) => script,
            P2PK(pubkey) =>
                Builder::gen_p2pk(&bitcoin::PublicKey { compressed: false, key: pubkey }).into_script(),
            P2PKH(pubkey_hash) => Builder::gen_p2pkh(&pubkey_hash).into_script(),
            P2SH(script_hash) => Builder::gen_p2sh(&script_hash).into_script(),
            P2OR(data) => Builder::gen_op_return(&data).into_script(),
            P2WPKH(wpubkey_hash) => Builder::gen_v0_p2wpkh(&wpubkey_hash).into_script(),
            P2WSH(wscript_hash) => Builder::gen_v0_p2wsh(&wscript_hash).into_script(),
            P2TR(pubkey) => unimplemented!(),
        })
    }
}
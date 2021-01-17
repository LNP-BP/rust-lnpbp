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

use bitcoin::blockdata::{opcodes::all::*, script};
use bitcoin::secp256k1::PublicKey;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut};

use crate::bp::{
    chain::AssetId, HashLock, HashPreimage, IntoPk, LockScript, PubkeyScript,
    WitnessScript,
};
use crate::lnp::application::payment::{ChannelId, ExtensionId, TxType};
use crate::lnp::application::{channel, ChannelExtension, Extension, Messages};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HtlcKnown {
    pub amount: u64,
    pub preimage: HashPreimage,
    pub id: u64,
    pub cltv_expiry: u32,
    pub asset_id: Option<AssetId>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HtlcSecret {
    pub amount: u64,
    pub hashlock: HashLock,
    pub id: u64,
    pub cltv_expiry: u32,
    pub asset_id: Option<AssetId>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Htlc {
    // Sets of HTLC informations
    offered_htlcs: Vec<HtlcSecret>,
    received_htlcs: Vec<HtlcSecret>,
    resolved_htlcs: Vec<HtlcKnown>,

    // Commitment round specific information
    to_self_delay: u16,
    revocation_pubkey: PublicKey,
    local_htlc_pubkey: PublicKey,
    remote_htlc_pubkey: PublicKey,
    local_delayed_pubkey: PublicKey,

    // Channel specific information
    channel_id: ChannelId,
    commitment_outpoint: OutPoint,
    htlc_minimum_msat: u64,
    max_htlc_value_in_flight_msat: u64,
    total_htlc_value_in_flight_msat: u64,
    max_accepted_htlcs: u16,
    total_accepted_htlcs: u16,
    last_recieved_htlc_id: u64,
    last_offered_htlc_id: u64,
}

impl channel::State for Htlc {}

impl Extension for Htlc {
    type Identity = ExtensionId;

    fn identity(&self) -> Self::Identity {
        ExtensionId::Htlc
    }

    fn update_from_peer(
        &mut self,
        message: &Messages,
    ) -> Result<(), channel::Error> {
        match message {
            Messages::UpdateAddHtlc(message) => {
                if message.channel_id == self.channel_id {
                    // Checks
                    // 1. sending node should afford current fee rate after
                    // adding this htlc to its local
                    // commitment including anchor outputs
                    // if opt in.
                    if message.amount_msat == 0
                        || message.amount_msat < self.htlc_minimum_msat
                    {
                        return Err(channel::Error::HTLC(
                            "amount_msat has to be greaterthan 0".to_string(),
                        ));
                    } else if self.total_accepted_htlcs
                        == self.max_accepted_htlcs
                    {
                        return Err(channel::Error::HTLC(
                            "max no. of HTLC limit exceeded".to_string(),
                        ));
                    } else if message.amount_msat
                        + self.total_htlc_value_in_flight_msat
                        > self.max_htlc_value_in_flight_msat
                    {
                        return Err(channel::Error::HTLC(
                            "max HTLC inflight amount limit exceeded"
                                .to_string(),
                        ));
                    } else if message.cltv_expiry > 500000000 {
                        return Err(channel::Error::HTLC(
                            "cltv_expiry limit exceeded".to_string(),
                        ));
                    } else if message.amount_msat.leading_zeros() < 32 {
                        return Err(channel::Error::HTLC(
                            "Leading zeros not satisfied for Bitcoin network"
                                .to_string(),
                        ));
                    } else if message.htlc_id <= self.last_recieved_htlc_id {
                        return Err(channel::Error::HTLC(
                            "HTLC id violation occured".to_string(),
                        )); // TODO handle reconnection
                    } else {
                        let htlc = HtlcSecret {
                            amount: message.amount_msat,
                            hashlock: message.payment_hash,
                            id: message.htlc_id,
                            cltv_expiry: message.cltv_expiry,
                            asset_id: message.asset_id,
                        };
                        self.received_htlcs.push(htlc);

                        self.last_recieved_htlc_id += 1;
                    }
                } else {
                    return Err(channel::Error::HTLC(
                        "Missmatched channel_id, bad remote node".to_string(),
                    ));
                }
            }
            Messages::UpdateFulfillHtlc(message) => {
                if message.channel_id == self.channel_id {
                    // Get the corresponding offered htlc
                    let (index, offered_htlc) = self
                        .offered_htlcs
                        .iter()
                        .enumerate()
                        .filter(|(index, htlc)| htlc.id == message.htlc_id)
                        .next()
                        .ok_or(channel::Error::HTLC(
                            "HTLC id didn't match".to_string(),
                        ))?;

                    // Check for correct hash preimage in the message
                    if offered_htlc.hashlock
                        == HashLock::from(message.payment_preimage)
                    {
                        self.received_htlcs.remove(index);
                        let resolved_htlc = HtlcKnown {
                            amount: offered_htlc.amount,
                            preimage: message.payment_preimage,
                            id: message.htlc_id,
                            cltv_expiry: offered_htlc.cltv_expiry,
                            asset_id: offered_htlc.asset_id,
                        };

                        self.resolved_htlcs.push(resolved_htlc);
                    }
                } else {
                    return Err(channel::Error::HTLC(
                        "Missmatched channel_id, bad remote node".to_string(),
                    ));
                }
            }
            Messages::UpdateFailHtlc(message) => {
                if message.channel_id == self.channel_id {
                    // get the offered HTLC to fail
                    let (index, offered_htlc) = self
                        .offered_htlcs
                        .iter()
                        .enumerate()
                        .filter(|(index, htlc)| htlc.id == message.htlc_id)
                        .next()
                        .ok_or(channel::Error::HTLC(
                            "HTLC id didn't match".to_string(),
                        ))?;

                    self.offered_htlcs.remove(index);

                    // TODO the failure reason should be handled here
                }
            }
            Messages::UpdateFailMalformedHtlc(_) => {}
            Messages::CommitmentSigned(_) => {}
            Messages::RevokeAndAck(_) => {}
            Messages::ChannelReestablish(_) => {}
            _ => {}
        }
        Ok(())
    }

    fn extension_state(&self) -> Box<dyn channel::State> {
        Box::new(self.clone())
    }
}

impl ChannelExtension for Htlc {
    fn channel_state(&self) -> Box<dyn channel::State> {
        Box::new(self.clone())
    }

    fn apply(
        &mut self,
        tx_graph: &mut channel::TxGraph,
    ) -> Result<(), channel::Error> {
        // Process offered HTLCs
        for (index, offered) in self.offered_htlcs.iter().enumerate() {
            let htlc_output = TxOut::ln_offered_htlc(
                offered.amount,
                self.revocation_pubkey,
                self.local_htlc_pubkey,
                self.remote_htlc_pubkey,
                offered.hashlock,
            );
            tx_graph.cmt_outs.push(htlc_output); // Should htlc outputs be inside graph.cmt?

            let htlc_tx = Psbt::ln_htlc(
                offered.amount,
                self.commitment_outpoint,
                offered.cltv_expiry,
                self.revocation_pubkey,
                self.local_delayed_pubkey,
                self.to_self_delay,
            );
            // Last index of transaction in graph
            let last_index = tx_graph.last_index(TxType::HtlcTimeout) + 1;
            tx_graph.insert_tx(
                TxType::HtlcTimeout,
                (last_index + index) as u64,
                htlc_tx,
            );
        }

        // Process recieved HTLCs
        for (index, recieved) in self.received_htlcs.iter().enumerate() {
            let htlc_output = TxOut::ln_received_htlc(
                recieved.amount,
                self.revocation_pubkey,
                self.local_htlc_pubkey,
                self.remote_htlc_pubkey,
                recieved.cltv_expiry,
                recieved.hashlock.clone(),
            );
            tx_graph.cmt_outs.push(htlc_output);

            let htlc_tx = Psbt::ln_htlc(
                recieved.amount,
                self.commitment_outpoint,
                recieved.cltv_expiry,
                self.revocation_pubkey,
                self.local_delayed_pubkey,
                self.to_self_delay,
            );
            // Figure out the last index of transaction in graph
            let last_index = tx_graph.last_index(TxType::HtlcSuccess) + 1;
            tx_graph.insert_tx(
                TxType::HtlcSuccess,
                (last_index + index) as u64,
                htlc_tx,
            );
        }
        Ok(())
    }
}

pub trait ScriptGenerators {
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self;

    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self;

    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl ScriptGenerators for LockScript {
    fn ln_offered_htlc(
        _: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocationpubkey.into_pk().pubkey_hash())
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&remote_htlcpubkey.into_pk())
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_NOTIF)
            .push_opcode(OP_DROP)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_key(&local_htlcpubkey.into_pk())
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_HASH160)
            .push_slice(payment_hash.as_ref())
            .push_opcode(OP_EQUALVERIFY)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
            .into()
    }

    fn ln_received_htlc(
        _: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_DUP)
            .push_opcode(OP_HASH160)
            .push_slice(&revocationpubkey.into_pk().pubkey_hash())
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_key(&remote_htlcpubkey.into_pk())
            .push_opcode(OP_SWAP)
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_HASH160)
            .push_slice(payment_hash.as_ref())
            .push_opcode(OP_EQUALVERIFY)
            .push_int(2)
            .push_opcode(OP_SWAP)
            .push_key(&local_htlcpubkey.into_pk())
            .push_int(2)
            .push_opcode(OP_CHECKMULTISIG)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_DROP)
            .push_int(cltv_expiry as i64)
            .push_opcode(OP_CLTV)
            .push_opcode(OP_DROP)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_ENDIF)
            .into_script()
            .into()
    }

    fn ln_htlc_output(
        _: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        script::Builder::new()
            .push_opcode(OP_IF)
            .push_key(&revocationpubkey.into_pk())
            .push_opcode(OP_ELSE)
            .push_int(to_self_delay as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&local_delayedpubkey.into_pk())
            .push_opcode(OP_ENDIF)
            .push_opcode(OP_CHECKSIG)
            .into_script()
            .into()
    }
}

impl ScriptGenerators for WitnessScript {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        LockScript::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .into()
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        LockScript::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        )
        .into()
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        LockScript::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .into()
    }
}

impl ScriptGenerators for PubkeyScript {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        WitnessScript::ln_offered_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            payment_hash,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        WitnessScript::ln_received_htlc(
            amount,
            revocationpubkey,
            local_htlcpubkey,
            remote_htlcpubkey,
            cltv_expiry,
            payment_hash,
        )
        .to_p2wsh()
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        WitnessScript::ln_htlc_output(
            amount,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        )
        .to_p2wsh()
    }
}

impl ScriptGenerators for TxOut {
    #[inline]
    fn ln_offered_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        payment_hash: HashLock,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_offered_htlc(
                amount,
                revocationpubkey,
                local_htlcpubkey,
                remote_htlcpubkey,
                payment_hash,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_received_htlc(
        amount: u64,
        revocationpubkey: PublicKey,
        local_htlcpubkey: PublicKey,
        remote_htlcpubkey: PublicKey,
        cltv_expiry: u32,
        payment_hash: HashLock,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_received_htlc(
                amount,
                revocationpubkey,
                local_htlcpubkey,
                remote_htlcpubkey,
                cltv_expiry,
                payment_hash,
            )
            .into(),
        }
    }

    #[inline]
    fn ln_htlc_output(
        amount: u64,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        TxOut {
            value: amount,
            script_pubkey: PubkeyScript::ln_htlc_output(
                amount,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            )
            .into(),
        }
    }
}

pub trait TxGenerators {
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self;
}

impl TxGenerators for Transaction {
    /// NB: For HTLC Success transaction always set `cltv_expiry` parameter
    ///     to zero!
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        Transaction {
            version: 2,
            lock_time: cltv_expiry,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: none!(),
                sequence: 0,
                witness: empty!(),
            }],
            output: vec![TxOut::ln_htlc_output(
                amount,
                revocationpubkey,
                local_delayedpubkey,
                to_self_delay,
            )],
        }
    }
}

impl TxGenerators for Psbt {
    fn ln_htlc(
        amount: u64,
        outpoint: OutPoint,
        cltv_expiry: u32,
        revocationpubkey: PublicKey,
        local_delayedpubkey: PublicKey,
        to_self_delay: u16,
    ) -> Self {
        Psbt::from_unsigned_tx(Transaction::ln_htlc(
            amount,
            outpoint,
            cltv_expiry,
            revocationpubkey,
            local_delayedpubkey,
            to_self_delay,
        ))
        .expect("Tx has empty sigs so PSBT creation does not faile")
    }
}

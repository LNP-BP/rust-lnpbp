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


#![allow(unused_imports)]

use std::collections::{HashSet, HashMap};
use std::convert::TryInto;

use bitcoin::{Txid, Transaction, OutPoint};

use petgraph::{Directed, Direction, stable_graph::StableGraph};
use petgraph::visit::{Bfs, EdgeRef, Reversed};
use petgraph::graph::{NodeIndex, DefaultIx};

use crate::common::Wrapper;

use super::{Transition, Metadata, State};
use super::state::{Partial, Bound};
use super::data;
use super::seal;
use super::validation::{TxFetch, ValidationError};
use super::schema::Schema;

#[derive(Debug, Clone)]
pub enum GraphError {
    InvalidOpenSeal(NodeIndex<DefaultIx>),
    OpenSealAsParent,
}

#[derive(Debug, Clone)]
pub enum HistoryGraphNode {
    Open(usize, seal::Seal),
    Transition(Transition, Txid),
    Genesis(Transition),
}

#[derive(Debug, Clone)]
pub struct HistoryGraph {
    graph: StableGraph<HistoryGraphNode, (), Directed>,
    open: HashSet<NodeIndex<DefaultIx>>,
    genesis: NodeIndex<DefaultIx>,
}

impl HistoryGraph {
    /// Internal method to add all the open seals created in a transition
    fn add_open_seals(&mut self, from_transition: &Transition, to_node: NodeIndex<DefaultIx>) {
        for (index, state) in from_transition.state.iter().enumerate() {
            if let Partial::State(Bound { seal, .. }) = state {
                let open_seal_node = self.graph.add_node(HistoryGraphNode::Open(index, seal.clone()));
                self.graph.add_edge(open_seal_node, to_node, ());

                self.open.insert(open_seal_node);
            }
        }
    }

    /// Internal method to find the node indexes among the required open seals
    fn find_open_seals(&self, seals: Vec<&seal::Seal>) -> Result<HashSet<NodeIndex<DefaultIx>>, GraphError> {
        self
            .open
            .iter()
            .try_fold(HashSet::new(), |mut to_close, node_index| {
                if let Some(HistoryGraphNode::Open(_, node_seal)) = self.graph.node_weight(*node_index) {
                    if seals.iter().any(|seal| seal.compare(node_seal)) {
                        to_close.insert(*node_index);
                    }

                    Ok(to_close)
                } else {
                    Err(GraphError::InvalidOpenSeal(*node_index))
                }
            })
    }

    /// Creates a new graph starting from the genesis transition. The graph will contain the
    /// genesis itself plus all of its bound seals
    pub fn new(genesis: Transition) -> Self {
        let mut graph = StableGraph::new();
        let genesis_node = graph.add_node(HistoryGraphNode::Genesis(genesis.clone()));

        let mut graph = HistoryGraph {
            graph,
            genesis: genesis_node,
            open: HashSet::new(),
        };
        graph.add_open_seals(&genesis, graph.genesis);

        graph
    }

    /// Applies a transition to the graph, removing the closed seals and adding the newly created
    /// ones
    pub fn apply_transition(&mut self, transition: Transition, txid: Txid, closes: Vec<seal::Seal>) -> Result<(), GraphError> {
        // TODO: test with the same seal duplicated a few times

        let closing_indexes = self.find_open_seals(closes.iter().collect())?;

        // remove all the seals we are closing from the `open` vec
        self.open.retain(|node_index| !closing_indexes.contains(node_index));

        let new_node = self.graph.add_node(HistoryGraphNode::Transition(transition.clone(), txid));
        self.add_open_seals(&transition, new_node);

        for to_close in closing_indexes {
            // copy the edges connected to the node we are removing
            let to_edges = self
                .graph
                .edges_directed(to_close, Direction::Outgoing)
                .map(|edge| edge.target())
                .collect::<Vec<_>>();

            for to in to_edges {
                self.graph.add_edge(new_node, to, ());
            }

            // and then remove the node
            self.graph.remove_node(to_close);
        }

        Ok(())
    }

    /// Strips the part of the history that is not required to validate the requested open seals
    pub fn strip_history(&mut self, keep: Vec<seal::Seal>) -> Result<(), GraphError> {
        let mut keep_nodes = HashSet::new();

        for start in self.find_open_seals(keep.iter().collect())? {
            let mut bfs = Bfs::new(&self.graph, start);
            while let Some(nx) = bfs.next(&self.graph) {
                keep_nodes.insert(nx);
            }
        }

        self.graph.retain_nodes(|_, node| keep_nodes.contains(&node));

        Ok(())
    }

    pub fn merge_history(&mut self, other: Self) -> Result<(), GraphError> {
        // TODO: other is probably untrusted at this point, so more checks should be done. like:
        //       - make sure that there's only one genesis, and that it's ==
        //       - check that only the genesis has no closed seals
        //       - check the "open seals" and make sure they are really created by the transitions

        let mut transition_index = HashMap::new();
        let mut open_index = HashMap::new();

        // iterate `self.graph` from the genesis going forward (that's why edges are reversed), and
        // create an index of every transition or open seal we see
        let reversed_graph = Reversed(&self.graph);
        let mut bfs = Bfs::new(&reversed_graph, self.genesis);
        while let Some(nx) = bfs.next(&reversed_graph) {
            match self.graph.node_weight(nx).expect("Corrupted graph: missing node during BFS") {
                HistoryGraphNode::Genesis(_) => continue,
                HistoryGraphNode::Transition(_, txid) => { transition_index.insert(txid.clone(), nx); },
                HistoryGraphNode::Open(index, seal) => { open_index.insert((index.clone(), seal.txid.clone(), seal.vout.clone()), nx); },
            }
        }

        // Iterate `other.graph` from the genesis again. whenever we find a node that's missing in
        // `self.graph`, we add it and copy all the edges.
        //
        // Since we do a BFS, it's guaranteed that if we find a missing node, all of its "parent"
        // nodes will already be present.
        let reversed_other = Reversed(&other.graph);
        let mut bfs = Bfs::new(&reversed_other, other.genesis);
        while let Some(nx) = bfs.next(&reversed_other) {
            let mut add_to_self = |node: HistoryGraphNode, index_in_other: NodeIndex<DefaultIx>| -> Result<NodeIndex<DefaultIx>, GraphError> {
                // add the node to ourselves
                let new_node = self.graph.add_node(node);

                // iterate over all the neighbors in the `Outgoing` direction, so towards the
                // genesis. i.e., its parent nodes.
                for prev_node in other.graph.neighbors_directed(index_in_other, Direction::Outgoing) {
                    match other.graph.node_weight(prev_node).expect("Corrupted graph: missing node during BFS") {
                        HistoryGraphNode::Genesis(_) => { self.graph.add_edge(new_node, self.genesis, ()); },
                        HistoryGraphNode::Transition(_, prev_txid) => {
                            let corresponding_index = transition_index.get(prev_txid).expect(&format!("Corrupted graph: missing txid in `transition_index`: {:?}", prev_txid));
                            self.graph.add_edge(new_node, *corresponding_index, ());
                        },
                        HistoryGraphNode::Open(_, _) => return Err(GraphError::OpenSealAsParent),
                    }
                }

                Ok(new_node)
            };

            match other.graph.node_weight(nx).expect("Corrupted graph: missing node during BFS") {
                HistoryGraphNode::Genesis(_) => continue,
                HistoryGraphNode::Transition(transition, txid) => {
                    if transition_index.contains_key(txid) {
                        continue;
                    }

                    let new_node = add_to_self(HistoryGraphNode::Transition(transition.clone(), *txid), nx)?;

                    // add it to the index now that it's in `self.graph`
                    transition_index.insert(*txid, new_node);
                },
                HistoryGraphNode::Open(index, seal) => {
                    if open_index.contains_key(&(*index, seal.txid, seal.vout)) {
                        continue;
                    }

                    let new_node = add_to_self(HistoryGraphNode::Open(*index, seal.clone()), nx)?;

                    // add it to the index now that it's in `self.graph`
                    open_index.insert((*index, seal.txid, seal.vout), new_node);
                },
            }
        }

        Ok(())
    }

    pub fn validate<T>(&self, schema: &Schema, tx_fetch: &mut T, outpoint: OutPoint) -> Result<Option<data::PedersenCommitment>, ValidationError<T>>
    where
        T: TxFetch
    {
        let open_seal_nodes = self.find_open_seals(vec![&outpoint.try_into()?])?;
        if open_seal_nodes.is_empty() {
            return Err(ValidationError::InvalidOutpoint(outpoint));
        }

        // iterate all the seals we are closing
        for open_seal in open_seal_nodes {
            // start a bfs from that node
            let mut bfs = Bfs::new(&self.graph, open_seal);
            // for each node...
            while let Some(nx) = bfs.next(&self.graph) {
                // - if it's a transition, inspect it
                // - if it's the genesis, compare the asset id
                // - if it's an open seal == the one we are closing, skip it
                // - if it's a different open seal, return an error
                let (transition, txid) = match self.graph.node_weight(nx).expect("Corrupted graph: missing node during BFS") {
                    HistoryGraphNode::Transition(transition, txid) => (transition, txid),
                    HistoryGraphNode::Genesis(_) => continue, // TODO: check genesis
                    HistoryGraphNode::Open(_, seal) if seal.txid == Some(outpoint.txid) && seal.vout as u32 == outpoint.vout => continue, // open seal we are spending
                    HistoryGraphNode::Open(_, _) => return Err(GraphError::OpenSealAsParent.into()),
                };

                // fetch the transaction and check the commitment
                let tx = tx_fetch.fetch_from_txid(txid).map_err(ValidationError::TxFetch)?;
                // TODO: check that `tx` commits to the transition

                let inputs_set: HashSet<_> = tx.input.iter().map(|i| i.previous_output).collect();

                // validate the transition against its schema
                let partial_validation = schema.validate_transition(transition)?;

                let mut closed_seals = Vec::new();

                // iterate the parent nodes...
                for prev_node in self.graph.neighbors_directed(nx, Direction::Outgoing) {
                    // - if it's a transition or a genesis look for bound seals == the one we are closing
                    // - if it's an open seal, return an error
                    let (prev_transition, prev_txid) = match self.graph.node_weight(prev_node).expect("Corrupted graph: missing node during BFS") {
                        HistoryGraphNode::Transition(transition, txid) => (transition, Some(*txid)),
                        HistoryGraphNode::Genesis(transition) => (transition, None),
                        HistoryGraphNode::Open(_, _) => return Err(GraphError::OpenSealAsParent.into()),
                    };

                    // only take the partial items that are bound to one of the inputs of the
                    // current transaction
                    for partial in prev_transition.state.iter() {
                        match partial {
                            state @ Partial::State(Bound { id, seal, val }) if inputs_set.contains(&seal.as_outpoint(prev_txid)?) => closed_seals.push(state),
                            Partial::Commitment(_) => unimplemented!(), // TODO
                            _ => continue,
                        }
                    }
                }

                // check the closed seals against the schema (`partial_validation.should_close`)
                let input_commitments = partial_validation
                    .should_close
                    .expect("Transition should close some seals")
                    .validate(&schema.seals, closed_seals)?
                    .into_iter()
                    .map(|cmt| cmt.commitment)
                    .collect();

                println!("input_commitments: {:?}", input_commitments);

                // sum the inputs and compare it with the sum of outputs
                if !data::amount::verify_commit_sum(input_commitments, partial_validation.output_commitments) {
                    return Err(ValidationError::TxInNeTxOut);
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rgb::data;

    #[test]
    fn test_graph_apply_transition() {
        let genesis_open_seal = seal::Seal::from(Some(Default::default()), 5);
        let genesis = Transition {
            id: 0,
            meta: Metadata::from_inner(vec![]),
            state: State::from_inner(vec![Partial::State(Bound {
                id: seal::Type(0),
                seal: genesis_open_seal.clone(),
                val: data::Data::None,
            })]),
            script: None
        };

        let mut graph = HistoryGraph::new(genesis);
        println!("{:#?}", graph);

        let next_trans = Transition {
            id: 1,
            meta: Metadata::from_inner(vec![]),
            state: State::from_inner(vec![Partial::State(Bound {
                id: seal::Type(0),
                seal: seal::Seal::from(Some(Default::default()), 42),
                val: data::Data::None,
            })]),
            script: None,
        };

        graph.apply_transition(next_trans, Default::default(), vec![genesis_open_seal]);
        println!("{:#?}", graph);
    }

    #[test]
    fn test_graph_strip_history() {
        let seal = seal::Seal::from(Some(Default::default()), 0);
        let state = State::from_inner(
            vec![
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal.clone(),
                    val: data::Data::None,
                }),
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal::Seal::from(Some(Default::default()), 1),
                    val: data::Data::None,
                }),
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal::Seal::from(Some(Default::default()), 2),
                    val: data::Data::None,
                }),
            ]
        );
        let genesis = Transition {
            id: 0,
            meta: Metadata::from_inner(vec![]),
            state,
            script: None
        };

        let mut graph = HistoryGraph::new(genesis);
        println!("{:#?}", graph);

        graph.strip_history(vec![seal]);

        println!("{:#?}", graph);
    }

    #[test]
    fn test_graph_merge_history() {
        let genesis_open_seal = seal::Seal::from(Some(Default::default()), 42);
        let genesis = Transition {
            id: 0,
            meta: Metadata::from_inner(vec![]),
            state: State::from_inner(vec![Partial::State(Bound {
                id: seal::Type(0),
                seal: genesis_open_seal.clone(), 
                val: data::Data::None,
            })]),
            script: None
        };

        let mut graph = HistoryGraph::new(genesis);

        let seal_0 = seal::Seal::from(Some(Default::default()), 0);
        let seal_1 = seal::Seal::from(Some(Default::default()), 1);
        let state = State::from_inner(
            vec![
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal_0.clone(),
                    val: data::Data::None,
                }),
                Partial::State(Bound {
                    id: seal::Type(0),
                    seal: seal_1.clone(),
                    val: data::Data::None,
                }),
            ]
        );
        let next_trans = Transition {
            id: 1,
            meta: Metadata::from_inner(vec![]),
            state,
            script: None,
        };
        graph.apply_transition(next_trans, Txid::default(), vec![genesis_open_seal]);

        println!("initial graph {:#?}", graph);

        let mut history_0 = graph.clone();
        history_0.strip_history(vec![seal_0]);

        println!("{:#?}", history_0);

        let mut history_1 = graph.clone();
        history_1.strip_history(vec![seal_1]);

        history_0.merge_history(history_1);

        println!("{:#?}", history_0);
    }

    #[test]
    fn test_history_validate_rgb() {
        use std::convert::TryFrom;
        use std::ops::Deref;
        use bitcoin::{TxIn, Transaction, OutPoint};

        use crate::rgb::schemata::fungible::Rgb1;
        use crate::rgb::schemata::{Network, Schemata};
        use super::data;

        #[derive(Debug)]
        struct DummyTxFetch(HashMap<Txid, Transaction>);
        impl TxFetch for DummyTxFetch {
            type Error = ();

            fn fetch_from_txid(&mut self, txid: &Txid) -> Result<Transaction, Self::Error> {
                Ok(self.0.get(txid).unwrap().clone())
            }
        }

        let genesis_confidential_amount = data::amount::commit_last_item(1000, vec![]);

        let genesis_outpoint = OutPoint { txid: Default::default(), vout: 42 };
        let genesis_open_seal = seal::Seal::try_from(genesis_outpoint.clone()).unwrap();

        let balances = map!{
            genesis_outpoint.clone() => genesis_confidential_amount.commitment.clone()
        };
        let genesis = Rgb1::issue(Network::Regtest, "ALKS", "Alekos", None, balances, 1, None, None).unwrap();
        println!("{:#?}", genesis);

        let asset_id = genesis.transition_id().unwrap();
        println!("asset_id: {}", asset_id);

        let mut graph = HistoryGraph::new(genesis);
        println!("{:#?}", graph);

        let transfer_conf_amount_0 = data::amount::Confidential::from(500);
        let transfer_conf_amount_1 = data::amount::commit_last_item(500, vec![transfer_conf_amount_0.proof.deref().clone()]);

        let transfer_outpoint_0 = OutPoint { txid: Default::default(), vout: 100 };
        let transfer_outpoint_1 = OutPoint { txid: Default::default(), vout: 101 };
        let transfer_balances = map!{
            transfer_outpoint_0.clone() => transfer_conf_amount_0.commitment.clone(),
            transfer_outpoint_1.clone() => transfer_conf_amount_1.commitment.clone()
        };

        let transfer = Rgb1::transfer(transfer_balances).unwrap();
        println!("{:#?}", transfer);

        let committing_tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: genesis_outpoint,
                sequence: 0xFFFFFFFF,
                ..Default::default()
            }],
            output: vec![],
        };
        // (the commitment is not checked at the moment...)
        let mut tx_fetch = DummyTxFetch(map!{ committing_tx.txid() => committing_tx.clone() });

        graph.apply_transition(transfer, committing_tx.txid(), vec![genesis_open_seal]);
        println!("{:#?}", graph);

        let result = graph.validate(Rgb1::get_schema(), &mut tx_fetch, transfer_outpoint_0);
        println!("result = {:?}", result);
    }
}

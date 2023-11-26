// RGB wallet library for smart contracts on Bitcoin & Lightning network
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use amplify::num::{u5, u7};
use bpstd::{
    LeafInfo, ScriptPubkey, TapLeafHash, TapNodeHash, TapScript, TapTreeBuilder, Tx,
    UnfinalizedTree,
};
use commit_verify::{mpc, CommitVerify, CommitmentId, TryCommitVerify};
use dbc::tapret::{TapretCommitment, TapretPathProof, TapretProof};
use dbc::{Anchor, Proof};
use seals::txout::CloseMethod;

use super::lnpbp4::OutputLnpbp4;
use super::opret::OutputOpret;
use super::tapret::OutputTapret;
use super::{Lnpbp4PsbtError, OpretKeyError, TapretKeyError, PSBT_OUT_LNPBP4_MIN_TREE_DEPTH};
use crate::Psbt;

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum DbcPsbtError {
    /// Using non-empty taptree is not supported in RGB v0.10. Please update.
    TapTreeNonEmpty,

    /// taproot output doesn't specify internal key.
    NoInternalKey,

    /// none of the outputs is market as a commitment host.
    NoHostOutput,

    /// multiple commitment outputs are found
    MultipleCommitmentHosts,

    /// commitment method {0} is not supported yet. Please update.
    MethodUnsupported(CloseMethod),

    #[from]
    #[display(inner)]
    Mpc(mpc::Error),

    #[from]
    #[display(inner)]
    Lnpbp4Psbt(Lnpbp4PsbtError),

    #[from]
    #[display(inner)]
    TapretKey(TapretKeyError),

    #[from]
    #[display(inner)]
    OpretKey(OpretKeyError),

    #[from]
    #[display(inner)]
    TaprootBuilder(UnfinalizedTree),
}

pub trait PsbtDbc {
    fn dbc_conclude(
        &mut self,
        method: CloseMethod,
    ) -> Result<Anchor<mpc::MerkleBlock>, DbcPsbtError>;
}

impl PsbtDbc for Psbt {
    fn dbc_conclude(
        &mut self,
        method: CloseMethod,
    ) -> Result<Anchor<mpc::MerkleBlock>, DbcPsbtError> {
        if self
            .outputs
            .iter()
            .filter(|output| output.is_tapret_host() | output.is_opret_host())
            .count()
            > 1
        {
            return Err(DbcPsbtError::MultipleCommitmentHosts);
        }

        let (_, output) = self
            .outputs
            .iter_mut()
            .enumerate()
            .find(|(_, output)| {
                (output.is_tapret_host() && method == CloseMethod::TapretFirst)
                    | (output.is_opret_host() && method == CloseMethod::OpretFirst)
            })
            .ok_or(DbcPsbtError::NoHostOutput)?;

        let messages = output.lnpbp4_message_map()?;
        let min_depth =
            u5::with(output.lnpbp4_min_tree_depth().unwrap_or(PSBT_OUT_LNPBP4_MIN_TREE_DEPTH));
        let source = mpc::MultiSource {
            min_depth,
            messages,
            static_entropy: None,
        };
        let merkle_tree = mpc::MerkleTree::try_commit(&source)?;
        let entropy = merkle_tree.entropy();
        output.set_lnpbp4_entropy(entropy)?;
        let commitment = merkle_tree.commitment_id();

        // 2. Depending on the method modify output which is necessary to modify
        // TODO: support non-empty tap trees
        let proof = if method == CloseMethod::TapretFirst {
            if output.tap_tree.is_some() {
                return Err(DbcPsbtError::TapTreeNonEmpty);
            }
            let tapret_commitment = &TapretCommitment::with(commitment, 0);
            let script_commitment = TapScript::commit(tapret_commitment);

            let commitment_leaf = LeafInfo::tap_script(u7::with(0), script_commitment.clone());
            let mut builder = TapTreeBuilder::new();
            builder.push_leaf(commitment_leaf).expect("builder is complete");

            let tap_tree = builder.finish()?;
            let internal_pk = output.tap_internal_key.ok_or(DbcPsbtError::NoInternalKey)?;
            let tapret_proof = TapretProof {
                path_proof: TapretPathProof::root(tapret_commitment.nonce),
                internal_pk,
            };

            output.tap_tree = Some(tap_tree.clone());

            // let merkle_root = tap_tree.merkle_root();
            let merkle_root: TapNodeHash = TapLeafHash::with_tap_script(&script_commitment).into();
            output.set_tapret_commitment(commitment, &tapret_proof.path_proof)?;
            output.script = ScriptPubkey::p2tr(internal_pk, Some(merkle_root));
            Proof::TapretFirst(tapret_proof)
        } else if method == CloseMethod::OpretFirst {
            output.set_opret_commitment(commitment)?;
            output.script = ScriptPubkey::op_return(&commitment.to_byte_array());
            Proof::OpretFirst
        } else {
            return Err(DbcPsbtError::MethodUnsupported(method));
        };

        let anchor = Anchor {
            txid: Tx::from(self.to_unsigned_tx()).txid(),
            mpc_proof: mpc::MerkleBlock::from(merkle_tree),
            dbc_proof: proof,
        };

        Ok(anchor)
    }
}

// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2023 Dr Maxim Orlovsky. All rights reserved.
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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::num::NonZeroU32;

use bc::{Outpoint, Txid};

use crate::derive::DeriveSpk;
use crate::NormalIndex;

pub struct WalletDescr<D: DeriveSpk> {
    script_pubkey: D,
    keychains: BTreeSet<NormalIndex>,
}

pub struct WalletData {
    pub name: String,
    pub tx_annotations: BTreeMap<Txid, String>,
    pub txout_annotations: BTreeMap<Outpoint, String>,
}

pub struct WalletCache {
    last_used: NormalIndex,
    headers: HashMap<NonZeroU32, BlockInfo>,
    tx: HashMap<Txid, TxInfo>,
    utxo: HashMap<Outpoint, UtxoInfo>,
    spent: HashMap<Outpoint, TxoInfo>,
    addr: HashMap<(NormalIndex, NormalIndex), AddrInfo>,
}

pub struct Wallet<D: DeriveSpk> {
    descr: WalletDescr<D>,
    data: WalletData,
    cache: WalletCache,
}

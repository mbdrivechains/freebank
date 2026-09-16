use std::collections::{BTreeMap, HashMap, HashSet};

use fallible_iterator::FallibleIterator as _;
use futures::Stream;
use heed::types::SerdeBincode;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sneed::{DatabaseUnique, RoDatabaseUnique, RoTxn, RwTxn, UnitKey};

use crate::{
    authorization::Authorization,
    types::{
        Address, AmountOverflowError, Authorized, AuthorizedTransaction,
        BitAssetId, BlockHash, Body, FilledOutput, FilledOutputContent,
        FilledTransaction, GetAddress as _, GetBitcoinValue as _, Header,
        InPoint, M6id, OutPoint, OutPointKey, OutputContent, SpentOutput,
        Transaction, TxData, VERSION, Verify as _, Version, WithdrawalBundle,
        WithdrawalBundleStatus, proto::mainchain::TwoWayPegData,
    },
    util::Watchable,
};

mod amm;
pub mod bitassets;
mod block;
mod dutch_auction;
pub mod error;
mod rollback;
mod two_way_peg_data;
#[cfg(test)]
mod zero_input_replay_tests;

pub use amm::{AmmPair, PoolState as AmmPoolState};
pub use bitassets::SeqId as BitAssetSeqId;
pub use dutch_auction::DutchAuctionState;
pub use error::Error;
use rollback::{HeightStamped, RollBack};

pub const WITHDRAWAL_BUNDLE_FAILURE_GAP: u32 = 4;

/// Prevalidated block data containing computed values from validation
/// to avoid redundant computation during connection
pub struct PrevalidatedBlock {
    pub filled_transactions: Vec<FilledTransaction>,
    pub computed_merkle_root: crate::types::MerkleRoot,
    pub total_fees: bitcoin::Amount,
    pub coinbase_value: bitcoin::Amount,
    pub next_height: u32, // Precomputed next height to avoid DB read in write txn
}

/// Information we have regarding a withdrawal bundle
#[derive(Debug, Deserialize, Serialize)]
enum WithdrawalBundleInfo {
    /// Withdrawal bundle is known
    Known(WithdrawalBundle),
    /// Withdrawal bundle is unknown but unconfirmed / failed
    Unknown,
    /// If an unknown withdrawal bundle is confirmed, ALL UTXOs are
    /// considered spent.
    UnknownConfirmed {
        spend_utxos: BTreeMap<OutPoint, FilledOutput>,
    },
}

type WithdrawalBundlesDb = DatabaseUnique<
    SerdeBincode<M6id>,
    SerdeBincode<(
        WithdrawalBundleInfo,
        RollBack<HeightStamped<WithdrawalBundleStatus>>,
    )>,
>;

#[derive(Clone)]
pub struct State {
    /// Current tip
    tip: DatabaseUnique<UnitKey, SerdeBincode<BlockHash>>,
    /// Current height
    height: DatabaseUnique<UnitKey, SerdeBincode<u32>>,
    /// Associates ordered pairs of BitAssets to their AMM pool states
    amm_pools: amm::PoolsDb,
    bitassets: bitassets::Dbs,
    /// Associates Dutch auction sequence numbers with auction state
    dutch_auctions: dutch_auction::Db,
    utxos: DatabaseUnique<OutPointKey, SerdeBincode<FilledOutput>>,
    stxos: DatabaseUnique<OutPointKey, SerdeBincode<SpentOutput>>,
    /// Pending withdrawal bundle. MUST exist in withdrawal_bundles
    pending_withdrawal_bundle: DatabaseUnique<UnitKey, SerdeBincode<M6id>>,
    /// Latest failed (known) withdrawal bundle
    latest_failed_withdrawal_bundle:
        DatabaseUnique<UnitKey, SerdeBincode<RollBack<HeightStamped<M6id>>>>,
    /// Withdrawal bundles and their status.
    /// Some withdrawal bundles may be unknown.
    /// in which case they are `None`.
    withdrawal_bundles: WithdrawalBundlesDb,
    /// Deposit blocks and the height at which they were applied, keyed sequentially
    deposit_blocks: DatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    >,
    /// Withdrawal bundle event blocks and the height at which they were applied, keyed sequentially
    withdrawal_bundle_event_blocks: DatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    >,
    _version: DatabaseUnique<UnitKey, SerdeBincode<Version>>,
}

impl State {
    pub const NUM_DBS: u32 = bitassets::Dbs::NUM_DBS + 12;

    pub fn new(env: &sneed::Env) -> Result<Self, Error> {
        let mut rwtxn = env.write_txn()?;
        let tip = DatabaseUnique::create(env, &mut rwtxn, "tip")?;
        let height = DatabaseUnique::create(env, &mut rwtxn, "height")?;
        let amm_pools = DatabaseUnique::create(env, &mut rwtxn, "amm_pools")?;
        let bitassets = bitassets::Dbs::new(env, &mut rwtxn)?;
        let dutch_auctions =
            DatabaseUnique::create(env, &mut rwtxn, "dutch_auctions")?;
        let utxos = DatabaseUnique::create(env, &mut rwtxn, "utxos")?;
        let stxos = DatabaseUnique::create(env, &mut rwtxn, "stxos")?;
        let pending_withdrawal_bundle = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "pending_withdrawal_bundle",
        )?;
        let latest_failed_withdrawal_bundle = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "latest_failed_withdrawal_bundle",
        )?;
        let withdrawal_bundles =
            DatabaseUnique::create(env, &mut rwtxn, "withdrawal_bundles")?;
        let deposit_blocks =
            DatabaseUnique::create(env, &mut rwtxn, "deposit_blocks")?;
        let withdrawal_bundle_event_blocks = DatabaseUnique::create(
            env,
            &mut rwtxn,
            "withdrawal_bundle_event_blocks",
        )?;
        let version = DatabaseUnique::create(env, &mut rwtxn, "state_version")?;
        if version.try_get(&rwtxn, &())?.is_none() {
            version.put(&mut rwtxn, &(), &*VERSION)?;
        }
        rwtxn.commit()?;
        Ok(Self {
            tip,
            height,
            amm_pools,
            bitassets,
            dutch_auctions,
            utxos,
            stxos,
            pending_withdrawal_bundle,
            latest_failed_withdrawal_bundle,
            withdrawal_bundles,
            withdrawal_bundle_event_blocks,
            deposit_blocks,
            _version: version,
        })
    }

    pub fn amm_pools(&self) -> &amm::RoPoolsDb {
        &self.amm_pools
    }

    pub fn bitassets(&self) -> &bitassets::Dbs {
        &self.bitassets
    }

    pub fn deposit_blocks(
        &self,
    ) -> &RoDatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    > {
        &self.deposit_blocks
    }

    pub fn dutch_auctions(&self) -> &dutch_auction::RoDb {
        &self.dutch_auctions
    }

    pub fn stxos(
        &self,
    ) -> &RoDatabaseUnique<OutPointKey, SerdeBincode<SpentOutput>> {
        &self.stxos
    }

    pub fn withdrawal_bundle_event_blocks(
        &self,
    ) -> &RoDatabaseUnique<
        SerdeBincode<u32>,
        SerdeBincode<(bitcoin::BlockHash, u32)>,
    > {
        &self.withdrawal_bundle_event_blocks
    }

    pub fn try_get_tip(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<BlockHash>, Error> {
        let tip = self.tip.try_get(rotxn, &())?;
        Ok(tip)
    }

    pub fn try_get_height(&self, rotxn: &RoTxn) -> Result<Option<u32>, Error> {
        let height = self.height.try_get(rotxn, &())?;
        Ok(height)
    }

    pub fn get_utxos(
        &self,
        rotxn: &RoTxn,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let utxos: HashMap<OutPoint, FilledOutput> = self
            .utxos
            .iter(rotxn)?
            .map(|(key, output)| Ok((key.to_outpoint(), output)))
            .collect()?;
        Ok(utxos)
    }

    pub fn get_utxos_by_addresses(
        &self,
        rotxn: &RoTxn,
        addresses: &HashSet<Address>,
    ) -> Result<HashMap<OutPoint, FilledOutput>, Error> {
        let utxos: HashMap<OutPoint, FilledOutput> = self
            .utxos
            .iter(rotxn)?
            .filter(|(_, output)| Ok(addresses.contains(&output.address)))
            .map(|(key, output)| Ok((key.to_outpoint(), output)))
            .collect()?;
        Ok(utxos)
    }

    /// Get the latest failed withdrawal bundle, and the height at which it failed
    pub fn get_latest_failed_withdrawal_bundle(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<(u32, M6id)>, Error> {
        let Some(latest_failed_m6id) =
            self.latest_failed_withdrawal_bundle.try_get(rotxn, &())?
        else {
            return Ok(None);
        };
        let latest_failed_m6id = latest_failed_m6id.latest().value;
        let (_bundle, bundle_status) = self.withdrawal_bundles.try_get(rotxn, &latest_failed_m6id)?
            .unwrap_or_else(||
                panic!("Inconsistent DBs: latest failed m6id {latest_failed_m6id} should exist in withdrawal_bundles")
            );
        let failed_height = bundle_status
            .iter()
            .rev()
            .find_map(|status| match status.value {
                WithdrawalBundleStatus::Failed => Some(status.height),
                WithdrawalBundleStatus::Confirmed
                | WithdrawalBundleStatus::Dropped
                | WithdrawalBundleStatus::Pending
                | WithdrawalBundleStatus::Submitted
                | WithdrawalBundleStatus::SubmittedUnexpected => None,
            })
            .unwrap_or_else(|| {
                panic!("missing failure status for {latest_failed_m6id}")
            });
        Ok(Some((failed_height, latest_failed_m6id)))
    }

    pub fn fill_transaction(
        &self,
        rotxn: &RoTxn,
        transaction: &Transaction,
    ) -> Result<FilledTransaction, Error> {
        let mut spent_utxos = Vec::with_capacity(transaction.inputs.len());
        for input in &transaction.inputs {
            let key = OutPointKey::from_outpoint(input);
            let utxo = self
                .utxos
                .try_get(rotxn, &key)?
                .ok_or(error::NoUtxo { outpoint: *input })?;
            spent_utxos.push(utxo);
        }
        Ok(FilledTransaction {
            spent_utxos,
            transaction: transaction.clone(),
        })
    }

    /// Fill a transaction that has already been applied
    pub fn fill_transaction_from_stxos(
        &self,
        rotxn: &RoTxn,
        tx: Transaction,
    ) -> Result<FilledTransaction, Error> {
        let txid = tx.txid();
        let mut spent_utxos = Vec::with_capacity(tx.inputs.len());
        // fill inputs last-to-first
        for (vin, input) in tx.inputs.iter().enumerate().rev() {
            let key = OutPointKey::from_outpoint(input);
            let stxo = self
                .stxos
                .try_get(rotxn, &key)?
                .ok_or(Error::NoStxo { outpoint: *input })?;
            assert_eq!(
                stxo.inpoint,
                InPoint::Regular {
                    txid,
                    vin: vin as u32
                }
            );
            spent_utxos.push(stxo.output);
        }
        spent_utxos.reverse();
        Ok(FilledTransaction {
            spent_utxos,
            transaction: tx,
        })
    }

    pub fn fill_authorized_transaction(
        &self,
        rotxn: &RoTxn,
        transaction: AuthorizedTransaction,
    ) -> Result<Authorized<FilledTransaction>, Error> {
        let filled_tx =
            self.fill_transaction(rotxn, &transaction.transaction)?;
        let authorizations = transaction.authorizations;
        Ok(Authorized {
            transaction: filled_tx,
            authorizations,
        })
    }

    /// Get pending withdrawal bundle and block height
    pub fn try_get_pending_withdrawal_bundle(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<(WithdrawalBundle, u32)>, Error> {
        let Some(m6id) = self.pending_withdrawal_bundle.try_get(rotxn, &())?
        else {
            return Ok(None);
        };
        let (bundle_info, bundle_status) =
            self.withdrawal_bundles.get(rotxn, &m6id)?;
        let bundle = match bundle_info {
            WithdrawalBundleInfo::Known(bundle) => bundle,
            WithdrawalBundleInfo::Unknown
            | WithdrawalBundleInfo::UnknownConfirmed { spend_utxos: _ } => {
                return Err(error::PendingWithdrawalBundleUnknown(m6id).into());
            }
        };
        let height = bundle_status.latest().height;
        Ok(Some((bundle, height)))
    }

    /// Check that
    /// * If the tx is a BitAsset reservation, then the number of bitasset
    ///   reservations in the outputs is exactly one more than the number of
    ///   bitasset reservations in the inputs.
    /// * If the tx is a BitAsset
    ///   registration, then the number of bitasset reservations in the outputs
    ///   is exactly one less than the number of bitasset reservations in the
    ///   inputs.
    /// * Otherwise, the number of bitasset reservations in the outputs
    ///   is exactly equal to the number of bitasset reservations in the inputs.
    pub fn validate_reservations(
        &self,
        tx: &FilledTransaction,
    ) -> Result<(), Error> {
        let n_reservation_inputs: usize = tx.spent_reservations().count();
        let n_reservation_outputs: usize = tx.reservation_outputs().count();
        if tx.is_reservation() {
            if n_reservation_outputs == n_reservation_inputs + 1 {
                return Ok(());
            }
        } else if tx.is_registration() {
            if n_reservation_inputs == n_reservation_outputs + 1 {
                return Ok(());
            }
        } else if n_reservation_inputs == n_reservation_outputs {
            return Ok(());
        }
        Err(Error::UnbalancedReservations {
            n_reservation_inputs,
            n_reservation_outputs,
        })
    }

    /** Check that
     *  * If the tx is a BitAsset registration, then
     *    * The number of BitAsset control coins in the outputs is exactly
     *      one more than the number of BitAsset control coins in the
     *      inputs
     *    * The number of BitAsset outputs is at least
     *      * The number of unique BitAsset inputs,
     *        if the initial supply is zero
     *      * One more than the number of unique BitAsset inputs,
     *        if the initial supply is nonzero.
     *    * The newly registered BitAsset must have been unregistered,
     *      prior to the registration tx.
     *    * The last output must be a BitAsset control coin
     *    * If the initial supply is nonzero,
     *      the second-to-last output must be a BitAsset output
     *    * Otherwise,
     *      * The number of BitAsset control coin outputs is exactly the number
     *        of BitAsset control coin inputs
     *      * The number of BitAsset outputs is at least
     *        the number of unique BitAssets in the inputs.
     *  * If the tx is a BitAsset update, then there must be at least one
     *    BitAsset control coin input and output.
     *  * If the tx is an AMM Burn, then
     *    * There must be at least two unique BitAsset outputs
     *    * The number of unique BitAsset outputs must be at most two more than
     *      the number of unique BitAsset inputs
     *    * The number of unique BitAsset inputs must be at most equal to the
     *      number of unique BitAsset outputs
     *  * If the tx is an AMM Mint, then
     *    * There must be at least two BitAsset inputs
     *    * The number of unique BitAsset outputs must be at most equal to the
     *      number of unique BitAsset inputs
     *    * The number of unique BitAsset inputs must be at most two more than
     *      the number of unique BitAsset outputs.
     *  * If the tx is an AMM Swap, then
     *    * There must be at least one BitAsset input
     *    * The number of unique BitAsset outputs must be one less than,
     *      one greater than, or equal to, the number of unique BitAsset inputs.
     *  * If the tx is a Dutch auction create, then
     *    * There must be at least one unique BitAsset input
     *    * The number of unique BitAsset outputs must be at most equal to the
     *      number of unique BitAsset inputs
     *    * The number of unique BitAsset inputs must be at most one more than
     *      the number of unique BitAsset outputs.
     *  * If the tx is a Dutch auction bid, then
     *    * There must be at least one BitAsset input
     *    * The number of unique BitAsset outputs must be one less than,
     *      one greater than, or equal to, the number of unique BitAsset inputs.
     *  * If the tx is a Dutch auction collect, then
     *    * There must be at least one unique BitAsset output
     *    * The number of unique BitAsset outputs must be at most two more than
     *      the number of unique BitAsset inputs
     *    * The number of unique BitAsset inputs must be at most equal to the
     *      number of unique BitAsset outputs
     * */
    pub fn validate_bitassets(
        &self,
        rotxn: &RoTxn,
        tx: &FilledTransaction,
    ) -> Result<(), Error> {
        // number of unique bitassets in the inputs
        let n_unique_bitasset_inputs: usize = tx
            .spent_bitassets()
            .filter_map(|(_, output)| output.bitasset())
            .unique()
            .count();
        let n_bitasset_control_inputs: usize =
            tx.spent_bitasset_controls().count();
        let n_bitasset_outputs: usize = tx.bitasset_outputs().count();
        let n_unique_bitasset_outputs: usize =
            tx.unique_spent_bitassets().len();
        let n_bitasset_control_outputs: usize =
            tx.bitasset_control_outputs().count();
        if tx.is_update()
            && (n_bitasset_control_inputs < 1 || n_bitasset_control_outputs < 1)
        {
            return Err(error::BitAsset::NoBitAssetsToUpdate.into());
        }
        if tx.is_amm_burn()
            && (n_unique_bitasset_outputs < 2
                || n_unique_bitasset_inputs > n_unique_bitasset_outputs
                || n_unique_bitasset_outputs > n_unique_bitasset_inputs + 2)
        {
            return Err(error::Amm::InvalidBurn.into());
        };
        if tx.is_amm_mint()
            && (n_unique_bitasset_inputs < 2
                || n_unique_bitasset_outputs > n_unique_bitasset_inputs
                || n_unique_bitasset_inputs > n_unique_bitasset_outputs + 2)
        {
            return Err(error::Amm::TooFewBitAssetsToMint.into());
        };
        if (tx.is_amm_swap() || tx.is_dutch_auction_bid())
            && (n_unique_bitasset_inputs < 1
                || !{
                    let min_unique_bitasset_outputs =
                        n_unique_bitasset_inputs.saturating_sub(1);
                    let max_unique_bitasset_outputs =
                        n_unique_bitasset_inputs + 1;
                    (min_unique_bitasset_outputs..=max_unique_bitasset_outputs)
                        .contains(&n_unique_bitasset_outputs)
                })
        {
            let err = error::dutch_auction::Bid::Invalid;
            return Err(Error::DutchAuction(err.into()));
        };
        if tx.is_dutch_auction_create()
            && (n_unique_bitasset_inputs < 1
                || n_unique_bitasset_outputs > n_unique_bitasset_inputs
                || n_unique_bitasset_inputs > n_unique_bitasset_outputs + 1)
        {
            return Err(error::DutchAuction::TooFewBitAssetsToCreate.into());
        };
        if tx.is_dutch_auction_collect()
            && (n_unique_bitasset_outputs < 1
                || n_unique_bitasset_inputs > n_unique_bitasset_outputs
                || n_unique_bitasset_outputs > n_unique_bitasset_inputs + 2)
        {
            let err = error::dutch_auction::Collect::Invalid;
            return Err(Error::DutchAuction(err.into()));
        };
        if let Some(TxData::BitAssetRegistration {
            name_hash,
            revealed_nonce,
            initial_supply,
            ..
        }) = tx.data()
        {
            if n_bitasset_control_outputs != n_bitasset_control_inputs + 1 {
                return Err(Error::UnbalancedBitAssetControls {
                    n_bitasset_control_inputs,
                    n_bitasset_control_outputs,
                });
            };
            if !tx
                .outputs()
                .last()
                .is_some_and(|last_output| last_output.is_bitasset_control())
            {
                return Err(Error::LastOutputNotControlCoin);
            }
            if *initial_supply == 0 {
                if n_bitasset_outputs < n_unique_bitasset_inputs {
                    return Err(Error::UnbalancedBitAssets {
                        n_unique_bitasset_inputs,
                        n_bitasset_outputs,
                    });
                }
            } else {
                if n_bitasset_outputs < n_unique_bitasset_inputs + 1 {
                    return Err(Error::UnbalancedBitAssets {
                        n_unique_bitasset_inputs,
                        n_bitasset_outputs,
                    });
                }
                let outputs = tx.outputs();
                let second_to_last_output = outputs.get(outputs.len() - 2);
                if !second_to_last_output
                    .is_some_and(|s2l_output| s2l_output.is_bitasset())
                {
                    return Err(Error::SecondLastOutputNotBitAsset);
                }
            }
            let bitasset_id = BitAssetId(*name_hash);
            // A registration must burn the reservation that commits to it,
            // i.e. a spent reservation whose commitment equals
            // keyed_hash(revealed_nonce, name_hash). Without this check,
            // `apply_registration` would later fail to find the reservation
            // to burn.
            {
                let implied_commitment =
                    blake3::keyed_hash(revealed_nonce, name_hash).into();
                let burns_matching_reservation =
                    tx.spent_reservations().any(|(_, filled_output)| {
                        filled_output.reservation_commitment()
                            == Some(&implied_commitment)
                    });
                if !burns_matching_reservation {
                    return Err(
                        error::BitAsset::NoReservationForRegistration {
                            bitasset: bitasset_id,
                        }
                        .into(),
                    );
                }
            }
            if self
                .bitassets
                .try_get_bitasset(rotxn, &bitasset_id)?
                .is_some()
            {
                return Err(Error::BitAssetAlreadyRegistered {
                    name_hash: *name_hash,
                });
            };
            Ok(())
        } else {
            if n_bitasset_control_outputs != n_bitasset_control_inputs {
                return Err(Error::UnbalancedBitAssetControls {
                    n_bitasset_control_inputs,
                    n_bitasset_control_outputs,
                });
            };
            if n_bitasset_outputs < n_unique_bitasset_inputs {
                return Err(Error::UnbalancedBitAssets {
                    n_unique_bitasset_inputs,
                    n_bitasset_outputs,
                });
            }
            if n_unique_bitasset_inputs == 0 && n_bitasset_outputs != 0 {
                return Err(Error::UnbalancedBitAssets {
                    n_unique_bitasset_inputs,
                    n_bitasset_outputs,
                });
            }
            Ok(())
        }
    }

    /// FreeBank consensus gate (operator decision 2026-09-15). The chassis
    /// token/market features — BitAssets (reservation/registration/update),
    /// the AMM (mint/burn/swap) and Dutch auctions (create/bid/collect) — are
    /// disabled on this chain. Reject any transaction whose `data` is one of
    /// those variants, and any transaction that CREATES a disabled coin (raw
    /// on-wire output content) or SPENDS one (filled content of an input — a
    /// coin of those kinds cannot exist after genesis, but guard both).
    ///
    /// This is called from [`Self::validate_filled_transaction`], the single
    /// choke point on BOTH the live block-connect path (`block::prevalidate`)
    /// and the mempool path (`Self::validate_transaction`). The coinbase, which
    /// is not a transaction and does not pass here, is gated structurally in
    /// `block::connect_prevalidated`'s coinbase whitelist.
    ///
    /// Every match is exhaustive (no wildcard) so that a future credit-layer
    /// variant appended to any of these enums forces a compile error here
    /// rather than being silently admitted.
    fn validate_chassis_features_disabled(
        tx: &FilledTransaction,
    ) -> Result<(), Error> {
        // 1. Transaction data variant.
        match &tx.transaction.data {
            None => {}
            Some(TxData::AmmBurn { .. })
            | Some(TxData::AmmMint { .. })
            | Some(TxData::AmmSwap { .. }) => return Err(Error::DisabledAmm),
            Some(TxData::BitAssetReservation { .. })
            | Some(TxData::BitAssetRegistration { .. })
            | Some(TxData::BitAssetMint(_))
            | Some(TxData::BitAssetUpdate(_)) => {
                return Err(Error::DisabledBitAsset);
            }
            Some(TxData::DutchAuctionCreate(_))
            | Some(TxData::DutchAuctionBid { .. })
            | Some(TxData::DutchAuctionCollect { .. }) => {
                return Err(Error::DisabledDutchAuction);
            }
        }
        // 2. Raw output content on the wire.
        for output in tx.outputs().iter() {
            match &output.content {
                OutputContent::Bitcoin(_) | OutputContent::Withdrawal(_) => {}
                OutputContent::AmmLpToken(_) => return Err(Error::DisabledAmm),
                OutputContent::BitAsset(_)
                | OutputContent::BitAssetControl
                | OutputContent::BitAssetReservation => {
                    return Err(Error::DisabledBitAsset);
                }
                OutputContent::DutchAuctionReceipt => {
                    return Err(Error::DisabledDutchAuction);
                }
            }
        }
        // 3. Filled content of spent inputs.
        for (_, spent_output) in tx.spent_inputs() {
            match &spent_output.content {
                FilledOutputContent::Bitcoin(_)
                | FilledOutputContent::BitcoinWithdrawal(_) => {}
                FilledOutputContent::AmmLpToken { .. } => {
                    return Err(Error::DisabledAmm);
                }
                FilledOutputContent::BitAsset(..)
                | FilledOutputContent::BitAssetControl(_)
                | FilledOutputContent::BitAssetReservation(..) => {
                    return Err(Error::DisabledBitAsset);
                }
                FilledOutputContent::DutchAuctionReceipt(_) => {
                    return Err(Error::DisabledDutchAuction);
                }
            }
        }
        Ok(())
    }

    /// FreeBank consensus rule R2 (BIP30-style): an outpoint key that is
    /// about to be created must not already exist in `utxos` (unspent) OR in
    /// `stxos` (spent). `connect_prevalidated` writes created outputs with an
    /// unchecked `put` and `disconnect_tip` deletes them by key / restores
    /// spent ones from `stxos`, so a re-created key would make undo inexact
    /// (the UTXO set would depend on reorg history) or impossible (`NoUtxo` /
    /// `NoStxo`). Keys of different `OutPoint` variants never collide (the
    /// borsh variant tag is the first key byte).
    pub(crate) fn ensure_outpoint_is_new(
        &self,
        rotxn: &RoTxn,
        outpoint: &OutPoint,
    ) -> Result<(), Error> {
        let key = OutPointKey::from_outpoint(outpoint);
        if self.utxos.contains_key(rotxn, &key)?
            || self.stxos.contains_key(rotxn, &key)?
        {
            return Err(Error::OutPointAlreadyExists {
                outpoint: *outpoint,
            });
        }
        Ok(())
    }

    /// Validates a filled transaction, and returns the fee
    pub fn validate_filled_transaction(
        &self,
        rotxn: &RoTxn,
        tx: &FilledTransaction,
    ) -> Result<bitcoin::Amount, Error> {
        // FreeBank consensus rule R1: a transaction must spend at least one
        // input. The coinbase is not a `Transaction` and does not pass here.
        // Without this, a zero-input tx has a txid that is a pure function of
        // its outputs/memo, so the identical tx can be mined again after it
        // leaves the mempool, re-creating `Regular{txid,vout}` keys. With it,
        // every txid commits to at least one outpoint that can be spent only
        // once, so `Regular` output keys are unique by construction (R2 below
        // is then defence in depth for them, and load-bearing for coinbase
        // keys, see `block::prevalidate`).
        if tx.transaction.inputs.is_empty() {
            return Err(Error::NoInputs { txid: tx.txid() });
        }
        // FreeBank: reject disabled chassis token/market families first, in
        // both the mempool and block-connect paths (this fn is the shared
        // choke point). Money-path txs (Bitcoin transfers, deposits,
        // withdrawals) are untouched.
        let () = Self::validate_chassis_features_disabled(tx)?;
        let () = self.validate_reservations(tx)?;
        let () = self.validate_bitassets(rotxn, tx)?;
        let fee = tx.bitcoin_fee()?;
        for (outpoint, output) in tx.spent_inputs() {
            // a withdrawal output is committed to a bundle and can only be
            // spent by the bundle, never by a transaction
            if output.content.is_withdrawal() {
                return Err(Error::SpendWithdrawalOutput {
                    outpoint: *outpoint,
                });
            }
        }
        // FreeBank consensus rule R2 for transaction outputs (see
        // `ensure_outpoint_is_new`). Runs on the mempool path and, via
        // `block::prevalidate`, against the pre-block state on connect.
        let txid = tx.txid();
        for vout in 0..tx.transaction.outputs.len() {
            let outpoint = OutPoint::Regular {
                txid,
                vout: vout as u32,
            };
            let () = self.ensure_outpoint_is_new(rotxn, &outpoint)?;
        }
        Ok(fee)
    }

    pub fn validate_transaction(
        &self,
        rotxn: &RoTxn,
        transaction: &AuthorizedTransaction,
    ) -> Result<bitcoin::Amount, Error> {
        let filled_transaction =
            self.fill_transaction(rotxn, &transaction.transaction)?;
        for (authorization, spent_utxo) in transaction
            .authorizations
            .iter()
            .zip(filled_transaction.spent_utxos.iter())
        {
            if authorization.get_address() != spent_utxo.address {
                return Err(Error::WrongPubKeyForAddress);
            }
        }
        let () = Authorization::verify_transaction(transaction)
            .map_err(Error::Authorization)?;
        let fee =
            self.validate_filled_transaction(rotxn, &filled_transaction)?;
        Ok(fee)
    }

    pub fn get_last_deposit_block_hash(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<bitcoin::BlockHash>, Error> {
        let block_hash = self
            .deposit_blocks
            .last(rotxn)?
            .map(|(_, (block_hash, _))| block_hash);
        Ok(block_hash)
    }

    pub fn get_last_withdrawal_bundle_event_block_hash(
        &self,
        rotxn: &RoTxn,
    ) -> Result<Option<bitcoin::BlockHash>, Error> {
        let block_hash = self
            .withdrawal_bundle_event_blocks
            .last(rotxn)?
            .map(|(_, (block_hash, _))| block_hash);
        Ok(block_hash)
    }

    /// Get total sidechain wealth in Bitcoin
    pub fn sidechain_wealth(
        &self,
        rotxn: &RoTxn,
    ) -> Result<bitcoin::Amount, Error> {
        let mut total_deposit_utxo_value = bitcoin::Amount::ZERO;
        self.utxos.iter(rotxn)?.map_err(Error::from).for_each(
            |(outpoint_key, output)| {
                let outpoint = outpoint_key.to_outpoint();
                if let OutPoint::Deposit(_) = outpoint {
                    total_deposit_utxo_value = total_deposit_utxo_value
                        .checked_add(output.get_bitcoin_value())
                        .ok_or(AmountOverflowError)?;
                }
                Ok::<_, Error>(())
            },
        )?;
        let mut total_deposit_stxo_value = bitcoin::Amount::ZERO;
        let mut total_withdrawal_stxo_value = bitcoin::Amount::ZERO;
        self.stxos.iter(rotxn)?.map_err(Error::from).for_each(
            |(outpoint_key, spent_output)| {
                let outpoint = outpoint_key.to_outpoint();
                if let OutPoint::Deposit(_) = outpoint {
                    total_deposit_stxo_value = total_deposit_stxo_value
                        .checked_add(spent_output.output.get_bitcoin_value())
                        .ok_or(AmountOverflowError)?;
                }
                if let InPoint::Withdrawal { .. } = spent_output.inpoint {
                    total_withdrawal_stxo_value = total_withdrawal_stxo_value
                        .checked_add(spent_output.output.get_bitcoin_value())
                        .ok_or(AmountOverflowError)?;
                }
                Ok::<_, Error>(())
            },
        )?;
        let total_wealth: bitcoin::Amount = total_deposit_utxo_value
            .checked_add(total_deposit_stxo_value)
            .ok_or(AmountOverflowError)?
            .checked_sub(total_withdrawal_stxo_value)
            .ok_or(AmountOverflowError)?;
        Ok(total_wealth)
    }

    pub fn validate_block(
        &self,
        rotxn: &RoTxn,
        header: &Header,
        body: &Body,
    ) -> Result<bitcoin::Amount, Error> {
        block::validate(self, rotxn, header, body)
    }

    pub fn connect_block(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<(), Error> {
        block::connect(self, rwtxn, header, body)
    }

    pub fn disconnect_tip(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<(), Error> {
        block::disconnect_tip(self, rwtxn, header, body)
    }

    pub fn connect_two_way_peg_data(
        &self,
        rwtxn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
    ) -> Result<(), Error> {
        two_way_peg_data::connect(self, rwtxn, two_way_peg_data)
    }

    pub fn disconnect_two_way_peg_data(
        &self,
        rwtxn: &mut RwTxn,
        two_way_peg_data: &TwoWayPegData,
    ) -> Result<(), Error> {
        two_way_peg_data::disconnect(self, rwtxn, two_way_peg_data)
    }

    pub fn prevalidate_block(
        &self,
        rotxn: &RoTxn,
        header: &Header,
        body: &Body,
    ) -> Result<PrevalidatedBlock, Error> {
        block::prevalidate(self, rotxn, header, body)
    }

    pub fn connect_prevalidated_block(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
        prevalidated: PrevalidatedBlock,
    ) -> Result<(), Error> {
        block::connect_prevalidated(self, rwtxn, header, body, prevalidated)
    }

    pub fn apply_block(
        &self,
        rwtxn: &mut RwTxn,
        header: &Header,
        body: &Body,
    ) -> Result<(), Error> {
        let prevalidated = self.prevalidate_block(rwtxn, header, body)?;
        self.connect_prevalidated_block(rwtxn, header, body, prevalidated)?;
        Ok(())
    }
}

impl Watchable<()> for State {
    type WatchStream = impl Stream<Item = ()>;

    /// Get a signal that notifies whenever the tip changes
    fn watch(&self) -> Self::WatchStream {
        tokio_stream::wrappers::WatchStream::new(self.tip.watch().clone())
    }
}

#[cfg(test)]
mod test {
    use bitcoin::hashes::Hash as _;
    use ed25519_dalek::SigningKey;

    use crate::{
        authorization,
        state::{Error, State, error},
        types::{
            Address, AssetId, AuthorizedTransaction, BitAssetData, BitAssetId,
            Body, DutchAuctionId, FilledOutput, FilledOutputContent,
            FilledTransaction, Hash, Header, InPoint, OutPoint, OutPointKey,
            Output, OutputContent, SpentOutput, Transaction, TxData, Txid,
            VerifyingKey, WithdrawalOutputContent,
        },
    };

    fn temp_dir(test_name: &str) -> anyhow::Result<temp_dir::TempDir> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let res = temp_dir::TempDir::with_prefix(format!(
            "bitassets-{test_name}-{}-{nanos}",
            std::process::id()
        ))?;
        Ok(res)
    }

    // open a fresh state-backed env in a unique temp dir
    pub fn temp_env(
        test_name: &str,
    ) -> anyhow::Result<(temp_dir::TempDir, sneed::Env)> {
        let temp_dir = temp_dir(test_name)?;
        let mut opts = heed::EnvOpenOptions::new();
        opts.map_size(64 * 1024 * 1024).max_dbs(State::NUM_DBS);
        let env = unsafe { sneed::Env::open(&opts, temp_dir.path()) }?;
        Ok((temp_dir, env))
    }

    pub fn fresh_state(
        test_name: &str,
    ) -> anyhow::Result<(temp_dir::TempDir, sneed::Env, State)> {
        let (temp_dir, env) = temp_env(test_name)?;
        let state = State::new(&env)?;
        Ok((temp_dir, env, state))
    }

    /// Create a bitcoin filled output
    pub fn bitcoin_filled_output(address: Address, sats: u64) -> FilledOutput {
        FilledOutput::new_bitcoin_value(
            address,
            bitcoin::Amount::from_sat(sats),
        )
    }

    /// Fund `address` with a single bitcoin UTXO of `value` sats, returning its
    /// outpoint.
    fn fund(
        env: &sneed::Env,
        state: &State,
        address: Address,
        value_sats: u64,
    ) -> OutPoint {
        let outpoint = OutPoint::Regular {
            txid: Default::default(),
            vout: 0,
        };
        let output = bitcoin_filled_output(address, value_sats);
        let mut rwtxn = env.write_txn().unwrap();
        state
            .utxos
            .put(&mut rwtxn, &OutPointKey::from(&outpoint), &output)
            .unwrap();
        rwtxn.commit().unwrap();
        outpoint
    }

    /// Build a BitAsset registration that registers `bitasset_id` with
    /// `revealed_nonce`, while spending a single reservation that commits to
    /// `reservation_commitment`.
    fn registration_tx(
        bitasset_id: BitAssetId,
        revealed_nonce: Hash,
        reservation_commitment: Hash,
        initial_supply: u64,
        bitasset_data: BitAssetData,
    ) -> FilledTransaction {
        let address = Address([0; 20]);
        let mut transaction = Transaction::new(
            vec![OutPoint::Regular {
                txid: Txid([0; 32]),
                vout: 0,
            }],
            vec![
                Output::new(address, OutputContent::BitAsset(initial_supply)),
                Output::new(address, OutputContent::BitAssetControl),
            ],
        );
        transaction.data = Some(TxData::BitAssetRegistration {
            name_hash: bitasset_id.0,
            revealed_nonce,
            bitasset_data: Box::new(bitasset_data),
            initial_supply,
        });
        let reservation = FilledOutput::new(
            address,
            FilledOutputContent::BitAssetReservation(
                Txid([0; 32]),
                reservation_commitment,
            ),
        );
        FilledTransaction {
            transaction,
            spent_utxos: vec![reservation],
        }
    }

    /// A transaction that spends an input without supplying an authorization
    /// for it must be rejected. Otherwise the `zip` of authorizations and
    /// spent UTXOs silently skips the unauthorized input, allowing any UTXO to
    /// be spent without a signature.
    #[test]
    fn validate_transaction_rejects_missing_authorization() -> anyhow::Result<()>
    {
        let (_temp_dir, env, state) = fresh_state("auth_count")?;
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key: VerifyingKey = signing_key.verifying_key().into();
        let address = authorization::get_address(&verifying_key);
        let outpoint = fund(&env, &state, address, 1000);

        let transaction = Transaction::new(
            vec![outpoint],
            vec![bitcoin_filled_output(address, 900).into()],
        );

        // The attack: spend the input while providing no authorization for it.
        let unauthorized = AuthorizedTransaction {
            transaction: transaction.clone(),
            authorizations: Vec::new(),
        };
        let rotxn = env.read_txn()?;
        let err = state
            .validate_transaction(&rotxn, &unauthorized)
            .expect_err("tx with no authorizations must be rejected");
        anyhow::ensure!(
            matches!(
                err,
                Error::Authorization(
                    crate::authorization::Error::NotEnoughAuthorizations
                )
            ),
            "unexpected error: {err:?}"
        );

        // The same transaction with a valid authorization is accepted.
        let authorized =
            authorization::authorize(&[(address, &signing_key)], transaction)?;
        state
            .validate_transaction(&rotxn, &authorized)
            .expect("correctly authorized tx should validate");
        Ok(())
    }

    /// A registration whose spent reservation does not commit to the
    /// registered name must be rejected. Otherwise it passes validation and
    /// later panics in `apply_registration`, which fails to find the
    /// reservation to burn.
    #[test]
    fn validate_bitassets_rejects_registration_without_matching_reservation()
    -> anyhow::Result<()> {
        let (_temp_dir, env, state) = fresh_state("registration")?;
        let rotxn = env.read_txn()?;
        let name_hash = [7; 32];
        let bitasset_id = BitAssetId(name_hash);
        let revealed_nonce: Hash = [3; 32];
        let initial_supply = 123;
        let bitasset_data = || BitAssetData::default();
        let implied_commitment: Hash =
            blake3::keyed_hash(&revealed_nonce, &name_hash).into();

        // The reservation commits to something other than the registered name.
        let mismatched_commitment: Hash = [0; 32];
        assert_ne!(mismatched_commitment, implied_commitment);
        let tx = registration_tx(
            bitasset_id,
            revealed_nonce,
            mismatched_commitment,
            initial_supply,
            bitasset_data(),
        );
        let err = state.validate_bitassets(&rotxn, &tx).expect_err(
            "registration without a matching reservation must be rejected",
        );
        anyhow::ensure!(
            matches!(
                err,
                Error::BitAsset(
                    error::BitAsset::NoReservationForRegistration { bitasset }
                ) if bitasset == bitasset_id
            ),
            "unexpected error: {err:?}"
        );

        // The same registration burning the matching reservation is accepted.
        let tx = registration_tx(
            bitasset_id,
            revealed_nonce,
            implied_commitment,
            initial_supply,
            bitasset_data(),
        );
        state.validate_bitassets(&rotxn, &tx).expect(
            "registration burning the matching reservation should validate",
        );
        Ok(())
    }

    #[test]
    fn cannot_spend_withdrawal_output() -> anyhow::Result<()> {
        let (_temp_dir, env, state) =
            fresh_state("cannot-spend-withdrawal-output")?;
        let main_address = {
            let pkh = bitcoin::PubkeyHash::hash(b"test pubkey");
            bitcoin::Address::p2pkh(pkh, bitcoin::NetworkKind::Test)
                .into_unchecked()
        };
        let withdrawal = FilledOutput {
            address: Address::ALL_ZEROS,
            content: FilledOutputContent::BitcoinWithdrawal(
                WithdrawalOutputContent {
                    value: bitcoin::Amount::from_sat(1000),
                    main_fee: bitcoin::Amount::from_sat(300),
                    main_address,
                },
            ),
            memo: Vec::new(),
        };
        let outpoint = OutPoint::Regular {
            txid: [1; 32].into(),
            vout: 0,
        };
        let tx = FilledTransaction {
            transaction: Transaction {
                inputs: vec![outpoint],
                outputs: vec![
                    bitcoin_filled_output(Address::ALL_ZEROS, 1300).into(),
                ],
                ..Default::default()
            },
            spent_utxos: vec![withdrawal],
        };
        let rotxn = env.read_txn()?;
        assert!(matches!(
            state.validate_filled_transaction(&rotxn, &tx),
            Err(crate::state::Error::SpendWithdrawalOutput { .. })
        ));
        Ok(())
    }

    // ---- FreeBank consensus gate: disabled chassis token/market features ----
    //
    // The BitAssets, AMM and Dutch-auction families are rejected in the single
    // shared validation choke point `validate_filled_transaction` (run by BOTH
    // the mempool path `validate_transaction` and the live block-connect path
    // `block::prevalidate`). These tests assert the EXACT reject reason (a
    // deleted guard must not leave the suite green) at mempool time and at
    // block connect (`State::apply_block`), and that the money path (plain
    // Bitcoin transfers, deposits, withdrawals) still validates.

    const DISABLED_BITASSET: &str =
        "freebank: bitasset transactions are disabled on this chain";
    const DISABLED_AMM: &str =
        "freebank: amm transactions are disabled on this chain";
    const DISABLED_DUTCH_AUCTION: &str =
        "freebank: dutch auction transactions are disabled on this chain";

    fn gate_header(
        prev_side_hash: Option<crate::types::BlockHash>,
        body: &Body,
    ) -> Header {
        Header {
            merkle_root: Body::compute_merkle_root(
                &body.coinbase,
                &body.transactions,
            ),
            prev_side_hash,
            prev_main_hash: bitcoin::BlockHash::from_byte_array([0; 32]),
        }
    }

    /// Build a `FilledTransaction` whose single input is a Bitcoin UTXO, with
    /// the given `data`, `outputs`, and spent-input `content`.
    fn gate_filled_tx(
        data: Option<TxData>,
        outputs: Vec<Output>,
        spent_content: FilledOutputContent,
    ) -> FilledTransaction {
        let address = Address([0; 20]);
        let input = OutPoint::Regular {
            txid: Txid([9; 32]),
            vout: 0,
        };
        let mut transaction = Transaction::new(vec![input], outputs);
        transaction.data = data;
        FilledTransaction {
            transaction,
            spent_utxos: vec![FilledOutput::new(address, spent_content)],
        }
    }

    fn assert_mempool_reject(
        env: &sneed::Env,
        state: &State,
        tx: &FilledTransaction,
        expected: &str,
    ) -> anyhow::Result<()> {
        let rotxn = env.read_txn()?;
        let err = state
            .validate_filled_transaction(&rotxn, tx)
            .expect_err("disabled-feature tx must be rejected at mempool time");
        anyhow::ensure!(
            err.to_string() == expected,
            "unexpected reject reason: {err}"
        );
        Ok(())
    }

    /// Apply a single-transaction block via the LIVE path (`apply_block` =
    /// prevalidate + connect_prevalidated), funding the tx's Bitcoin input
    /// first. Returns the (expected) error.
    fn assert_connect_reject(
        test_name: &str,
        data: TxData,
        expected: &str,
    ) -> anyhow::Result<()> {
        let (_temp_dir, env, state) = fresh_state(test_name)?;
        let address = Address([0; 20]);
        let outpoint = fund(&env, &state, address, 1000);
        let mut transaction = Transaction::new(vec![outpoint], Vec::new());
        transaction.data = Some(data);
        let body = Body {
            coinbase: Vec::new(),
            transactions: vec![transaction],
            authorizations: Vec::new(),
        };
        let header = gate_header(None, &body);
        let mut rwtxn = env.write_txn()?;
        let err = state.apply_block(&mut rwtxn, &header, &body).expect_err(
            "disabled-feature tx must be rejected at block connect",
        );
        drop(rwtxn);
        anyhow::ensure!(
            err.to_string() == expected,
            "unexpected reject reason: {err}"
        );
        Ok(())
    }

    #[test]
    fn gate_mempool_rejects_bitasset() -> anyhow::Result<()> {
        let (_temp_dir, env, state) = fresh_state("gate_mempool_bitasset")?;
        let address = Address([0; 20]);
        let btc_in = || {
            FilledOutputContent::new_bitcoin_value(bitcoin::Amount::from_sat(
                1000,
            ))
        };
        // (1) tx data variant
        assert_mempool_reject(
            &env,
            &state,
            &gate_filled_tx(Some(TxData::BitAssetMint(5)), vec![], btc_in()),
            DISABLED_BITASSET,
        )?;
        // (2) raw output content on the wire
        for content in [
            OutputContent::BitAsset(5),
            OutputContent::BitAssetControl,
            OutputContent::BitAssetReservation,
        ] {
            assert_mempool_reject(
                &env,
                &state,
                &gate_filled_tx(
                    None,
                    vec![Output::new(address, content)],
                    btc_in(),
                ),
                DISABLED_BITASSET,
            )?;
        }
        // (3) filled content of a spent input
        for content in [
            FilledOutputContent::BitAsset(BitAssetId([0; 32]), 5),
            FilledOutputContent::BitAssetControl(BitAssetId([0; 32])),
            FilledOutputContent::BitAssetReservation(Txid([0; 32]), [0; 32]),
        ] {
            assert_mempool_reject(
                &env,
                &state,
                &gate_filled_tx(None, vec![], content),
                DISABLED_BITASSET,
            )?;
        }
        Ok(())
    }

    #[test]
    fn gate_mempool_rejects_amm() -> anyhow::Result<()> {
        let (_temp_dir, env, state) = fresh_state("gate_mempool_amm")?;
        let address = Address([0; 20]);
        let btc_in = || {
            FilledOutputContent::new_bitcoin_value(bitcoin::Amount::from_sat(
                1000,
            ))
        };
        // (1) tx data variant
        assert_mempool_reject(
            &env,
            &state,
            &gate_filled_tx(
                Some(TxData::AmmSwap {
                    amount_spent: 1,
                    amount_receive: 1,
                    pair_asset: AssetId::Bitcoin,
                }),
                vec![],
                btc_in(),
            ),
            DISABLED_AMM,
        )?;
        // (2) raw output content
        assert_mempool_reject(
            &env,
            &state,
            &gate_filled_tx(
                None,
                vec![Output::new(address, OutputContent::AmmLpToken(1))],
                btc_in(),
            ),
            DISABLED_AMM,
        )?;
        // (3) filled content of a spent input
        assert_mempool_reject(
            &env,
            &state,
            &gate_filled_tx(
                None,
                vec![],
                FilledOutputContent::AmmLpToken {
                    asset0: AssetId::Bitcoin,
                    asset1: AssetId::Bitcoin,
                    amount: 1,
                },
            ),
            DISABLED_AMM,
        )?;
        Ok(())
    }

    #[test]
    fn gate_mempool_rejects_dutch_auction() -> anyhow::Result<()> {
        let (_temp_dir, env, state) = fresh_state("gate_mempool_dutch")?;
        let address = Address([0; 20]);
        let btc_in = || {
            FilledOutputContent::new_bitcoin_value(bitcoin::Amount::from_sat(
                1000,
            ))
        };
        // (1) tx data variant
        assert_mempool_reject(
            &env,
            &state,
            &gate_filled_tx(
                Some(TxData::DutchAuctionCollect {
                    asset_offered: AssetId::Bitcoin,
                    asset_receive: AssetId::Bitcoin,
                    amount_offered_remaining: 0,
                    amount_received: 0,
                }),
                vec![],
                btc_in(),
            ),
            DISABLED_DUTCH_AUCTION,
        )?;
        // (2) raw output content
        assert_mempool_reject(
            &env,
            &state,
            &gate_filled_tx(
                None,
                vec![Output::new(address, OutputContent::DutchAuctionReceipt)],
                btc_in(),
            ),
            DISABLED_DUTCH_AUCTION,
        )?;
        // (3) filled content of a spent input
        assert_mempool_reject(
            &env,
            &state,
            &gate_filled_tx(
                None,
                vec![],
                FilledOutputContent::DutchAuctionReceipt(DutchAuctionId(Txid(
                    [0; 32],
                ))),
            ),
            DISABLED_DUTCH_AUCTION,
        )?;
        Ok(())
    }

    #[test]
    fn gate_connect_rejects_bitasset() -> anyhow::Result<()> {
        assert_connect_reject(
            "gate_connect_bitasset",
            TxData::BitAssetMint(5),
            DISABLED_BITASSET,
        )
    }

    #[test]
    fn gate_connect_rejects_amm() -> anyhow::Result<()> {
        assert_connect_reject(
            "gate_connect_amm",
            TxData::AmmSwap {
                amount_spent: 1,
                amount_receive: 1,
                pair_asset: AssetId::Bitcoin,
            },
            DISABLED_AMM,
        )
    }

    #[test]
    fn gate_connect_rejects_dutch_auction() -> anyhow::Result<()> {
        assert_connect_reject(
            "gate_connect_dutch",
            TxData::DutchAuctionCollect {
                asset_offered: AssetId::Bitcoin,
                asset_receive: AssetId::Bitcoin,
                amount_offered_remaining: 0,
                amount_received: 0,
            },
            DISABLED_DUTCH_AUCTION,
        )
    }

    /// The money path is untouched: a plain Bitcoin transfer, a tx spending a
    /// deposit-origin UTXO, and a tx creating a withdrawal output all validate.
    #[test]
    fn gate_allows_money_path() -> anyhow::Result<()> {
        let (_temp_dir, env, state) = fresh_state("gate_allows_money_path")?;
        let address = Address([0; 20]);
        let rotxn = env.read_txn()?;

        // (a) plain Bitcoin transfer
        let btc_transfer = FilledTransaction {
            transaction: Transaction::new(
                vec![OutPoint::Regular {
                    txid: Txid([1; 32]),
                    vout: 0,
                }],
                vec![bitcoin_filled_output(address, 900).into()],
            ),
            spent_utxos: vec![bitcoin_filled_output(address, 1000)],
        };
        state
            .validate_filled_transaction(&rotxn, &btc_transfer)
            .expect("plain Bitcoin transfer must validate");

        // (b) spending a deposit-origin (money-path) input
        let deposit_spend = FilledTransaction {
            transaction: Transaction::new(
                vec![OutPoint::Deposit(bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2; 32]),
                    vout: 0,
                })],
                vec![bitcoin_filled_output(address, 400).into()],
            ),
            spent_utxos: vec![bitcoin_filled_output(address, 500)],
        };
        state
            .validate_filled_transaction(&rotxn, &deposit_spend)
            .expect("spending a deposit must validate");

        // (c) creating a withdrawal output
        let main_address = {
            let pkh = bitcoin::PubkeyHash::hash(b"test pubkey");
            bitcoin::Address::p2pkh(pkh, bitcoin::NetworkKind::Test)
                .into_unchecked()
        };
        let withdrawal_tx = FilledTransaction {
            transaction: Transaction::new(
                vec![OutPoint::Regular {
                    txid: Txid([3; 32]),
                    vout: 0,
                }],
                vec![Output::new(
                    address,
                    OutputContent::Withdrawal(WithdrawalOutputContent {
                        value: bitcoin::Amount::from_sat(400),
                        main_fee: bitcoin::Amount::from_sat(100),
                        main_address,
                    }),
                )],
            ),
            spent_utxos: vec![bitcoin_filled_output(address, 1000)],
        };
        state
            .validate_filled_transaction(&rotxn, &withdrawal_tx)
            .expect("withdrawal output must validate through the gate");
        Ok(())
    }

    #[test]
    fn sidechain_wealth() -> anyhow::Result<()> {
        use std::str::FromStr;

        use bitcoin::hashes::Hash as _;

        let (_temp_dir, env, state) = fresh_state("sidechain-wealth")?;
        {
            let mut rwtxn = env.write_txn()?;

            // One unspent DEPOSIT UTXO: 50 sats.
            let deposit_utxo_op = OutPoint::Deposit(bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )?,
                vout: 0,
            });
            state.utxos.put(
                &mut rwtxn,
                &OutPointKey::from(&deposit_utxo_op),
                &bitcoin_filled_output(Address::ALL_ZEROS, 50),
            )?;

            // Two spent DEPOSIT STXOs: 100 + 100 sats.
            for (i, sats) in [(2u8, 100u64), (3u8, 100u64)] {
                let op = OutPoint::Deposit(bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([i; 32]),
                    vout: 0,
                });
                let stxo = SpentOutput {
                    output: bitcoin_filled_output(Address::ALL_ZEROS, sats),
                    inpoint: InPoint::Regular {
                        txid: [i; 32].into(),
                        vin: 0,
                    },
                };
                state
                    .stxos
                    .put(&mut rwtxn, &OutPointKey::from(&op), &stxo)?;
            }

            // Two WITHDRAWAL STXOs: 10 + 10 sats
            for (i, sats) in [(4u8, 10u64), (5u8, 10u64)] {
                let op = OutPoint::Regular {
                    txid: [i; 32].into(),
                    vout: 0,
                };
                let stxo = SpentOutput {
                    output: bitcoin_filled_output(Address::ALL_ZEROS, sats),
                    inpoint: InPoint::Withdrawal {
                        m6id: crate::types::M6id(
                            bitcoin::Txid::from_byte_array([i; 32]),
                        ),
                    },
                };
                state
                    .stxos
                    .put(&mut rwtxn, &OutPointKey::from(&op), &stxo)?;
            }

            rwtxn.commit()?;
        }

        let rotxn = env.read_txn()?;
        let sidechain_wealth = state.sidechain_wealth(&rotxn)?;

        // Correct value: deposit UTXO 50 + deposit STXOs 200 - withdrawal
        // STXOs 20 = 230 sats.
        let expected_sidechain_wealth = bitcoin::Amount::from_sat(230);
        anyhow::ensure!(
            sidechain_wealth == expected_sidechain_wealth,
            "Expected sidechain wealth ({}), but computed ({})",
            expected_sidechain_wealth,
            sidechain_wealth,
        );
        Ok(())
    }
}

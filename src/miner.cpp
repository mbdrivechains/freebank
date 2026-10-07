// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <miner.h>

#include <token.h>

#include <amount.h>
#include <base58.h>
#include <bmmcache.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/consensus.h>
#include <consensus/tx_verify.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <deposit.h>
#include <hash.h>
#include <house.h>
#include <l1client.h>
#include <validation.h>
#include <net.h>
#include <note.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <policy/withdrawalbundle.h>
#include <primitives/transaction.h>
#include <script/standard.h>
#include <sidechain.h>
#include <sidechainclient.h>
#include <timedata.h>
#include <txdb.h>
#include <util.h>
#include <utilmoneystr.h>
#include <validation.h>
#include <validationinterface.h>
#include <wallet/coincontrol.h>
#include <wallet/fees.h>

#include <algorithm>
#include <queue>
#include <utility>

#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest fee rate of a transaction combined with all
// its ancestors.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockWeight = 0;

static const uint64_t nRefundOutputSize = 34;

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions(const CChainParams& params)
{
    // Block resource limits
    // If neither -blockmaxsize or -blockmaxweight is given, limit to DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    if (gArgs.IsArgSet("-blockmintxfee")) {
        CAmount n = 0;
        ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n);
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions(params)) {}

BlockAssembler::Options BMMTemplateAssemblerOptions()
{
    BlockAssembler::Options options = DefaultOptions(Params());
    const int64_t nCap = gArgs.GetArg("-bmmblockmaxweight", (int64_t)DEFAULT_BMM_BLOCK_MAX_WEIGHT);
    if (nCap > 0 && (size_t)nCap < options.nBlockMaxWeight)
        options.nBlockMaxWeight = nCap;
    return options;
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();
    setBlockWithdrawalIDs.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

// The first transaction of a failed template that the block cannot hold (v0.2.19): the shortest prefix of the
// block's transactions that fails TestBlockValidity ends with it. The template adds packages ancestors first, so
// every prefix is a valid order. Each prefix keeps the refund requests and their in-block ancestors (the coinbase pays
// their refunds) and gets a coinbase that claims exactly its fees, with the witness commitment made again. nullptr if
// the block fails with only those kept transactions, so the fault is not one mempool transaction.
static CTransactionRef FindFirstInvalidTx(const CBlock& block, const std::vector<CAmount>& vTxFees, CBlockIndex* pindexPrev,
                                          bool fCheckBMM, bool fReorg, const CChainParams& chainparams, CValidationState& stateOut)
{
    const size_t n = block.vtx.size() - 1;
    if (n == 0 || vTxFees.size() != block.vtx.size())
        return nullptr;

    std::vector<bool> vKeep(n + 1, false);
    std::map<uint256, size_t> mapPos;
    for (size_t i = 1; i <= n; i++) {
        mapPos[block.vtx[i]->GetHash()] = i;
        for (const CTxOut& o : block.vtx[i]->vout) {
            uint256 id;
            std::vector<unsigned char> vchSig;
            if (o.scriptPubKey.IsWithdrawalRefundRequest(id, vchSig)) {
                vKeep[i] = true;
                break;
            }
        }
    }
    for (size_t i = n; i >= 1; i--) {   // parents come first, so one backward pass marks every ancestor
        if (!vKeep[i]) continue;
        for (const CTxIn& in : block.vtx[i]->vin) {
            auto it = mapPos.find(in.prevout.hash);
            if (it != mapPos.end()) vKeep[it->second] = true;
        }
    }

    CMutableTransaction cb(*block.vtx[0]);
    const int nCommitPos = GetWitnessCommitmentIndex(block);
    if (nCommitPos != -1)
        cb.vout.erase(cb.vout.begin() + nCommitPos);
    CAmount nTxFees = 0;
    for (size_t i = 1; i <= n; i++) nTxFees += vTxFees[i];
    const CAmount nOtherFees = cb.vout[0].nValue - nTxFees;   // deposit fees: not from block transactions

    auto fails = [&](size_t k, CValidationState& state) {
        CBlock b = block;
        b.fChecked = false;
        b.vtx.resize(1);
        CAmount nFees = nOtherFees;
        for (size_t i = 1; i <= n; i++) {
            if (i <= k || vKeep[i]) {
                b.vtx.push_back(block.vtx[i]);
                nFees += vTxFees[i];
            }
        }
        CMutableTransaction c(cb);
        c.vout[0].nValue = nFees;
        b.vtx[0] = MakeTransactionRef(std::move(c));
        GenerateCoinbaseCommitment(b, pindexPrev, chainparams.GetConsensus());
        return !TestBlockValidity(state, chainparams, b, pindexPrev, false, fCheckBMM, fReorg);
    };

    CValidationState state0;
    if (fails(0, state0))
        return nullptr;
    size_t lo = 0, hi = n;   // prefix lo passes, prefix hi fails (the whole template)
    while (hi - lo > 1) {
        const size_t mid = lo + (hi - lo) / 2;
        CValidationState state;
        if (fails(mid, state)) {
            hi = mid;
            stateOut = state;
        } else {
            lo = mid;
        }
    }
    if (hi == n)
        fails(n, stateOut);
    return block.vtx[hi];
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx, bool fCheckBMM, const uint256& hashPrevBlock, CAmount* nFeesOut, const uint256& hashMainTip)
{
    // TODO
    // Usually this is called via RefreshBMM of the SidechainPage. SidechainPage
    // will call UpdateMainBlockHashCache right before calling this, but maybe
    // we should update it here instead / also as we will use the mainchain tip
    // when generating the prevBlock commit.

    if (fCheckBMM && !CheckMainchainConnection()) {
        LogPrintf("%s: Error: Cannot generate new BMM block without mainchain connection!\n", __func__);
        return nullptr;
    }

    // v0.2.19 (C6 demand-tag-zero-pool-brick): a pooled transaction the block
    // cannot hold no longer stops block production. Before, the failed template
    // threw on every attempt until the transaction left the mempool (up to 14
    // days). Now the transaction at fault is found, dropped from the mempool with
    // its descendants, and the template is built again; after
    // MAX_TEMPLATE_EVICTIONS drops, this block is built from no mempool
    // transactions, and the next template carries on dropping.
    LOCK2(cs_main, mempool.cs);
    for (int nTry = 0; ; nTry++) {
        const bool fNoMempoolTxs = nTry >= MAX_TEMPLATE_EVICTIONS;
        bool fInvalid = false;
        CValidationState state;
        std::unique_ptr<CBlockTemplate> t = CreateNewBlockOnce(scriptPubKeyIn, hashPrevBlock, nFeesOut, hashMainTip,
                                                               fCheckBMM, fNoMempoolTxs, fInvalid, state);
        if (!fInvalid)
            return t;
        if (fNoMempoolTxs)
            throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));

        CBlockIndex* pindexPrev = hashPrevBlock.IsNull() ? chainActive.Tip() : mapBlockIndex[hashPrevBlock];
        CValidationState stateTx;
        CTransactionRef ptxBad = FindFirstInvalidTx(t->block, t->vTxFees, pindexPrev, fCheckBMM, !hashPrevBlock.IsNull(),
                                                    chainparams, stateTx);
        if (!ptxBad) {
            LogPrintf("%s: template failed (%s) and no single mempool transaction is at fault; building this block from no mempool transactions\n",
                      __func__, FormatStateMessage(state));
            nTry = MAX_TEMPLATE_EVICTIONS - 1;
            continue;
        }
        LogPrintf("%s: template failed: dropping tx %s (%s) and its descendants from the mempool\n", __func__,
                  ptxBad->GetHash().ToString(), FormatStateMessage(stateTx));
        mempool.removeRecursive(*ptxBad, MemPoolRemovalReason::UNKNOWN);
    }
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlockOnce(const CScript& scriptPubKeyIn, const uint256& hashPrevBlock, CAmount* nFeesOut, const uint256& hashMainTip, bool fCheckBMM, bool fNoMempoolTxs, bool& fInvalid, CValidationState& state)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);

    CBlockIndex* pindexPrev;
    if (hashPrevBlock.IsNull()) {
        pindexPrev = chainActive.Tip();
    } else {
        if (mapBlockIndex.count(hashPrevBlock) == 0) {
            LogPrintf("%s: Specified prevblock: %s does not exist!\n", __func__, hashPrevBlock.ToString());
            return nullptr;
        }
        pindexPrev = mapBlockIndex[hashPrevBlock];
    }

    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = true;

    // Try to create a Withdrawal Bundle for this block. We want to know if a Withdrawal Bundle is going to
    // be generated because we will skip adding refund transactions to the
    // same block as a Withdrawal Bundle. We will add the Withdrawal Bundle to the block later if created.
    CTransactionRef withdrawalBundleTx;
    CTransactionRef withdrawalBundleDataTx;
    bool fCreatedWithdrawalBundle = false;
    if (CreateWithdrawalBundleTx(nHeight, withdrawalBundleTx, withdrawalBundleDataTx, false /* fReplicationCheck */,
                true /* fCheckUnique */)) {
        fCreatedWithdrawalBundle = true;
    }

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    std::vector<CTxMemPool::txiter> vRefund;
    if (!fNoMempoolTxs) {
        addClockTxs(nPackagesSelected);
        addPackageTxs(nPackagesSelected, nDescendantsUpdated, vRefund, !fCreatedWithdrawalBundle /* fIncludeRefunds */);
    }

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;
    nLastBlockWeight = nBlockWeight;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;

    SidechainClient client;

    // Create Withdrawal Bundle status updates
    // Lookup the current Withdrawal Bundle
    SidechainWithdrawalBundle withdrawalBundle;
    uint256 hashCurrentWithdrawalBundle;
    psidechaintree->GetLastWithdrawalBundleHash(hashCurrentWithdrawalBundle);
    if (psidechaintree->GetWithdrawalBundle(hashCurrentWithdrawalBundle, withdrawalBundle)) {
        if (withdrawalBundle.status == WITHDRAWAL_BUNDLE_CREATED) {
            // Check if the Withdrawal Bundle has been paid out or failed.
            // v0.2.17: decided exactly as ConnectBlock checks the mark
            // (GetBundleOutcomeOnL1), as of the L1 tip this block's bid builds
            // on; the check asks as of the L1 block that carries the bid, its
            // child. Before, the builder marked "failed" on any failed event
            // in the whole L1 history, and ConnectBlock could then reject every
            // block it built.
            const uint256 hashMainForMark = hashMainTip.IsNull() ? bmmCache.GetLastMainBlockHash() : hashMainTip;
            char cOutcome = 0;
            if (GetBundleOutcomeOnL1(withdrawalBundle, pindexPrev, hashMainForMark, cOutcome) == L1Answer::YES) {
                if (cOutcome == 'F')
                    coinbaseTx.vout.push_back(CTxOut(0, GenerateWithdrawalBundleFailCommit(hashCurrentWithdrawalBundle)));
                else if (cOutcome == 'S')
                    coinbaseTx.vout.push_back(CTxOut(0, GenerateWithdrawalBundleSpentCommit(hashCurrentWithdrawalBundle)));
            }
        }
    }

    // Add previous sidechain block hash & previous mainchain block hash to
    // the coinbase.
    // v0.2.16: a caller that pinned the mainchain tip T (get_block_template)
    // passes it in, so the commit cannot race a cache refresh on another thread.
    CScript scriptPrev = GeneratePrevBlockCommit(hashMainTip.IsNull() ? bmmCache.GetLastMainBlockHash() : hashMainTip,
                                                 pindexPrev->GetBlockHash());
    coinbaseTx.vout.push_back(CTxOut(0, scriptPrev));

    // Add current hashWithdrawalBundle to coinbase output
    if (!hashCurrentWithdrawalBundle.IsNull()) {
        CScript scriptWithdrawalBundle = GenerateWithdrawalBundleHashCommit(hashCurrentWithdrawalBundle);
        coinbaseTx.vout.push_back(CTxOut(0, scriptWithdrawalBundle));
    }

    // Add block version to coinbase output
    CScript scriptVersion = GenerateBlockVersionCommit(pblock->nVersion);
    coinbaseTx.vout.push_back(CTxOut(0, scriptVersion));

    // Add Withdrawal Bundle to block if one was created earlier
    if (fCreatedWithdrawalBundle) {
        for (const CTxOut& out : withdrawalBundleDataTx->vout)
            coinbaseTx.vout.push_back(out);
    }

    // Create refund payout output(s) unless there is a Withdrawal Bundle in this block.
    //
    // Don't add too many refunds.
    //
    if (!fCreatedWithdrawalBundle) {
        uint64_t nRefundAdded = 0;
        for (const CTxMemPool::txiter& it : vRefund) {
            CTransactionRef tx = it->GetSharedTx();
            if (tx == nullptr) continue;

            // Find the refund script
            uint256 id;
            id.SetNull();
            std::vector<unsigned char> vchSig;
            for (const CTxOut& o : tx->vout) {
                if (!o.scriptPubKey.IsWithdrawalRefundRequest(id, vchSig))
                    continue;
                break;
            }
            if (id.IsNull())
                continue;

            // Verify refund request & get data
            SidechainWithdrawal withdrawal;
            if (!VerifyWithdrawalRefundRequest(id, vchSig, withdrawal)) {
                LogPrintf("%s: Miner failed to verify withdrawal refund request! ID: %s\n", __func__, id.ToString());
                return nullptr;
            }

            // Try to add the refund payout output - if we cannot then remove it
            // and stop trying to process more refunds

            // Figure out how much weight the refund payout will add
            coinbaseTx.vout.push_back(CTxOut(withdrawal.amount, GetScriptForDestination(DecodeDestination(withdrawal.strRefundDestination))));
            uint64_t nCoinbaseTxSize = GetVirtualTransactionSize(coinbaseTx);

            nRefundAdded += nCoinbaseTxSize;
        }
    }

    // Get list of deposits from the mainchain

    std::vector<SidechainDeposit> vDeposit;

    SidechainDeposit lastDeposit;
    uint256 hashLastDeposit;
    uint32_t nBurnIndex = 0;
    bool fHaveDeposits = psidechaintree->GetLastDeposit(lastDeposit);
    if (fHaveDeposits) {
        hashLastDeposit = lastDeposit.dtx.GetHash();
        nBurnIndex = lastDeposit.nBurnIndex;
    }
    vDeposit = client.UpdateDeposits(hashLastDeposit, nBurnIndex);

    // Find new deposits
    std::vector<SidechainDeposit> vDepositNew;
    for (const SidechainDeposit& d: vDeposit) {
        // We look up the deposit using the hash of the deposit without the
        // payout amount set because we do not know the payout amount yet.
        if (!psidechaintree->HaveDepositNonAmount(d.GetID())) {
            vDepositNew.push_back(d);
        }
    }

    // v0.2.17 A9: a problem with the new deposits leaves them out of this
    // block; it no longer stops block making (each of these returned no
    // template, so one bad deposit halted the chain).
    bool fSkipDeposits = false;

    // Check deposit burn index
    for (const SidechainDeposit& d : vDepositNew) {
        if (d.nBurnIndex >= d.dtx.vout.size()) {
            LogPrintf("%s: Error: new deposit has invalid burn index:\n%s\n", __func__, d.ToString());
            fSkipDeposits = true;
            break;
        }
    }

    // Sort the deposits into CTIP UTXO spend order
    std::vector<SidechainDeposit> vDepositSorted;
    if (!fSkipDeposits && !SortDeposits(vDepositNew, vDepositSorted)) {
        LogPrintf("%s: Error: Failed to sort deposits!\n", __func__);
        fSkipDeposits = true;
    }

    // Create deposit payout output(s)
    //
    // Make sure we don't add too many deposit outputs
    //
    uint64_t nAddedSize = 0;
    CAmount nFeesAdded = CAmount(0);
    // A vector of vectors of CTxOut - each vector of CTxOut contains all of the
    // outputs for one deposit. When adding / removing deposits of the coinbase
    // transaction we have to add or remove all of the outputs for a deposit.
    std::vector<std::vector<CTxOut>> vOutPackages;

    //
    // Create the deposit payout outputs for deposits.
    //
    // - First deposit in the list should have spent the sidechain CTIP that
    // the sidechain already knows about (in db) if one exists.
    //
    // - Set the payout amount by subtracting the previous CTIP from the next.
    //
    // - Create and return a vector of vectors where each sub vector is the list
    // of outputs required to payout a deposit correctly. We keep the outputs
    // for each deposit contained in their own vector instead of combining them
    // all because we must include all of the outputs for a deposit payout to
    // be valid and if we run out of space we need to know which outputs to
    // remove without invalidating a deposit.

    // Look up CTIP spent by first new deposit and calculate payout
    if (vDepositSorted.size()) {
        const SidechainDeposit& first = vDepositSorted.front();
        if (fHaveDeposits) {
            bool fFound = false;
            for (const CTxIn& in : first.dtx.vin) {
                if (in.prevout.hash == lastDeposit.dtx.GetHash()
                        && lastDeposit.dtx.vout.size() > in.prevout.n
                        && lastDeposit.nBurnIndex == in.prevout.n) {
                    // Calculate payout amount
                    CAmount ctipAmount = lastDeposit.dtx.vout[lastDeposit.nBurnIndex].nValue;
                    if (first.amtUserPayout > ctipAmount)
                        vDepositSorted.front().amtUserPayout -= ctipAmount;
                    else
                        vDepositSorted.front().amtUserPayout = CAmount(0);

                    fFound = true;
                    break;
                }
            }
            if (!fFound) {
                LogPrintf("%s: Error: No CTIP found for first deposit in sorted list: %s (mainchain txid)\n", __func__, first.dtx.GetHash().ToString());
                fSkipDeposits = true;
            }
        } else {
            // This is the very first deposit for this sidechain so we don't
            // need to look up the CTIP that it spent. Logged per template that
            // carries it (a rebuild before it connects logs again), never on a
            // build without new deposits (v0.2.15 logged it on every one).
            LogPrintf("%s: first deposit for this sidechain: %s (mainchain txid)\n", __func__, first.dtx.GetHash().ToString());
        }
    }

    // Now that we have the value for the known CTIP that was spent for the
    // first deposit in the sorted list and have calculated the payout amount
    // for that deposit we can calculate the payout amount for the rest of the
    // deposits in the list.
    //
    // Calculate payout for remaining deposits
    if (!fSkipDeposits && vDepositSorted.size() > 1) {
        std::vector<SidechainDeposit>::iterator it = vDepositSorted.begin() + 1;
        for (; it != vDepositSorted.end(); it++) {
            // Points to the previous deposit in the sorted list
            std::vector<SidechainDeposit>::iterator itPrev = it - 1;

            // Find the output (ctip) this deposit spend and subract it from
            // the user payout amount. Note that we've already sorted by CTIP so
            // they all should exist but we are going to double check anyways.
            bool fFound = false;
            for (const CTxIn& in : it->dtx.vin) {
                if (in.prevout.hash == itPrev->dtx.GetHash()
                        && itPrev->dtx.vout.size() > in.prevout.n
                        && itPrev->nBurnIndex == in.prevout.n) {
                    // Calculate payout amount
                    CAmount ctipAmount = itPrev->dtx.vout[itPrev->nBurnIndex].nValue;

                    if (it->amtUserPayout > ctipAmount)
                        it->amtUserPayout -= ctipAmount;
                    else
                        it->amtUserPayout = CAmount(0);

                    fFound = true;
                    break;
                }
            }
            if (!fFound) {
                LogPrintf("%s: Error: Failed to calculate payout amount - no CTIP found for deposit: %s (mainchain txid)\n", __func__, it->dtx.GetHash().ToString());
                fSkipDeposits = true;
                break;
            }
        }
    }
    if (fSkipDeposits) {
        LogPrintf("%s: building this block without new deposits\n", __func__);
        vDepositSorted.clear();
    }

    // Create the deposit outputs.
    // We will loop through the sorted list of new deposits, double check a few
    // things, and then create an output paying the deposit to the destination
    // string if possible. We will also add an OP_RETURN output with the
    // serialization of the SidechainDeposit object.
    for (const SidechainDeposit& deposit : vDepositSorted) {
        // Outputs created to payout this deposit - to be added to vOutPackages
        std::vector<CTxOut> vOut;

        // Special case for Withdrawal Bundle change return. We don't pay anyone this deposit
        // but it still must be added to the database.
        if (deposit.strDest == SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST) {
            vOut.push_back(CTxOut(0, deposit.GetScript()));
            // Add this deposits output to the vector of deposit outputs
            vOutPackages.push_back(vOut);
            continue;
        }

        // Payout deposit. The decision of WHETHER a payout is owed, and of what
        // shape, belongs to GetDepositPayoutOutput and to nothing else - the
        // validator asks the same function. Two independent copies of this rule
        // is what D-2 was.
        CTxOut depositOut;
        if (GetDepositPayoutOutput(deposit, depositOut))
            vOut.push_back(depositOut);

        // Add serialization of deposit
        vOut.push_back(CTxOut(0, deposit.GetScript()));

        // Add this deposits outputs to the vector of deposit outputs
        vOutPackages.push_back(vOut);
    }

    if (vOutPackages.size())
        LogPrintf("%s: Created deposit outputs for: %u deposits!\n", __func__, vOutPackages.size());

    for (const auto& v : vOutPackages) {
        // Add all of the outputs for this deposit to the coinbase tx
        for (const CTxOut& o : v)
            coinbaseTx.vout.push_back(o);

        // If this deposit has a payout output, it had to pay a fee
        if (v.size() > 1)
            nFeesAdded += SIDECHAIN_DEPOSIT_FEE;

        // Check the block size now & remove this deposit if the block size
        // became too large.
        uint64_t nSize = GetVirtualTransactionSize(coinbaseTx);
        if (nAddedSize + nSize + nBlockWeight > MAX_BLOCK_WEIGHT) {
            for (size_t i = 0; i < v.size(); i++) {
                coinbaseTx.vout.pop_back();
            }
            if (v.size() > 1)
                nFeesAdded -= SIDECHAIN_DEPOSIT_FEE;
            break;
        }

        nAddedSize += nSize;
    }
    nFees += nFeesAdded;

    coinbaseTx.vout[0].nValue = nFees;

    if (nFeesOut)
        *nFeesOut = nFees;

    // Signal the most recent Withdrawal Bundle created by this sidechain
    if (!hashCurrentWithdrawalBundle.IsNull())
        pblock->hashWithdrawalBundle = hashCurrentWithdrawalBundle;

    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));
    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = -nFees;

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    // We have to skip BMM checks when first creating a block as we haven't
    // received BMM proof from the mainchain yet.
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false,
                fCheckBMM, hashPrevBlock.IsNull() ? false : true)) {
        fInvalid = true;
        return std::move(pblocktemplate);
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
// - the withdrawal poison-row guard (from nWithdrawalGuardHeight)
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    // Withdrawal poison-row guard (v0.2.13): from nWithdrawalGuardHeight a block
    // holding an unpayable withdrawal is invalid (ConnectBlock
    // bad-withdrawal-unpayable), but ATMP applies the rule only from that height,
    // so one admitted earlier can still be pooled here. Included, the template
    // still passes TestBlockValidity (ConnectBlock returns under fJustCheck
    // before its sidechain-object checks), so we would BMM-mine a block that
    // ConnectBlock then rejects - again on every template while the tx stays
    // pooled: block production stalls and each try spends an L1 BMM bid. The
    // mempool sweep (EvictUnpayableWithdrawals) evicts it on the tip change;
    // this skip is the template-side half and holds whatever path the pool
    // took. Testing the whole package also drops every descendant, because a
    // descendant's package always carries its unconfirmed withdrawal ancestor.
    const bool fWithdrawalGuard = WithdrawalGuardActive(nHeight, chainparams.GetConsensus().nWithdrawalGuardHeight);
    for (const CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
        std::string strUnpayable;
        if (fWithdrawalGuard && TxHasUnpayableWithdrawal(it->GetTx(), strUnpayable)) {
            LogPrintf("%s: skipping unpayable withdrawal %s (%s)\n", __func__, it->GetTx().GetHash().ToString(), strUnpayable);
            return false;
        }
        // v0.2.18: a withdrawal id already stored, or already created in this
        // template, makes the block fail ConnectBlock (bad-withdrawal-not-new)
        // after TestBlockValidity passed it - skip the package instead.
        std::vector<uint256> vWID;
        GetTxWithdrawalIDs(it->GetTx(), vWID);
        for (const uint256& wid : vWID) {
            SidechainWithdrawal held;
            if (setBlockWithdrawalIDs.count(wid) || psidechaintree->GetWithdrawal(wid, held)) {
                LogPrintf("%s: skipping withdrawal %s: id %s is not new\n", __func__, it->GetTx().GetHash().ToString(), wid.ToString());
                return false;
            }
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    {
        std::vector<uint256> vWID;
        GetTxWithdrawalIDs(iter->GetTx(), vWID);
        setBlockWithdrawalIDs.insert(vWID.begin(), vWID.end());
    }
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();

    // If we are adding a refund, also account for the payout coinbase output
    if (iter->IsWithdrawalRefund()) {
        nBlockWeight += nRefundOutputSize;
    }

    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (const CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

bool IsClockTx(const CTransaction& tx)
{
    if (tx.nVersion == TRANSACTION_NOTE_VERSION)
        return tx.nNoteOp == NOTE_OP_REDEEM || tx.nNoteOp == NOTE_OP_DEMAND ||
               tx.nNoteOp == NOTE_OP_PROTEST || tx.nNoteOp == NOTE_OP_CLAIM ||
               tx.nNoteOp == NOTE_OP_TOKEN_CLAIM || tx.nNoteOp == NOTE_OP_TOKEN_COLLECT;   // v0.2.21: token holders' turn
    if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION)
        return tx.nDepositOp == DEPOSIT_OP_WITHDRAW || tx.nDepositOp == DEPOSIT_OP_CLAIM;
    if (tx.nVersion == TRANSACTION_HOUSE_VERSION)
        return tx.nHouseOp == HOUSE_OP_ATTEST;
    return false;
}

void BlockAssembler::addClockTxs(int &nPackagesSelected)
{
    // Oldest first, so a long-waiting demand goes in before a newer one.
    std::vector<CTxMemPool::txiter> vClock;
    for (CTxMemPool::txiter it = mempool.mapTx.begin(); it != mempool.mapTx.end(); ++it) {
        if (IsClockTx(it->GetTx()))
            vClock.push_back(it);
    }
    if (vClock.empty())
        return;
    std::sort(vClock.begin(), vClock.end(), [](CTxMemPool::txiter a, CTxMemPool::txiter b) {
        if (a->GetTime() != b->GetTime()) return a->GetTime() < b->GetTime();
        return a->GetTx().GetHash() < b->GetTx().GetHash();
    });

    // Half the block at most: the fee-rate pass keeps room for everything else.
    const uint64_t nClockMaxWeight = nBlockWeight + (nBlockMaxWeight - nBlockWeight) / 2;
    uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    for (CTxMemPool::txiter iter : vClock) {
        if (inBlock.count(iter))
            continue;
        CTxMemPool::setEntries package;
        mempool.CalculateMemPoolAncestors(*iter, package, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
        onlyUnconfirmed(package);
        package.insert(iter);

        // A refund is only ever added after the fee-rate pass has checked it on its
        // own (v0.2.17), so a package that carries one waits for that pass.
        uint64_t nSize = 0;
        int64_t nSigOps = 0;
        CAmount nPackageFees = 0;
        bool fRefund = false;
        for (CTxMemPool::txiter it : package) {
            nSize += it->GetTxSize();
            nSigOps += it->GetSigOpCost();
            nPackageFees += it->GetModifiedFee();
            fRefund |= it->IsWithdrawalRefund();
        }
        if (fRefund)
            continue;
        if (nPackageFees < blockMinFeeRate.GetFee(nSize))
            continue;
        if (nBlockWeight + WITNESS_SCALE_FACTOR * nSize >= nClockMaxWeight || !TestPackage(nSize, nSigOps))
            continue;
        if (!TestPackageTransactions(package))
            continue;

        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(package, iter, sortedEntries);
        for (CTxMemPool::txiter it : sortedEntries)
            AddToBlock(it);
        ++nPackagesSelected;
    }
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated, std::vector<CTxMemPool::txiter>& vRefund, bool fIncludeRefunds)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    std::set<uint256> setRefund;
    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // Skip refunds if we don't want to include them. (v0.2.17: mi may be
        // at the end while mapModifiedTx still has entries: never read it then.)
        const bool fMapTxLeft = mi != mempool.mapTx.get<ancestor_score>().end();
        if (fMapTxLeft && !fIncludeRefunds && mi->IsWithdrawalRefund()) {
            ++mi;
            continue;
        }

        // Very refund in the mempool again before adding it to a block
        if (fMapTxLeft && mi->IsWithdrawalRefund()) {
            CTransactionRef tx = mi->GetSharedTx();
            if (tx == nullptr) {
                ++mi;
                continue;
            }

            // Find the refund script
            uint256 id;
            id.SetNull();
            std::vector<unsigned char> vchSig;
            for (const CTxOut& o : tx->vout) {
                if (!o.scriptPubKey.IsWithdrawalRefundRequest(id, vchSig))
                    continue;
                break;
            }
            if (id.IsNull()) {
                ++mi;
                continue;
            }

            // Double check that we haven't already added another refund request
            // txn for this same withdrawal ID (that would be invalid).
            if (setRefund.count(id)) {
                LogPrintf("%s: Invalid (duplicate withdrawal ID) refund in mempool!\n", __func__);
                ++mi;
                continue;
            }

            SidechainWithdrawal withdrawal;
            if (!VerifyWithdrawalRefundRequest(id, vchSig, withdrawal)) {
                ++mi;
                continue;
            }
        }

        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        // Add the size of the refund payout that will be added to the coinbase
        if (iter->IsWithdrawalRefund()) {
            packageSize += nRefundOutputSize;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // v0.2.17: a refund goes into a block only when the loop above has met
        // and checked it on its own, and never into a block that creates a
        // bundle. A child's package must not pull one in as an ancestor: in a
        // bundle block the coinbase has no refund payout for it, so the
        // template failed its own check and no block could be built.
        bool fRefundUnchecked = false;
        for (CTxMemPool::txiter it : ancestors) {
            if (it->IsWithdrawalRefund() && (it != iter || fUsingModified || !fIncludeRefunds)) {
                fRefundUnchecked = true;
                break;
            }
        }
        if (fRefundUnchecked) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // Test if all tx's are Final
        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            // Keep track of withdrawal refunds that are added
            if (sortedEntries[i]->IsWithdrawalRefund()) {
                vRefund.push_back(sortedEntries[i]);
            }

            AddToBlock(sortedEntries[i]);

            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

// The worst case of the coinbase scriptSig IncrementExtraNonce builds: the height
// and the extra nonce are unsigned ints, each at most a 5-byte CScriptNum behind a
// 1-byte push; the tag is one direct push (a length byte, then the bytes).
static_assert(MAX_COINBASE_TAG_BYTES < OP_PUSHDATA1, "the coinbase tag must fit one direct push");
static_assert((1 + 5) + (1 + 5) + (1 + MAX_COINBASE_TAG_BYTES) <= 100,
              "a tagged coinbase scriptSig must stay within the 100 bytes consensus allows");

bool ParseCoinbaseTag(const std::string& strIn, std::string& strTag, CScript& scriptTag, std::string& strError)
{
    const std::string strWhitespace = " \t\r\n";
    const size_t nBegin = strIn.find_first_not_of(strWhitespace);
    if (nBegin == std::string::npos) {
        strError = strprintf("-coinbasetag is empty. Set a name of 1 to %u printable ASCII characters, "
                             "or remove the setting to produce blocks without a tag.", MAX_COINBASE_TAG_BYTES);
        return false;
    }
    const size_t nEnd = strIn.find_last_not_of(strWhitespace);
    const std::string str = strIn.substr(nBegin, nEnd - nBegin + 1);

    if (str.size() > MAX_COINBASE_TAG_BYTES) {
        strError = strprintf("-coinbasetag is %u bytes long; the limit is %u bytes.", str.size(), MAX_COINBASE_TAG_BYTES);
        return false;
    }
    for (size_t i = 0; i < str.size(); i++) {
        const unsigned char c = str[i];
        if (c < 0x20 || c > 0x7e) {
            strError = strprintf("-coinbasetag has a byte outside printable ASCII (0x%02x at position %u). "
                                 "Use letters, digits, punctuation and spaces only.", c, i + 1);
            return false;
        }
    }

    strTag = str;
    scriptTag = CScript() << std::vector<unsigned char>(str.begin(), str.end());
    return true;
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

bool BlockAssembler::GenerateBMMBlock(CBlock& block, std::string& strError, CAmount* nFeesOut, const std::vector<CMutableTransaction>& vtx, const uint256& hashPrevBlock, const CScript& scriptPubKey, const uint256& hashMainTip)
{
    // v0.2.16: the old "replace every tx but the coinbase" path wrote through
    // this temporary assembler's unset member pblock (undefined behaviour) and
    // would have left a stale witness commitment. No caller passes txs; refuse.
    if (vtx.size()) {
        strError = "Replacing a BMM block's transactions is not supported!\n";
        return false;
    }

    // Either generate a new scriptPubKey or use the one that has optionally
    // been passed in
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    if (scriptPubKey.empty()) {
        const std::vector<CWalletRef> wallets = GetWallets();
        if (wallets.empty()) {
            strError = "No wallet active!\n";
            return false;
        }

        // Create script
        std::shared_ptr<CReserveScript> coinbaseScript;
        wallets[0]->GetScriptForMining(coinbaseScript);

        if (!coinbaseScript || coinbaseScript->reserveScript.empty()) {
            strError = "Failed to get script for mining!\n";
            return false;
        }
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript, true, false, hashPrevBlock, nFeesOut, hashMainTip);
    } else {
        pblocktemplate = BlockAssembler(Params()).CreateNewBlock(scriptPubKey, true, false, hashPrevBlock, nFeesOut, hashMainTip);
    }

    if (!pblocktemplate.get()) {
        strError = "Failed to get block template!\n";
        return false;
    }

    unsigned int nExtraNonce = 0;
    CBlock *pblock = &pblocktemplate->block;
    {
        // v0.2.16: mapBlockIndex is read under cs_main
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(pblock->hashPrevBlock);
        if (mi == mapBlockIndex.end()) {
            strError = "Invalid hashPrevBlock!\n";
            return false;
        }
        IncrementExtraNonce(pblock, mi->second, nExtraNonce);
    }

    block = *pblock;

    return true;
}


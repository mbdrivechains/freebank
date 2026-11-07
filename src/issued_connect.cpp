// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Issued tokens against the units state (server side; issued.cpp holds the context-free rules).

#include <issued.h>

#include <arith_uint256.h>
#include <chainparams.h>
#include <hash.h>
#include <script/standard.h>
#include <coins.h>
#include <consensus/validation.h>
#include <pubkey.h>
#include <txmempool.h>   // MEMPOOL_HEIGHT
#include <house.h>
#include <houserate.h>
#include <note.h>
#include <deposit.h>   // DepositDemand (the bid at a demand)
#include <pool.h>
#include <units.h>
#include <txdb.h>
#include <validation.h>   // punitsdb
#include <utilstrencodings.h>

#include <algorithm>
#include <limits>
#include <memory>

#include <map>
#include <tuple>
#include <set>


bool ConnectIssuedTx(const CTransaction& tx, const CCoinsViewCache& view, CUnitsView& units, int nHeight,
                     CValidationState& state, const std::function<bool(uint32_t, CHouse&)>* pfnGetHouse)
{
    // Frozen units: what the spent coins carry (the annex's at creation, or a later FREEZE's) must go where this
    // transaction's annex puts them, token by token; the spent coins' FREEZE records go with them.
    // Nothing is written until every check has passed, so a refused transaction leaves `units` as it found it.
    std::map<uint256, uint64_t> mapFrozenIn;
    std::vector<UnitsKey> vFrozenErase;
    for (const CTxIn& in : tx.vin) {
        const Coin& coin = view.AccessCoin(in.prevout);
        if (coin.IsSpent() || !coin.fIssued)
            continue;
        uint64_t nFrozen = coin.nIssuedFrozen;
        const UnitsKey key = IssuedFrozenKey(in.prevout.hash, in.prevout.n);
        if (units.Get(key, nFrozen))
            vFrozenErase.push_back(key);
        mapFrozenIn[coin.assetID] += nFrozen;
    }
    std::map<uint256, uint64_t> mapUnitsOut, mapFrozenOut;
    if (HasIssuedAnnex(tx.nVersion) && !IssuedSumAnnex(tx, mapUnitsOut, mapFrozenOut))
        return state.DoS(100, false, REJECT_INVALID, "bad-issued-annex-units");
    // A burn of frozen units is refused: they stay frozen, wherever they go.
    for (const auto& p : mapFrozenIn)
        if (p.second && (!mapFrozenOut.count(p.first) || mapFrozenOut[p.first] != p.second))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-frozen-flow");
    for (const auto& p : mapFrozenOut)
        if (p.second && (!mapFrozenIn.count(p.first) || mapFrozenIn[p.first] != p.second))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-frozen-flow");

    const auto fnEraseSpentFrozen = [&]() {
        for (const UnitsKey& key : vFrozenErase)
            units.Erase(key);
    };
    // Gold B (D-2026-11-07-1; houserate.h): HOUSE_OP_RATE. SETKEY's approvers were checked by CheckHouseOperation; here the
    // key is written, or a POST's rate-key signature checked and the rate applied (spread, rise cap, day records) at this
    // block's clock. Last of the checks: ApplyHouseRatePost writes only on success, and nothing after it can fail.
    if (tx.nVersion == TRANSACTION_HOUSE_VERSION && tx.nHouseOp == HOUSE_OP_RATE) {
        HouseRate rate;
        if (!DecodeHousePayload(tx.vchHousePayload, rate))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-rate-payload");
        if (rate.nKind == HOUSE_RATE_SETKEY) {
            units.Put(RateKeyKey(rate.nHouseID), rate.vchRatePubKey);
        } else {
            std::vector<unsigned char> vchKey;
            if (!units.Get(RateKeyKey(rate.nHouseID), vchKey))
                return state.DoS(0, false, REJECT_INVALID, "bad-house-rate-nokey");
            if (!CPubKey(vchKey).VerifyStrict(HouseRateSigHash(rate.nHouseID, tx, rate), rate.vchRateSig))
                return state.DoS(100, false, REJECT_INVALID, "bad-house-rate-sig");
            CChainClock clock;
            if (!GetChainClock(units, clock))
                return state.DoS(0, false, REJECT_INVALID, "bad-house-rate-noclock");
            std::string strReject;
            if (!ApplyHouseRatePost(units, rate.nHouseID, rate.nBid, rate.nAsk, (uint32_t)nHeight, clock.nMonoTime,
                                    Params().GetConsensus().GramAt(nHeight), strReject, clock.nActiveTime))
                return state.DoS(strReject == "bad-house-rate-spread" ? 100 : 0, false, REJECT_INVALID, strReject);
        }
    }

    // Gold B (GOLD_B.md §3; review 2026-11-07): a formal demand fixes the rate at the demand - record the bid in effect
    // at its block, which a house-alone discharge must pay at least.
    if (tx.nVersion == TRANSACTION_NOTE_VERSION && tx.nNoteOp == NOTE_OP_DEMAND) {
        NoteDemand dm;
        if (DecodeNotePayload(tx.vchNotePayload, dm) && dm.nHouseID != 0)
            RecordDemandBid(units, dm.nHouseID, (uint32_t)nHeight);
    }
    if (tx.nVersion == TRANSACTION_DEPOSIT_VERSION && tx.nDepositOp == DEPOSIT_OP_DEMAND) {
        DepositDemand dd;
        if (DecodeDepositPayload(tx.vchDepositPayload, dd) && dd.nHouseID != 0)
            RecordDemandBid(units, dd.nHouseID, (uint32_t)nHeight);
    }

    // Gold B (GOLD_B.md §4): the swap records, after CheckNoteOperation's checks (against this same view).
    if (tx.nVersion == TRANSACTION_NOTE_VERSION && IsNoteSwapOp(tx.nNoteOp)) {
        CChainClock clock;
        if (!GetChainClock(units, clock))
            return state.DoS(0, false, REJECT_INVALID, "bad-note-swap-noclock");
        const Consensus::GramParams& gpSwap = Params().GetConsensus().GramAt(nHeight);
        const int64_t nClockNow = ClockAtHeight(nHeight);                       // a shortfall's lapse runs on the clock
        const int64_t nLapseClock = (int64_t)gpSwap.nShortfallLapseSecs / 600;
        if (tx.nNoteOp == NOTE_OP_SWAP) {
            NoteSwap sw;
            if (!DecodeNotePayload(tx.vchNotePayload, sw))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-swap-payload");
            uint64_t nBid = 0, nAsk = 0;
            if (!HouseRateForChecks(sw.nHouseID, nHeight, nBid, nAsk) || nBid == 0)
                return state.DoS(0, false, REJECT_INVALID, "bad-note-swap-no-rate");
            CSwapRecord rec;
            rec.nHouseID = sw.nHouseID;
            rec.nUnits = sw.nUnits;
            rec.nChainID = sw.nChainID;
            rec.vchContract = sw.vchContract;
            rec.vchEthAddress = sw.vchEthAddress;
            rec.vchPayoutScript = sw.vchPayoutScript;
            rec.nBid0 = nBid;
            rec.nDemandHeight = (uint32_t)nHeight;
            rec.nDeadlineActive = clock.nActiveTime + (int64_t)gpSwap.nSwapDeadlineSecs;
            SwapOpen(units, sw.hashLock, rec);
        } else if (tx.nNoteOp == NOTE_OP_SWAP_DONE) {
            NoteSwapDone d;
            if (!DecodeNotePayload(tx.vchNotePayload, d))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-swap-done-payload");
            SwapSettle(units, d.hashLock, SWAP_DONE, 0, clock.nMonoTime, nClockNow, nLapseClock);
        } else if (tx.nNoteOp == NOTE_OP_SWAP_PAY) {
            NoteSwapPay p;
            CSwapRecord r;
            if (!DecodeNotePayload(tx.vchNotePayload, p) || !units.Get(SwapKey(p.hashLock), r))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-swap-pay-payload");
            const uint64_t nBidT = SwapBidAtDeadlineForChecks(r);
            if (clock.nActiveTime >= r.nDeadlineActive)
                SwapFixBidT(units, p.hashLock);
            // The shortfall counts what was actually paid (review 2026-11-07): a payment built at the bid at demand that
            // confirms just past the deadline owes no shortfall.
            uint64_t nRate = SwapPayRate(r, nBidT, clock.nActiveTime);
            {
                const CScript scriptPayout(r.vchPayoutScript.begin(), r.vchPayoutScript.end());
                unsigned __int128 nPaid = 0;
                for (const CTxOut& o : tx.vout)
                    if (o.scriptPubKey == scriptPayout)
                        nPaid += (uint64_t)o.nValue;
                if (r.nUnits > 0) {
                    const unsigned __int128 nPaidRate = nPaid * 1000 / r.nUnits;
                    const uint64_t nEff = (uint64_t)std::min<unsigned __int128>(nPaidRate, (unsigned __int128)r.nBid0);
                    nRate = std::max(nRate, nEff);
                }
            }
            SwapSettle(units, p.hashLock, SWAP_PAID, nRate, clock.nMonoTime, nClockNow, nLapseClock);
        } else if (tx.nNoteOp == NOTE_OP_SWAP_CLAIM) {
            NoteSwapClaim c;
            if (!DecodeNotePayload(tx.vchNotePayload, c))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-swap-claim-payload");
            SwapClaim(units, c.hashLock);
        } else if (tx.nNoteOp == NOTE_OP_SWAP_EXPIRE) {
            NoteSwapExpire e;
            if (!DecodeNotePayload(tx.vchNotePayload, e))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-swap-expire-payload");
            SwapFixBidT(units, e.hashLock);
        } else {
            NoteSwapProtest pro;
            if (!DecodeNotePayload(tx.vchNotePayload, pro))
                return state.DoS(100, false, REJECT_INVALID, "bad-note-swap-protest-payload");
            SwapFixBidT(units, pro.hashLock);
            SwapMarkProtested(units, pro.hashLock);
        }
    }

    // Gold B (GOLD_B.md §2): HOUSE_OP_CHARTER, its approvers checked by CheckHouseOperation; the rules and the write here.
    if (tx.nVersion == TRANSACTION_HOUSE_VERSION && tx.nHouseOp == HOUSE_OP_CHARTER) {
        HouseCharter ch;
        if (!DecodeHousePayload(tx.vchHousePayload, ch))
            return state.DoS(100, false, REJECT_INVALID, "bad-house-charter-payload");
        CChainClock clock;
        if (!GetChainClock(units, clock))
            return state.DoS(0, false, REJECT_INVALID, "bad-house-charter-noclock");
        std::string strReject;
        if (!ApplyHouseCharter(units, ch, (uint32_t)nHeight, clock.nMonoTime, Params().GetConsensus().GramAt(nHeight),
                               strReject))
            return state.DoS(0, false, REJECT_INVALID, strReject);
    }

    if (tx.nVersion != TRANSACTION_TOKEN_VERSION) {
        fnEraseSpentFrozen();
        return true;
    }

    // D-2026-11-04-1 (3b), Gold B (hole 4): creating a token or a pool burns nCreateFeeSats of sECX to CreationBurnScript
    // outputs: spam can't grow the per-block scans for free. Burned, never paid to a producer (legal GO_NOGO condition 2).
    // A fixed amount: no price is needed. A creation carries no withdrawal: its burn could otherwise back the withdrawal
    // too (ClaimWithdrawalBurn takes any OP_RETURN of the amount).
    if (tx.nIssuedOp == ISSUED_OP_CREATE || tx.nIssuedOp == ISSUED_OP_POOL_CREATE) {
        const Consensus::GramParams& gpFee = Params().GetConsensus().GramAt(nHeight);
        if (gpFee.nCreateFeeSats > 0) {
            const CScript scriptBurn = CreationBurnScript();
            CAmount nBurned = 0;
            for (const CTxOut& o : tx.vout) {
                std::vector<unsigned char> vchObj;
                if (o.scriptPubKey.IsSidechainObj(vchObj))
                    return state.DoS(100, false, REJECT_INVALID, "bad-issued-create-sidechain-obj");
                if (o.scriptPubKey == scriptBurn)
                    nBurned += o.nValue;
            }
            if (nBurned < gpFee.nCreateFeeSats)
                return state.DoS(0, false, REJECT_INVALID, "bad-issued-create-fee");
        }
    }

    switch (tx.nIssuedOp) {
    case ISSUED_OP_CREATE: {
        IssuedCreate x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);   // shape checked
        if (!CPubKey(x.vchIssuerKey).VerifyStrict(IssuedSigHash(tx), x.vchIssuerSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-create-sig");
        CIssuedToken token;
        token.tokenID = tx.GetHash();
        if (units.Have(IssuedTokenKey(token.tokenID)))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-create-exists");
        token.nKind = x.nKind;
        token.strTicker = x.strTicker;
        token.vchIssuerKey = x.vchIssuerKey;
        token.vchFreezeKey = x.vchFreezeKey;
        token.vchBackingContract = x.vchBackingContract;
        token.vchBackingAddress = x.vchBackingAddress;
        token.strUpstream = x.strUpstream;
        token.nIssuerHouseID = x.nIssuerHouseID;
        token.nCreateHeight = nHeight;
        units.Put(IssuedTokenKey(token.tokenID), token);
        break;
    }
    case ISSUED_OP_MINT: {
        IssuedMint x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(x.tokenID), token))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-mint-token");
        if (!CPubKey(token.vchIssuerKey).VerifyStrict(IssuedSigHash(tx), x.vchIssuerSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-mint-sig");
        if (token.nSupply > (uint64_t)MAX_MONEY - x.nUnits)
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-mint-supply");
        token.nSupply += x.nUnits;
        units.Put(IssuedTokenKey(x.tokenID), token);
        break;
    }
    case ISSUED_OP_BURN: {
        IssuedBurn x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(x.tokenID), token))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-burn-token");
        if (token.nSupply < x.nUnits)
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-burn-supply");   // unreachable: supply covers every coin
        CIssuedBurn burn;
        burn.nUnits = x.nUnits;
        burn.vchEthDest = x.vchEthDest;
        burn.nHeight = nHeight;
        burn.txid = tx.GetHash();
        burn.nCumUnits = x.nUnits;
        if (token.nBurnSeq > 0) {
            CIssuedBurn prev;
            // Saturating (review 11-04): a wrapped total would let an issuer mint and burn its way to "nothing owed";
            // saturated, the check fails closed and only the issuer's own token suffers.
            if (units.Get(IssuedBurnKey(x.tokenID, token.nBurnSeq - 1), prev))
                burn.nCumUnits = prev.nCumUnits > std::numeric_limits<uint64_t>::max() - x.nUnits
                                     ? std::numeric_limits<uint64_t>::max() : prev.nCumUnits + x.nUnits;
        }
        units.Put(IssuedBurnKey(x.tokenID, token.nBurnSeq), burn);
        token.nBurnSeq++;
        token.nSupply -= x.nUnits;
        units.Put(IssuedTokenKey(x.tokenID), token);
        break;
    }
    case ISSUED_OP_TRANSFER:
        break;
    case ISSUED_OP_FREEZE:
    case ISSUED_OP_UNFREEZE: {
        IssuedFreeze x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(x.tokenID), token))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-token");
        if (token.vchFreezeKey.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-no-key");
        if (!CPubKey(token.vchFreezeKey).VerifyStrict(IssuedSigHash(tx), x.vchFreezeSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-sig");
        std::set<COutPoint> setSpent;
        for (const CTxIn& in : tx.vin)
            setSpent.insert(in.prevout);
        std::vector<std::pair<UnitsKey, uint64_t>> vFrozenWrite;
        for (size_t k = 0; k < x.vOutpoint.size(); k++) {
            const COutPoint& o = x.vOutpoint[k];
            if (setSpent.count(o))   // its record would outlive the coin
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-spent");
            const Coin& coin = view.AccessCoin(o);
            // A coin of this token, confirmed (an unconfirmed coin's state is its annex's until it connects).
            if (coin.IsSpent() || !coin.fIssued || coin.assetID != x.tokenID || coin.nHeight == MEMPOOL_HEIGHT)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-coin");
            if (x.vFrozen[k] > coin.nIssuedUnits)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-units");
            const UnitsKey key = IssuedFrozenKey(o.hash, o.n);
            uint64_t nNow = coin.nIssuedFrozen;
            units.Get(key, nNow);
            if (tx.nIssuedOp == ISSUED_OP_FREEZE ? x.vFrozen[k] <= nNow : x.vFrozen[k] >= nNow)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-direction");
            vFrozenWrite.emplace_back(key, x.vFrozen[k]);
        }
        for (const std::pair<UnitsKey, uint64_t>& w : vFrozenWrite)
            units.Put(w.first, w.second);
        break;
    }
    case ISSUED_OP_POOL_CREATE: {
        IssuedPoolCreate x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(x.tokenID), token))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-token");
        // Dollar tokens only from nDollarPoolTime (no forks, D-2026-11-05-3; Gold B: no gold kind any more); never a
        // freeze-keyed token (R1-6).
        const Consensus::Params& cp = Params().GetConsensus();
        if (token.nKind == ISSUED_KIND_POOL_LP ||
                (token.nKind == ISSUED_KIND_USD_CENTS && !LaterRuleOn(cp.nDollarPoolTime, nHeight)))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-kind");
        if (!token.vchFreezeKey.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-freeze-key");
        if (units.Have(TokenPoolKey(x.tokenID)))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-exists");
        uint64_t nLpToCreator = 0, nLpSupply = 0;
        if (!PoolLpMintInitial(x.nInitUnits, x.nInitSats, nLpToCreator, nLpSupply) || nLpToCreator != x.nLpOut)
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-lp-amount");
        CTokenPool pool;
        pool.tokenID = x.tokenID;
        pool.nFeeBps = x.nFeeBps;
        pool.nLpSupply = nLpSupply;
        pool.nUnits = x.nInitUnits;
        pool.nSats = x.nInitSats;
        pool.outToken = COutPoint(tx.GetHash(), 0);
        pool.outSats = COutPoint(tx.GetHash(), 1);
        pool.nCreateHeight = nHeight;
        CIssuedToken lp;
        lp.tokenID = LpTokenID(x.tokenID);
        lp.nKind = ISSUED_KIND_POOL_LP;
        lp.strTicker = "LP";
        lp.nCreateHeight = nHeight;
        lp.nSupply = nLpToCreator;
        units.Put(TokenPoolKey(x.tokenID), pool);
        units.Put(IssuedTokenKey(lp.tokenID), lp);
        break;
    }
    case ISSUED_OP_POOL_ADD:
    case ISSUED_OP_POOL_REMOVE:
    case ISSUED_OP_POOL_SWAP: {
        const uint256 tokenID = IssuedPoolOpToken(tx);
        CTokenPool pool;
        if (!units.Get(TokenPoolKey(tokenID), pool))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-unknown");
        // The reserves are the custody pair the transaction spends (tx_verify pinned them to this pool's tagged
        // coins at vin[0] / vin[1]); in a block they are the record's.
        if (tx.vin.size() < 2)
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-custody-in");
        const Coin& cToken = view.AccessCoin(tx.vin[0].prevout);
        const Coin& cSats = view.AccessCoin(tx.vin[1].prevout);
        if (cToken.IsSpent() || cSats.IsSpent() || !cToken.fIssued || cToken.assetID != tokenID ||
                cToken.out.scriptPubKey != TokenPoolScript(tokenID) || cSats.out.scriptPubKey != TokenPoolScript(tokenID) ||
                !cToken.fCustody || !cSats.fCustody)
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-custody-in");
        const uint64_t nUnits = cToken.nIssuedUnits;
        const CAmount nSats = cSats.out.nValue;
        const uint64_t nUnitsNew = FindIssuedOut(tx, 0)->nUnits;
        const CAmount nSatsNew = tx.vout[1].nValue;
        CIssuedToken lp;
        units.Get(IssuedTokenKey(LpTokenID(tokenID)), lp);
        if (tx.nIssuedOp == ISSUED_OP_POOL_ADD) {
            IssuedPoolAdd x;
            DecodeIssuedPayload(tx.vchIssuedPayload, x);
            if (x.nPriorLpSupply != pool.nLpSupply)
                return state.DoS(0, false, REJECT_INVALID, "bad-issued-pool-lp-prior");
            uint64_t nMinted = 0;
            if (!PoolLpMintProportional(x.nAddUnits, x.nAddSats, nUnits, nSats, pool.nLpSupply, nMinted) ||
                    nMinted != x.nLpMinted)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-lp-amount");
            if (nUnitsNew != nUnits + x.nAddUnits || nSatsNew != nSats + x.nAddSats)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-reserves");
            pool.nLpSupply += nMinted;
            lp.nSupply += nMinted;
        } else if (tx.nIssuedOp == ISSUED_OP_POOL_REMOVE) {
            IssuedPoolRemove x;
            DecodeIssuedPayload(tx.vchIssuedPayload, x);
            if (x.nPriorLpSupply != pool.nLpSupply)
                return state.DoS(0, false, REJECT_INVALID, "bad-issued-pool-lp-prior");
            uint64_t nUnitsOut = 0;
            CAmount nSatsOut = 0;
            if (!PoolLpRedeemAmounts(x.nBurnLp, nUnits, nSats, pool.nLpSupply, nUnitsOut, nSatsOut) ||
                    nUnitsOut != x.nUnitsOut || nSatsOut != x.nSatsOut)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-lp-amount");
            if (nUnitsNew != nUnits - nUnitsOut || nSatsNew != nSats - nSatsOut)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-reserves");
            pool.nLpSupply -= x.nBurnLp;
            lp.nSupply -= x.nBurnLp;
        } else {
            IssuedPoolSwap x;
            DecodeIssuedPayload(tx.vchIssuedPayload, x);
            uint64_t nOut = 0;
            const bool fOk = x.fSellTokens ? PoolSwapOut(x.nAmountIn, nUnits, (uint64_t)nSats, pool.nFeeBps, nOut)
                                           : PoolSwapOut(x.nAmountIn, (uint64_t)nSats, nUnits, pool.nFeeBps, nOut);
            if (!fOk || nOut != x.nAmountOut)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-swap-amount");
            const bool fReserves = x.fSellTokens
                ? (nUnitsNew == nUnits + x.nAmountIn && nSatsNew == nSats - (CAmount)nOut)
                : (nUnitsNew == nUnits - nOut && nSatsNew == nSats + (CAmount)x.nAmountIn);
            if (!fReserves)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-reserves");
        }
        pool.nUnits = nUnitsNew;
        pool.nSats = nSatsNew;
        pool.outToken = COutPoint(tx.GetHash(), 0);
        pool.outSats = COutPoint(tx.GetHash(), 1);
        units.Put(TokenPoolKey(tokenID), pool);
        if (tx.nIssuedOp != ISSUED_OP_POOL_SWAP)
            units.Put(IssuedTokenKey(lp.tokenID), lp);
        break;
    }
    default:
        return state.DoS(100, false, REJECT_INVALID, "bad-issued-op");
    }
    fnEraseSpentFrozen();
    return true;
}

// The units view the issuing checks read: ConnectBlock's or the mempool's while a scope is open (UnitsCheckScope).
static const CUnitsView* g_pUnitsCheckView = nullptr;

UnitsCheckScope::UnitsCheckScope(const CUnitsView* pView) : pPrev(g_pUnitsCheckView) { g_pUnitsCheckView = pView; }
UnitsCheckScope::~UnitsCheckScope() { g_pUnitsCheckView = pPrev; }
const CUnitsView* UnitsCheckScope::Current() { return g_pUnitsCheckView; }

extern std::unique_ptr<CUnitsDB> punitsdb;

namespace {
bool NoteCoinDemanded(const Coin& coin)
{
    // D-2026-11-04-1 (3c): every demanded note, plain or pre-auth: each accrues interest the house owes.
    return !coin.IsSpent() && coin.fNote && NoteDemandHeightOf(coin.nDemandHeight) != 0;
}
void KeyAdd(CUnitsView& units, const UnitsKey& key, uint64_t nUnits, bool fAdd)
{
    uint64_t n = 0;
    units.Get(key, n);
    n = fAdd ? n + nUnits : n - std::min(n, nUnits);   // never below zero (deterministic either way)
    if (n == 0)
        units.Erase(key);
    else
        units.Put(key, n);
}
} // namespace

void UnitsQueueSpend(CUnitsView& units, const CTransaction& tx, const CCoinsViewCache& view)
{
    if (tx.IsCoinBase())
        return;
    for (const CTxIn& in : tx.vin) {
        const Coin& coin = view.AccessCoin(in.prevout);
        if (NoteCoinDemanded(coin))
            KeyAdd(units, DemandedKey(coin.nHouseID, coin.nDemandHeight), coin.nNoteUnits, false);
    }
}

void UnitsQueueCreate(CUnitsView& units, const CTransaction& tx, const CCoinsViewCache& view)
{
    const uint256 txid = tx.GetHash();
    for (uint32_t o = 0; o < tx.vout.size(); o++) {
        const Coin& coin = view.AccessCoin(COutPoint(txid, o));
        if (NoteCoinDemanded(coin))
            KeyAdd(units, DemandedKey(coin.nHouseID, coin.nDemandHeight), coin.nNoteUnits, true);
    }
}

uint64_t HouseDemandInterestForChecks(const CHouse& house, int nHeight)
{
    // D-2026-11-04-1 (3c): the interest a house's demanded notes have accrued by nHeight, each tag's units together
    // (one floor per tag: at most a milligram per tag above the per-coin sum, against the house).
    const Consensus::Params& consensus = Params().GetConsensus();
    unsigned __int128 nTotal = 0;
    const auto fnScan = [&](const CUnitsView& view) {
        for (const std::pair<UnitsKey, UnitsValue>& p : view.Scan(UnitsKey(UNITS_DEMANDED).U32(house.nHouseID), UnitsKey(), SIZE_MAX)) {
            const std::vector<unsigned char>& k = p.first.v;
            if (k.size() != 9)
                continue;
            const uint32_t nTag = ((uint32_t)k[5] << 24) | ((uint32_t)k[6] << 16) | ((uint32_t)k[7] << 8) | (uint32_t)k[8];
            uint64_t n = 0;
            try {
                CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
                ss >> n;
            } catch (const std::exception&) {
                continue;
            }
            const CAmount nInterest = NoteDemandInterest(house, nTag, n, (uint32_t)std::max(nHeight, 0), consensus);
            if (nInterest > 0)
                nTotal += (uint64_t)nInterest;
        }
    };
    if (g_pUnitsCheckView) {
        fnScan(*g_pUnitsCheckView);
    } else {
        CUnitsView view(punitsdb.get());
        fnScan(view);
    }
    return nTotal > std::numeric_limits<uint64_t>::max() ? std::numeric_limits<uint64_t>::max() : (uint64_t)nTotal;
}

CAmount HouseAttestedTillSats(const CHouse& house, int nHeight)
{
    if (house.nLastAttestHeight == 0 || (int64_t)nHeight <= (int64_t)house.nLastAttestHeight ||
            ClockSince(house.nLastAttestHeight, nHeight) > (int64_t)HOUSE_ATTEST_STALENESS)   // clock time (GOLD_B §6)
        return 0;
    return house.amountLastAttestReserves;
}

std::function<void(const CHouse&, int, CHouseCapital&)> g_fnCapitalForChecksTestOverride;

static uint64_t SatsToMgAt(CAmount nSats, uint64_t nSatsPerGram)
{
    if (nSats <= 0 || nSatsPerGram == 0)
        return 0;
    const unsigned __int128 n = (unsigned __int128)(uint64_t)nSats * 1000 / nSatsPerGram;   // rounded down: the house's side
    return n > (unsigned __int128)MAX_MONEY ? (uint64_t)MAX_MONEY : (uint64_t)n;
}

bool HouseCapitalForChecks(const CHouse& house, int nHeight, CAmount amountTillSats, CHouseCapital& cap)
{
    cap = CHouseCapital();
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
    const uint64_t nMaxMultiple = std::max<uint64_t>(1, 10000 / std::max<uint32_t>(1, gp.nCapitalMinBps));
    if (g_fnCapitalForChecksTestOverride) {
        g_fnCapitalForChecksTestOverride(house, nHeight, cap);
        if (cap.nCapacityMg == 0)
            cap.nCapacityMg = (uint64_t)std::min<unsigned __int128>((unsigned __int128)cap.nEscrowMg * nMaxMultiple,
                                                                    std::numeric_limits<uint64_t>::max());
        return true;
    }
    uint64_t nBidMax = 0, nAskMax = 0;
    if (!HouseRateMaxForChecks(house.nHouseID, nHeight, 30, nBidMax, nAskMax) || nAskMax == 0)
        return false;
    cap.nEscrowMg = SatsToMgAt(house.ActiveEscrow(), nAskMax);
    cap.nTillMg = SatsToMgAt(amountTillSats, nAskMax);
    // The ramp (GOLD_B §5): each tranche of an active partner's escrow counts at m = 2^(clean periods), up to the floor's
    // limit; a period is nRampPeriodBlocks clock blocks since the latest of the tranche's arrival, the house's last
    // protest (every cure starts with one) and the end of its last suspension, so an unclean event resets every tranche
    // to 1x. (Security stage A V1, 2026-11-08: a suspension, up to a year, counted as clean time.)
    unsigned __int128 nCapacity = 0;
    auto fnAdd = [&](CAmount amount, uint32_t nStart) {
        if (amount <= 0)
            return;
        const uint32_t nClean = std::max({nStart, house.nProtestHeight, house.nDeferEndedHeight});
        const int64_t nPeriods = gp.nRampPeriodBlocks ? ClockSince(nClean, nHeight) / (int64_t)gp.nRampPeriodBlocks : 63;
        const uint64_t m = nPeriods >= 16 ? nMaxMultiple : std::min<uint64_t>(nMaxMultiple, (uint64_t)1 << nPeriods);
        nCapacity += (unsigned __int128)SatsToMgAt(amount, nAskMax) * m;
    };
    for (uint32_t i = 0; i < house.vPartner.size(); i++) {
        const HousePartner& p = house.vPartner[i];
        if (p.status != HOUSE_PARTNER_ACTIVE)
            continue;
        CAmount covered = 0;
        for (const CEscrowTranche& tr : house.vEscrowTranche) {
            if (tr.nPartner != i || covered + tr.amount > p.amountPledge)
                continue;
            covered += tr.amount;
            fnAdd(tr.amount, tr.nStartHeight);
        }
        fnAdd(p.amountPledge - covered, house.nRegisteredHeight);   // a record from before the tranches: from registration
    }
    cap.nCapacityMg = (uint64_t)std::min<unsigned __int128>(nCapacity, std::numeric_limits<uint64_t>::max());
    return true;
}

bool GoldParEligible(const CHouse& house, int nHeight)
{
    if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
        return false;
    CHouseCapital cap;
    if (!HouseCapitalForChecks(house, nHeight, HouseAttestedTillSats(house, nHeight), cap))
        return false;
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
    return (unsigned __int128)cap.nTillMg * 10000 >= (unsigned __int128)house.nMintedUnits * gp.nTillMinBps;
}

uint32_t GoldTillRatioBps(const CHouse& house, int nHeight)
{
    if (house.nMintedUnits == 0)
        return 10000;
    CHouseCapital cap;
    if (!HouseCapitalForChecks(house, nHeight, HouseAttestedTillSats(house, nHeight), cap))
        return 0;
    const unsigned __int128 bps = (unsigned __int128)cap.nTillMg * 10000 / (unsigned __int128)house.nMintedUnits;
    return bps > 10000 ? 10000 : (uint32_t)bps;
}

uint32_t GoldBrassageBps(const CHouse& house, int nHeight)
{
    if (house.nMintedUnits == 0)
        return 0;
    // D-2026-11-05-1 (Michael, option A): an Open house always redeems at par. A thin till only stops issuing, so
    // without this a paying house would charge its holders for keeping a thin till.
    if (HouseEffectiveStatus(house, nHeight) == HOUSE_STATUS_OPEN)
        return 0;
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
    return BrassageBpsAt(GoldTillRatioBps(house, nHeight), gp.nTillMinBps);
}

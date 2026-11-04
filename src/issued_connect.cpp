// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Issued tokens against the units state (server side; issued.cpp holds the context-free rules).

#include <issued.h>

#include <chainparams.h>
#include <coins.h>
#include <consensus/validation.h>
#include <pubkey.h>
#include <txmempool.h>   // MEMPOOL_HEIGHT
#include <house.h>
#include <note.h>
#include <pool.h>
#include <pricefeed.h>
#include <units.h>
#include <txdb.h>
#include <validation.h>   // phousetree (the vault freeze reads house status)
#include <utilstrencodings.h>

#include <limits>
#include <memory>

#include <map>
#include <tuple>
#include <set>

namespace {
std::vector<std::pair<std::tuple<uint8_t, uint32_t, uint256>, uint64_t>> HouseVaults(const CUnitsView& units, uint32_t nHouseID);
/** A house's units of one token across its capital and till. */
uint64_t HouseTokenVaultTotal(const CUnitsView& units, uint32_t nHouseID, const uint256& tokenID)
{
    uint64_t n = 0;
    for (const auto& v : HouseVaults(units, nHouseID))
        if (std::get<2>(v.first) == tokenID)
            n += v.second;
    return n;
}
} // namespace

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
    // 5b, review round 1b: frozen vault gold leaves only with a house's last units of that token - CLOSE, the residual
    // settle, or a partner's RECLAIM when its capital is all the house holds of the token - and then rides on, still
    // frozen (it joins the frozen inputs; the record goes to zero, its grace clock running on). Any other outflow takes
    // at most the house's unfrozen units of the token.
    std::vector<std::pair<UnitsKey, CVaultFrozen>> vVaultFrozenWrite;
    {
        std::map<std::pair<uint32_t, uint256>, uint64_t> mapVaultOut;
        for (const CVaultMove& m : tx.vVaultMove)
            if (m.nDelta < 0)
                mapVaultOut[std::make_pair(m.nHouseID, m.tokenID)] += (uint64_t)(-m.nDelta);
        for (const auto& o : mapVaultOut) {
            const UnitsKey key = VaultFrozenKey(o.first.first, o.first.second);
            CVaultFrozen f;
            if (!units.Get(key, f) || f.nFrozen == 0)
                continue;
            const uint64_t nTotal = HouseTokenVaultTotal(units, o.first.first, o.first.second);
            if (o.second == nTotal) {
                mapFrozenIn[o.first.second] += std::min(f.nFrozen, nTotal);
                f.nFrozen = 0;
                f.nClearSince = (uint32_t)nHeight;
                vVaultFrozenWrite.emplace_back(key, f);
            } else if (o.second > (nTotal > f.nFrozen ? nTotal - f.nFrozen : 0)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-frozen");
            }
        }
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

    // Vault moves (step 5): a vault holds gold tokens only and never goes below zero; the chain-wide total per token
    // follows (it shares out each token's bond cap). Checked here, written with the rest below.
    std::vector<std::pair<UnitsKey, uint64_t>> vVaultWrite;
    std::map<uint256, int64_t> mapVaultTotalDelta;
    for (const CVaultMove& m : tx.vVaultMove) {
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(m.tokenID), token) || token.nKind != ISSUED_KIND_GOLD_MG)
            return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-token");
        // Review round 1 (G1a): gold enters a vault only while its token is trusted (bonded, backed, no shortfall) -
        // a self-made token would otherwise count at par in equity, claims and the insolvency snapshot.
        if (m.nDelta > 0 && !token.fTrusted)
            return state.DoS(0, false, REJECT_INVALID, "bad-vault-move-untrusted");
        // G3i: at most 8 tokens and 64 entries per house, so CLOSE (every entry, one output per token) always fits one
        // transaction.
        if (m.nDelta > 0 && !units.Have(VaultKey(m.nHouseID, m.nKind, m.nPartner, m.tokenID))) {
            std::set<std::tuple<uint8_t, uint32_t, uint256>> setEntry;
            std::set<uint256> setTok;
            for (const auto& e : HouseVaults(units, m.nHouseID)) {
                setEntry.insert(e.first);
                setTok.insert(std::get<2>(e.first));
            }
            for (const CVaultMove& n : tx.vVaultMove)
                if (n.nHouseID == m.nHouseID && n.nDelta > 0) {
                    setEntry.insert(std::make_tuple(n.nKind, n.nPartner, n.tokenID));
                    setTok.insert(n.tokenID);
                }
            if (setEntry.size() > MAX_ISSUED_OUTS || setTok.size() > MAX_ISSUED_TOKENS_PER_TX)
                return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-house-limit");
        }
        const UnitsKey key = VaultKey(m.nHouseID, m.nKind, m.nPartner, m.tokenID);
        uint64_t nBal = 0;
        units.Get(key, nBal);
        if (m.nDelta < 0 && nBal < (uint64_t)(-m.nDelta))
            return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-balance");
        vVaultWrite.emplace_back(key, m.nDelta > 0 ? nBal + (uint64_t)m.nDelta : nBal - (uint64_t)(-m.nDelta));
        mapVaultTotalDelta[m.tokenID] += m.nDelta;
    }
    // (Frozen units can't enter a vault: the frozen-flow rule above makes them ride on, frozen, in annex outputs; frozen
    // vault gold leaves only as checked at the top.)

    const auto fnEraseSpentFrozen = [&]() {
        for (const UnitsKey& key : vFrozenErase)
            units.Erase(key);
        for (const std::pair<UnitsKey, CVaultFrozen>& w : vVaultFrozenWrite)
            units.Put(w.first, w.second);
        for (const std::pair<UnitsKey, uint64_t>& w : vVaultWrite) {
            if (w.second == 0)
                units.Erase(w.first);
            else
                units.Put(w.first, w.second);
        }
        for (const std::pair<const uint256, int64_t>& d : mapVaultTotalDelta) {
            uint64_t nTotal = 0;
            units.Get(VaultTotalKey(d.first), nTotal);
            nTotal = d.second >= 0 ? nTotal + (uint64_t)d.second : nTotal - std::min<uint64_t>(nTotal, (uint64_t)(-d.second));
            if (nTotal == 0)
                units.Erase(VaultTotalKey(d.first));
            else
                units.Put(VaultTotalKey(d.first), nTotal);
        }
    };
    if (tx.nVersion != TRANSACTION_TOKEN_VERSION) {
        fnEraseSpentFrozen();
        return true;
    }

    // D-2026-11-04-1 (3b): creating a token or a pool burns nCreateFeeMg of gold's worth of sECX at the payout price of
    // the block before, to CreationBurnScript outputs: spam can't grow the per-block scans for free. Burned, never paid
    // to a producer (legal GO_NOGO condition 2). No price, no creation. A creation carries no withdrawal: its burn
    // could otherwise back the withdrawal too (ClaimWithdrawalBurn takes any OP_RETURN of the amount).
    if (tx.nIssuedOp == ISSUED_OP_CREATE || tx.nIssuedOp == ISSUED_OP_POOL_CREATE) {
        const Consensus::GramParams& gpFee = Params().GetConsensus().GramAt(nHeight);
        if (gpFee.nCreateFeeMg > 0) {
            uint64_t nPrice = 0;
            if (nHeight < 1 || !PayoutPrice(units, nHeight - 1, gpFee, nPrice) || nPrice == 0)
                return state.DoS(0, false, REJECT_INVALID, "bad-issued-create-no-price");
            const CScript scriptBurn = CreationBurnScript();
            CAmount nBurned = 0;
            for (const CTxOut& o : tx.vout) {
                std::vector<unsigned char> vchObj;
                if (o.scriptPubKey.IsSidechainObj(vchObj))
                    return state.DoS(100, false, REJECT_INVALID, "bad-issued-create-sidechain-obj");
                if (o.scriptPubKey == scriptBurn)
                    nBurned += o.nValue;
            }
            if (nBurned < CreationBurnSats(nPrice, gpFee.nCreateFeeMg))
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
        // Review round 1 (G1g, 1b): one token per backing (contract, address), so one pile of gold can't back two
        // tokens. First come - but a token that is not trusted 30 days after its creation (or after it stopped being
        // trusted) gives the address up, so nobody can squat a custody address with a token that never earns trust.
        if (token.nKind == ISSUED_KIND_GOLD_MG) {
            const UnitsKey keyAddr = UnitsKey(UNITS_BACKING_ADDRESS).Bytes(token.vchBackingContract).Bytes(token.vchBackingAddress);
            uint256 owner;
            if (units.Get(keyAddr, owner)) {
                CIssuedToken tokenOwner;
                const uint32_t nWindow = Params().GetConsensus().GramAt(nHeight).nFreezeGraceBlocks;
                if (units.Get(IssuedTokenKey(owner), tokenOwner)) {
                    const int64_t nSince = tokenOwner.nUntrustedSince ? tokenOwner.nUntrustedSince : tokenOwner.nCreateHeight;
                    if (tokenOwner.fTrusted || (int64_t)nHeight - nSince < (int64_t)nWindow)
                        return state.DoS(0, false, REJECT_INVALID, "bad-issued-create-backing-address-taken");
                }
            }
            units.Put(keyAddr, token.tokenID);
        }
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
        // 5b: freezes on house vaults - at most the house's units of the token; the grace clock (CVaultFrozen).
        std::vector<std::pair<UnitsKey, CVaultFrozen>> vVaultFreeze;
        const Consensus::GramParams& gpFreeze = Params().GetConsensus().GramAt(nHeight);
        for (const CVaultFreezeTarget& v : x.vVault) {
            if (v.nFrozen > HouseTokenVaultTotal(units, v.nHouseID, x.tokenID))
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-units");
            // G3e: no new FREEZE once the house has failed or wound down - its insolvency snapshot ranked notes,
            // deposits and partners on this gold, and a wound-down partner must still be able to reclaim (UNFREEZE stays
            // open). The house as the caller sees it (none: no check - the crash-replay path, whose HouseDB already
            // holds this block's effects).
            if (tx.nIssuedOp == ISSUED_OP_FREEZE && pfnGetHouse && *pfnGetHouse) {
                CHouse houseF;
                if ((*pfnGetHouse)(v.nHouseID, houseF)) {
                    const char cStatus = HouseEffectiveStatus(houseF, nHeight);
                    if (cStatus == HOUSE_STATUS_INSOLVENT || cStatus == HOUSE_STATUS_WOUNDDOWN)
                        return state.DoS(0, false, REJECT_INVALID, "bad-issued-freeze-house-failed");
                }
            }
            const UnitsKey key = VaultFrozenKey(v.nHouseID, x.tokenID);
            CVaultFrozen f;
            units.Get(key, f);
            if (tx.nIssuedOp == ISSUED_OP_FREEZE ? v.nFrozen <= f.nFrozen : v.nFrozen >= f.nFrozen)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-freeze-direction");
            if (f.nFrozen == 0 && v.nFrozen > 0) {
                if (f.nGraceStart == 0 ||
                        (f.nClearSince != 0 && (int64_t)nHeight - (int64_t)f.nClearSince >= (int64_t)gpFreeze.nFreezeClearBlocks))
                    f.nGraceStart = (uint32_t)nHeight;
                f.nClearSince = 0;
            }
            if (v.nFrozen == 0)
                f.nClearSince = (uint32_t)nHeight;
            f.nFrozen = v.nFrozen;
            vVaultFreeze.emplace_back(key, f);
        }
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
        for (const std::pair<UnitsKey, CVaultFrozen>& w : vVaultFreeze)
            units.Put(w.first, w.second);
        break;
    }
    case ISSUED_OP_POOL_CREATE: {
        IssuedPoolCreate x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(x.tokenID), token))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-pool-token");
        // Gold tokens; dollar tokens only from the height a later release sets; never a freeze-keyed token (R1-6).
        const Consensus::Params& cp = Params().GetConsensus();
        if (token.nKind == ISSUED_KIND_POOL_LP || (token.nKind == ISSUED_KIND_USD_CENTS && nHeight < cp.nDollarPoolHeight))
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
                !cToken.fOracleBond || !cSats.fOracleBond)
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
    case ISSUED_OP_BOND: {
        IssuedBond x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(x.tokenID), token))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-bond-token");
        if (!CPubKey(token.vchIssuerKey).VerifyStrict(IssuedSigHash(tx), x.vchIssuerSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-bond-sig");
        // A token has one bond coin: a new BOND consolidates it (tx_verify pinned any bond input to this token's
        // script), and the bond may not shrink, or a "top-up" would be an unbond without the delay.
        CAmount nOldIn = 0;
        bool fSpendsOld = false;
        for (const CTxIn& in : tx.vin) {
            const Coin& coin = view.AccessCoin(in.prevout);
            if (!coin.IsSpent() && coin.fOracleBond && IsIssuedBondScript(coin.out.scriptPubKey)) {
                nOldIn += coin.out.nValue;
                if (in.prevout == token.bondOutpoint)
                    fSpendsOld = true;
            }
        }
        if (!token.bondOutpoint.IsNull() && !fSpendsOld)
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-bond-not-consolidated");
        if (tx.vout[0].nValue < nOldIn)
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-bond-shrink");
        // Valued in grams when locked (design draft 9): no price, no bond. Chain state, not the sender's fault.
        const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
        uint64_t nSatsPerGram = 0;
        if (!PriceFeedPayoutView(units, nHeight - 1, gp, nSatsPerGram) || nSatsPerGram == 0)
            return state.DoS(0, false, REJECT_INVALID, "bad-issued-bond-no-price");
        token.bondOutpoint = COutPoint(tx.GetHash(), 0);
        token.nBondSats = tx.vout[0].nValue;
        token.nBondMgAtLock = (uint64_t)((unsigned __int128)token.nBondSats * 1000 / nSatsPerGram);
        token.nBondTopUpDeadline = 0;
        token.nUnbondRequestHeight = 0;
        units.Put(IssuedTokenKey(x.tokenID), token);
        break;
    }
    case ISSUED_OP_UNBOND: {
        IssuedUnbond x;
        DecodeIssuedPayload(tx.vchIssuedPayload, x);
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(x.tokenID), token))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-unbond-token");
        if (!CPubKey(token.vchIssuerKey).VerifyStrict(IssuedSigHash(tx), x.vchIssuerSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-unbond-sig");
        if (token.bondOutpoint.IsNull())
            return state.DoS(100, false, REJECT_INVALID, "bad-issued-unbond-none");
        if (!x.fWithdraw) {
            if (token.nUnbondRequestHeight != 0)
                return state.DoS(0, false, REJECT_INVALID, "bad-issued-unbond-pending");
            token.nUnbondRequestHeight = nHeight;   // the bond stops counting at once
        } else {
            if (token.nUnbondRequestHeight == 0 || nHeight < token.nUnbondRequestHeight + (int)ISSUED_UNBOND_DELAY)
                return state.DoS(0, false, REJECT_INVALID, "bad-issued-unbond-early");
            bool fSpends = false;
            for (const CTxIn& in : tx.vin)
                if (in.prevout == token.bondOutpoint)
                    fSpends = true;
            if (!fSpends)
                return state.DoS(100, false, REJECT_INVALID, "bad-issued-unbond-coin");
            token.bondOutpoint.SetNull();
            token.nBondSats = 0;
            token.nBondMgAtLock = 0;
            token.nBondTopUpDeadline = 0;
            token.nUnbondRequestHeight = 0;
        }
        units.Put(IssuedTokenKey(x.tokenID), token);
        break;
    }
    default:
        return state.DoS(100, false, REJECT_INVALID, "bad-issued-op");
    }
    fnEraseSpentFrozen();
    return true;
}

void TokenPoolsEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp)
{
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(UnitsKey(UNITS_TOKEN_POOL), UnitsKey(), SIZE_MAX)) {
        CTokenPool pool;
        try {
            CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
            ss >> pool;
        } catch (const std::exception&) {
            continue;
        }
        if (pool.nUnits == 0)
            continue;
        CPoolSample sample;
        sample.nSatsPerGram = (uint64_t)((unsigned __int128)pool.nSats * 1000 / pool.nUnits);
        sample.nUnits = pool.nUnits;
        CIssuedToken tokenS;
        if (units.Get(IssuedTokenKey(pool.tokenID), tokenS)) {
            uint64_t nHeld = 0;
            units.Get(VaultTotalKey(pool.tokenID), nHeld);
            sample.nSupply = tokenS.nSupply;
            sample.fCounts = tokenS.fTrusted && nHeld > 0 ? 1 : 0;
        }
        units.Put(PoolSampleKey(pool.tokenID, (uint32_t)nHeight), sample);
        // Back to the oldest height a payload may bind a price at, plus that height's view.
        const int64_t nOld = (int64_t)nHeight - (int64_t)(gp.nPoolViewBlocks + gp.nPriceBackBlocks);
        if (nOld >= 0 && units.Have(PoolSampleKey(pool.tokenID, (uint32_t)nOld)))
            units.Erase(PoolSampleKey(pool.tokenID, (uint32_t)nOld));
    }
}

bool TokenPoolView(const CUnitsView& units, const uint256& tokenID, int nHeight, const Consensus::GramParams& gp,
                   uint64_t& nSatsPerGram, bool& fDeep)
{
    return TokenPoolView(units, tokenID, nHeight, gp, nSatsPerGram, fDeep, nullptr);
}

bool TokenPoolView(const CUnitsView& units, const uint256& tokenID, int nHeight, const Consensus::GramParams& gp,
                   uint64_t& nSatsPerGram, bool& fDeep, bool* pfCounts)
{
    // Review round 1 (G1c): the view is the lower median of the samples (a one-block spike can't move it), depth is
    // judged against the supply each sample recorded, and the pool counts for the payout price only with a full
    // window of samples taken while its token was trusted and held in houses' vaults.
    const int64_t nFrom = std::max<int64_t>(0, (int64_t)nHeight - (int64_t)gp.nPoolViewBlocks + 1);
    unsigned __int128 nUnitsSum = 0, nSupplySum = 0;
    std::vector<uint64_t> vPrice;
    bool fAllCount = true;
    uint64_t nCount = 0;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(UnitsKey(UNITS_POOL_SAMPLE).Hash(tokenID),
                                                                PoolSampleKey(tokenID, (uint32_t)nFrom), SIZE_MAX)) {
        const std::vector<unsigned char>& k = p.first.v;   // prefix + token (32) + height (4)
        const uint32_t nH = ((uint32_t)k[33] << 24) | ((uint32_t)k[34] << 16) | ((uint32_t)k[35] << 8) | (uint32_t)k[36];
        if ((int64_t)nH > nHeight)
            break;
        CPoolSample sample;
        try {
            CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
            ss >> sample;
        } catch (const std::exception&) {
            continue;
        }
        vPrice.push_back(sample.nSatsPerGram);
        nUnitsSum += sample.nUnits;
        nSupplySum += sample.nSupply;
        fAllCount = fAllCount && sample.fCounts;
        nCount++;
    }
    if (nCount == 0)
        return false;
    nSatsPerGram = OracleLowerMedian(vPrice);
    fDeep = nSupplySum > 0 && nUnitsSum * 10000 >= nSupplySum * gp.nPoolDepthMinBps;
    if (pfCounts)
        *pfCounts = fAllCount && nCount >= gp.nPoolViewBlocks;
    return true;
}

bool PayoutPrice(const CUnitsView& units, int nHeight, const Consensus::GramParams& gp, uint64_t& nSatsPerGram)
{
    uint64_t nOracle = 0;
    const bool fOracle = PriceFeedPayoutView(units, nHeight, gp, nOracle) && nOracle > 0;
    std::vector<uint64_t> vDeep;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(UnitsKey(UNITS_TOKEN_POOL), UnitsKey(), SIZE_MAX)) {
        CTokenPool pool;
        try {
            CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
            ss >> pool;
        } catch (const std::exception&) {
            continue;
        }
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(pool.tokenID), token) || token.nKind != ISSUED_KIND_GOLD_MG)
            continue;
        uint64_t nView = 0;
        bool fDeep = false, fCounts = false;
        if (TokenPoolView(units, pool.tokenID, nHeight, gp, nView, fDeep, &fCounts) && fDeep && fCounts && nView > 0)
            vDeep.push_back(nView);
    }
    if (vDeep.empty()) {
        if (!fOracle)
            return false;
        nSatsPerGram = nOracle;   // shallow pools: the oracle alone
        return true;
    }
    const uint64_t nPools = OracleLowerMedian(vDeep);
    const uint64_t nCap = (uint64_t)((unsigned __int128)nPools * (10000 + gp.nPayoutCapBps) / 10000);
    nSatsPerGram = std::min(nCap, fOracle ? std::max(nOracle, nPools) : nPools);
    return true;
}

bool IssuedBurnOverdue(const CUnitsView& units, const CIssuedToken& token, uint64_t nPaidUnits, int nHeight,
                       const Consensus::GramParams& gp)
{
    if (token.nBurnSeq == 0)
        return false;
    // The units of every burn older than nBurnPayBlocks: the cumulative count of the newest such burn. Burn heights
    // rise with their sequence, so a binary search finds it in O(log burns).
    const int64_t nCutoff = (int64_t)nHeight - (int64_t)gp.nBurnPayBlocks;   // burns at heights below this are due
    uint64_t lo = 0, hi = token.nBurnSeq;   // find the first burn at or above the cutoff
    while (lo < hi) {
        const uint64_t mid = lo + (hi - lo) / 2;
        CIssuedBurn b;
        if (!units.Get(IssuedBurnKey(token.tokenID, mid), b))
            return false;
        if ((int64_t)b.nHeight < nCutoff)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo == 0)
        return false;   // no burn is due yet
    CIssuedBurn due;
    if (!units.Get(IssuedBurnKey(token.tokenID, lo - 1), due))
        return false;
    const uint64_t nUnpaid = due.nCumUnits > nPaidUnits ? due.nCumUnits - nPaidUnits : 0;
    const uint64_t nThreshold = std::max<uint64_t>(gp.nBurnUnpaidMinMg,
                                                   (uint64_t)((unsigned __int128)token.nSupply * gp.nBurnUnpaidBps / 10000));
    return nUnpaid > nThreshold;
}

void IssuedTokensEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp,
                          const std::function<bool(const CIssuedToken&)>& fnPoolDeep,
                          const std::function<bool(const CIssuedToken&)>& fnBackingClean)
{
    uint64_t nSatsPerGram = 0;
    const bool fPrice = PriceFeedPayoutView(units, nHeight, gp, nSatsPerGram) && nSatsPerGram != 0;
    uint64_t nPayout = 0;
    const bool fPayoutPrice = PayoutPrice(units, nHeight, gp, nPayout) && nPayout != 0;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(UnitsKey(UNITS_ISSUED_TOKEN), UnitsKey(), SIZE_MAX)) {
        CIssuedToken token;
        try {
            CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
            ss >> token;
        } catch (const std::exception&) {
            continue;
        }
        const CIssuedToken before = token;

        // The top-up clock: only a known price moves it.
        if (!token.bondOutpoint.IsNull() && token.nUnbondRequestHeight == 0 && fPrice) {
            const uint64_t nMgNow = (uint64_t)((unsigned __int128)token.nBondSats * 1000 / nSatsPerGram);
            if (nMgNow < token.nBondMgAtLock) {
                if (token.nBondTopUpDeadline == 0)
                    token.nBondTopUpDeadline = nHeight + (int)ISSUED_BOND_TOPUP_BLOCKS;
            } else {
                token.nBondTopUpDeadline = 0;
            }
        }

        // The flag issuing reads (one block behind: set here at the block's end): a fresh backing report covering the
        // supply, and a payout price (D-2026-11-01-6 item 3: issuing against a token stops while its backing report or
        // its price inputs are stale; redemption never stops).
        // Review round 1 (G1, G1f): trusted = gold, bonded and not unbonding, no bond shortfall past its deadline, and
        // backing clean. A shortfall past the deadline stops issuing (R3-2), not just k -> 1.
        const bool fBackingClean = token.nKind == ISSUED_KIND_GOLD_MG && fnBackingClean(token);
        const bool fShortfall = token.nBondTopUpDeadline != 0 && nHeight > token.nBondTopUpDeadline;
        uint256 addrOwner;
        const bool fOwnsAddress = units.Get(UnitsKey(UNITS_BACKING_ADDRESS).Bytes(token.vchBackingContract).Bytes(token.vchBackingAddress),
                                            addrOwner) && addrOwner == token.tokenID;
        const bool fTrusted = fBackingClean && !token.bondOutpoint.IsNull() && token.nUnbondRequestHeight == 0 && !fShortfall &&
                              token.nBondMgAtLock >= gp.nIssuerBondMinMg && fOwnsAddress;
        if (fTrusted)
            token.nUntrustedSince = 0;
        else if (token.fTrusted)
            token.nUntrustedSince = nHeight;
        token.fTrusted = fTrusted ? 1 : 0;
        token.fBackingOk = fTrusted && fPayoutPrice ? 1 : 0;

        // The k ladder.
        const bool fClean = fTrusted && fnPoolDeep(token);
        if (!fClean) {
            token.nK = 1;
            token.fKClean = 0;
        } else if (!token.fKClean) {
            token.fKClean = 1;
            token.nKSince = nHeight;
        } else if (token.nK < ISSUED_K_MAX && nHeight - token.nKSince >= (int)ISSUED_K_STEP_BLOCKS) {
            token.nK *= 2;
            token.nKSince = nHeight;
        }

        CDataStream a(SER_DISK, CLIENT_VERSION), b(SER_DISK, CLIENT_VERSION);
        a << before;
        b << token;
        if (a.str() != b.str())
            units.Put(p.first, token);
    }
}

namespace {

/** A house's vault balances: (kind, partner, token) -> units. */
std::vector<std::pair<std::tuple<uint8_t, uint32_t, uint256>, uint64_t>> HouseVaults(const CUnitsView& units, uint32_t nHouseID)
{
    std::vector<std::pair<std::tuple<uint8_t, uint32_t, uint256>, uint64_t>> v;
    for (const std::pair<UnitsKey, UnitsValue>& p : units.Scan(UnitsKey(UNITS_VAULT).U32(nHouseID), UnitsKey(), SIZE_MAX)) {
        const std::vector<unsigned char>& k = p.first.v;   // prefix + house (4) + kind (1) + partner (4) + token (32)
        if (k.size() != 42)
            continue;
        const uint8_t nKind = k[5];
        const uint32_t nPartner = ((uint32_t)k[6] << 24) | ((uint32_t)k[7] << 16) | ((uint32_t)k[8] << 8) | (uint32_t)k[9];
        uint256 token;
        std::copy(k.begin() + 10, k.end(), token.begin());
        uint64_t n = 0;
        try {
            CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
            ss >> n;
        } catch (const std::exception&) {
            continue;
        }
        v.emplace_back(std::make_tuple(nKind, nPartner, token), n);
    }
    return v;
}

} // namespace

bool CheckHouseVaultMoves(const CTransaction& tx, const CHouse& house, int nHeight, const CUnitsView& units,
                          CValidationState& state)
{
    // A CLOSE or a RECLAIM with gold left must move it, and a WINDDOWN waits for an empty till: checked below even
    // with no moves (review round 1, G3c/G3d).
    if (tx.vVaultMove.empty() && tx.nHouseOp != HOUSE_OP_CLOSE && tx.nHouseOp != HOUSE_OP_RECLAIM &&
            tx.nHouseOp != HOUSE_OP_WINDDOWN)
        return true;
    for (const CVaultMove& m : tx.vVaultMove)
        if (m.nHouseID != house.nHouseID)
            return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-house");

    if (tx.nHouseOp == HOUSE_OP_TOPUP) {
        HouseTopup t;
        DecodeHousePayload(tx.vchHousePayload, t);
        // D-2026-11-04-1 (3a): one partner's TOPUP adds only tokens the house already holds. A token new to the house
        // takes a slot (at most 8), so it comes in by the partners' agreement: the M-of-N TILL op. And a dust slot
        // (a token the house holds at most HOUSE_DUST_SLOT_MG of) can be cleared: the partner takes their whole entry
        // of it out in a TOPUP that adds at least as many mg of the house's other tokens, so capital never falls.
        std::map<uint256, uint64_t> mapHouse, mapMine;
        for (const auto& v : HouseVaults(units, house.nHouseID)) {
            mapHouse[std::get<2>(v.first)] += v.second;
            if (std::get<0>(v.first) == VAULT_CAPITAL && std::get<1>(v.first) == t.nPartnerIndex)
                mapMine[std::get<2>(v.first)] += v.second;
        }
        uint64_t nAdd = 0, nRemove = 0;
        std::set<uint256> setAdd, setRemove;
        for (const CVaultMove& m : tx.vVaultMove) {
            if (m.nKind != VAULT_CAPITAL || m.nPartner != t.nPartnerIndex || m.nDelta == 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-topup");
            if (m.nDelta > 0) {
                if (!mapHouse.count(m.tokenID))
                    return state.DoS(10, false, REJECT_INVALID, "bad-vault-move-topup-new-token");
                if (!setAdd.insert(m.tokenID).second)
                    return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-topup");
                nAdd += (uint64_t)m.nDelta;
            } else {
                const auto itHouse = mapHouse.find(m.tokenID);
                const auto itMine = mapMine.find(m.tokenID);
                if (itHouse == mapHouse.end() || itHouse->second > HOUSE_DUST_SLOT_MG || itMine == mapMine.end() ||
                        (uint64_t)(-m.nDelta) != itMine->second || !setRemove.insert(m.tokenID).second)
                    return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-topup-clear");
                nRemove += (uint64_t)(-m.nDelta);
            }
        }
        for (const uint256& id : setRemove)
            if (setAdd.count(id))
                return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-topup-clear");
        if (nRemove > 0 && nAdd < nRemove)
            return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-topup-clear");
        uint64_t nHeld = 0;
        for (const std::pair<const uint256, uint64_t>& h : mapMine)
            nHeld += h.second;
        if (nHeld + nAdd - nRemove < HOUSE_MIN_GOLD_PLEDGE_MG)
            return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-min-pledge");
        return true;
    }
    // Every vault entry of the house, whole, into the noteholders' mutual fund (CLOSE, and the residual settle).
    const auto fnAllToFund = [&](const std::string& strReason) {
        const auto vVault = HouseVaults(units, house.nHouseID);
        if (tx.vVaultMove.size() != vVault.size())
            return state.DoS(100, false, REJECT_INVALID, strReason);
        for (const auto& v : vVault) {
            bool fFound = false;
            for (const CVaultMove& m : tx.vVaultMove)
                if (m.nKind == std::get<0>(v.first) && m.nPartner == std::get<1>(v.first) && m.tokenID == std::get<2>(v.first) &&
                        m.nDelta < 0 && (uint64_t)(-m.nDelta) == v.second)
                    fFound = true;
            if (!fFound)
                return state.DoS(100, false, REJECT_INVALID, strReason);
        }
        for (const CIssuedOut& o : tx.vIssuedOut)
            if (!IsMutualFundScript(tx.vout[o.nOut].scriptPubKey))
                return state.DoS(100, false, REJECT_INVALID, strReason + "-dest");
        return true;
    };
    if (tx.nHouseOp == HOUSE_OP_RECLAIM && HouseEffectiveStatus(house, nHeight) == HOUSE_STATUS_INSOLVENT) {
        // Review round 1b (G3b): the residual settle closes the house for good, so it takes whatever gold is left - the
        // floors' remainders, gold claimants left, frozen gold, tokens past their grace - to the fund, as CLOSE would
        // (rather than wait for CLOSE: a few milligrams of rounding would otherwise hold every partner back two years).
        return fnAllToFund("bad-vault-move-settle");
    }
    if (tx.nHouseOp == HOUSE_OP_RECLAIM) {
        // The partner's gold leaves with its placeholder pledge, all of it: whatever let the reclaim through (tail
        // expired, wind-down) releases the whole pledge.
        HouseReclaim r;
        DecodeHousePayload(tx.vchHousePayload, r);
        std::map<uint256, uint64_t> mapHeld;
        for (const auto& v : HouseVaults(units, house.nHouseID))
            if (std::get<0>(v.first) == VAULT_CAPITAL && std::get<1>(v.first) == r.nPartnerIndex)
                mapHeld[std::get<2>(v.first)] = v.second;
        if (tx.vVaultMove.size() != mapHeld.size())
            return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-reclaim");
        for (const CVaultMove& m : tx.vVaultMove)
            if (m.nKind != VAULT_CAPITAL || m.nPartner != r.nPartnerIndex || m.nDelta >= 0 ||
                    !mapHeld.count(m.tokenID) || (uint64_t)(-m.nDelta) != mapHeld[m.tokenID])
                return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-reclaim");
        return true;
    }
    if (tx.nHouseOp == HOUSE_OP_WINDDOWN) {
        // G3d: after a wind-down the till can't move out (TILL out only while Open or Stressed), and RECLAIM takes
        // capital only - so the till must be empty first.
        if (!tx.vVaultMove.empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-op");
        for (const auto& v : HouseVaults(units, house.nHouseID))
            if (std::get<0>(v.first) == VAULT_TILL)
                return state.DoS(10, false, REJECT_INVALID, "bad-house-winddown-till-gold");
        return true;
    }
    if (tx.nHouseOp == HOUSE_OP_CLOSE) {
        // 5b: CLOSE takes everything left - every vault entry of the house, whole - into the noteholders' mutual fund
        // (locked until CM-3 defines its spender, like the ECX the same CLOSE sends there).
        return fnAllToFund("bad-vault-move-close");
    }
    if (tx.nHouseOp == HOUSE_OP_TILL) {
        const char chStatus = HouseEffectiveStatus(house, nHeight);
        for (const CVaultMove& m : tx.vVaultMove) {
            if (m.nKind != VAULT_TILL)
                return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-till");
            // DEFER locks the till where the holders can reach it; a failed house's till is the holders'.
            if (m.nDelta < 0 && chStatus != HOUSE_STATUS_OPEN && chStatus != HOUSE_STATUS_STRESSED)
                return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-till-locked");
        }
        return true;
    }
    return state.DoS(100, false, REJECT_INVALID, "bad-vault-move-op");
}

static const CUnitsView* g_pUnitsCheckView = nullptr;

UnitsCheckScope::UnitsCheckScope(const CUnitsView* pView) : pPrev(g_pUnitsCheckView) { g_pUnitsCheckView = pView; }
UnitsCheckScope::~UnitsCheckScope() { g_pUnitsCheckView = pPrev; }

extern std::unique_ptr<CUnitsDB> punitsdb;

std::function<void(const CHouse&, int, CGoldCount&)> g_fnGoldForChecksTestOverride;

namespace {
std::vector<std::pair<std::tuple<uint8_t, uint32_t, uint256>, uint64_t>> HouseVaults(const CUnitsView& units, uint32_t nHouseID);
} // namespace

std::map<uint256, uint64_t> HouseVaultTotalsForChecks(uint32_t nHouseID)
{
    std::map<uint256, uint64_t> mapTotal;
    const auto fnScan = [&](const CUnitsView& view) {
        for (const auto& v : HouseVaults(view, nHouseID))
            mapTotal[std::get<2>(v.first)] += v.second;
    };
    if (g_pUnitsCheckView) {
        fnScan(*g_pUnitsCheckView);
    } else {
        CUnitsView view(punitsdb.get());
        fnScan(view);
    }
    return mapTotal;
}

bool IssuedTokenValuedForChecks(const uint256& tokenID, int nHeight, uint32_t nGrace)
{
    CIssuedToken token;
    if (g_pUnitsCheckView)
        return g_pUnitsCheckView->Get(IssuedTokenKey(tokenID), token) && IssuedTokenValuedAt(token, nHeight, nGrace);
    CUnitsView view(punitsdb.get());
    return view.Get(IssuedTokenKey(tokenID), token) && IssuedTokenValuedAt(token, nHeight, nGrace);
}

bool IssuedTokenTrustedForChecks(const uint256& tokenID)
{
    CIssuedToken token;
    if (g_pUnitsCheckView)
        return g_pUnitsCheckView->Get(IssuedTokenKey(tokenID), token) && token.fTrusted;
    CUnitsView view(punitsdb.get());
    return view.Get(IssuedTokenKey(tokenID), token) && token.fTrusted;
}

std::map<uint256, uint64_t> HouseVaultFrozenForChecks(uint32_t nHouseID)
{
    std::map<uint256, uint64_t> mapFrozen;
    const auto fnScan = [&](const CUnitsView& view) {
        for (const std::pair<const uint256, uint64_t>& t : HouseVaultTotalsForChecks(nHouseID)) {
            CVaultFrozen f;
            if (view.Get(VaultFrozenKey(nHouseID, t.first), f) && f.nFrozen > 0)
                mapFrozen[t.first] = std::min(f.nFrozen, t.second);
        }
    };
    if (g_pUnitsCheckView) {
        fnScan(*g_pUnitsCheckView);
    } else {
        CUnitsView view(punitsdb.get());
        fnScan(view);
    }
    return mapFrozen;
}

std::map<uint256, uint64_t> HouseVaultFreeTotalsForChecks(uint32_t nHouseID, int nHeight)
{
    // What claims divide and the insolvency snapshot counts: each valued token's units less everything frozen (review
    // round 1, G1d: a token no longer trusted past its grace stays in the vault, for the fund at CLOSE).
    std::map<uint256, uint64_t> mapFree = HouseVaultTotalsForChecks(nHouseID);
    const uint32_t nGrace = Params().GetConsensus().GramAt(nHeight).nFreezeGraceBlocks;
    const auto fnSub = [&](const CUnitsView& view) {
        for (std::pair<const uint256, uint64_t>& t : mapFree) {
            CIssuedToken token;
            if (!view.Get(IssuedTokenKey(t.first), token) || !IssuedTokenValuedAt(token, nHeight, nGrace)) {
                t.second = 0;
                continue;
            }
            CVaultFrozen f;
            if (view.Get(VaultFrozenKey(nHouseID, t.first), f))
                t.second = t.second > f.nFrozen ? t.second - f.nFrozen : 0;
        }
    };
    if (g_pUnitsCheckView) {
        fnSub(*g_pUnitsCheckView);
    } else {
        CUnitsView view(punitsdb.get());
        fnSub(view);
    }
    for (auto it = mapFree.begin(); it != mapFree.end();)
        it = it->second == 0 ? mapFree.erase(it) : std::next(it);
    return mapFree;
}

std::map<uint256, uint64_t> HouseVaultFrozenZeroForChecks(uint32_t nHouseID, int nHeight)
{
    std::map<uint256, uint64_t> mapZero;
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
    const auto fnScan = [&](const CUnitsView& view) {
        for (const std::pair<const uint256, uint64_t>& t : HouseVaultTotalsForChecks(nHouseID)) {
            CVaultFrozen f;
            if (view.Get(VaultFrozenKey(nHouseID, t.first), f) && f.nFrozen > 0 &&
                    (int64_t)nHeight >= (int64_t)f.nGraceStart + (int64_t)gp.nFreezeGraceBlocks)
                mapZero[t.first] = std::min(f.nFrozen, t.second);
        }
    };
    if (g_pUnitsCheckView) {
        fnScan(*g_pUnitsCheckView);
    } else {
        CUnitsView view(punitsdb.get());
        fnScan(view);
    }
    return mapZero;
}

std::vector<CVaultEntry> HouseVaultEntriesForChecks(uint32_t nHouseID)
{
    std::vector<CVaultEntry> v;
    const auto fnScan = [&](const CUnitsView& view) {
        for (const auto& e : HouseVaults(view, nHouseID))
            v.push_back(CVaultEntry{std::get<0>(e.first), std::get<1>(e.first), std::get<2>(e.first), e.second});
    };
    if (g_pUnitsCheckView) {
        fnScan(*g_pUnitsCheckView);
    } else {
        CUnitsView view(punitsdb.get());
        fnScan(view);
    }
    return v;
}

namespace {
bool NoteCoinQueued(const Coin& coin)
{
    // The house-dischargeable queue: every pre-auth demand (a B3 formal demand or a queue demand; review round 1, G9).
    // A plain demand needs its holder to redeem, so it can't hold the house's queue up; it may still be paid from
    // capital when its holder comes.
    return !coin.IsSpent() && coin.fNote && NoteDemandIsPreAuth(coin.nDemandHeight);
}
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
void QueueAdd(CUnitsView& units, uint32_t nHouseID, uint32_t nDemandHeight, uint64_t nUnits, bool fAdd)
{
    const UnitsKey key = QueueKey(nHouseID, nDemandHeight);
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
        if (NoteCoinQueued(coin))
            QueueAdd(units, coin.nHouseID, NoteDemandHeightOf(coin.nDemandHeight), coin.nNoteUnits, false);
        if (NoteCoinDemanded(coin))
            KeyAdd(units, DemandedKey(coin.nHouseID, coin.nDemandHeight), coin.nNoteUnits, false);
    }
}

void UnitsQueueCreate(CUnitsView& units, const CTransaction& tx, const CCoinsViewCache& view)
{
    const uint256 txid = tx.GetHash();
    for (uint32_t o = 0; o < tx.vout.size(); o++) {
        const Coin& coin = view.AccessCoin(COutPoint(txid, o));
        if (NoteCoinQueued(coin))
            QueueAdd(units, coin.nHouseID, NoteDemandHeightOf(coin.nDemandHeight), coin.nNoteUnits, true);
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

uint64_t HouseQueueUnitsBeforeForChecks(uint32_t nHouseID, uint32_t nDemandHeight)
{
    uint64_t nTotal = 0;
    const auto fnScan = [&](const CUnitsView& view) {
        for (const std::pair<UnitsKey, UnitsValue>& p : view.Scan(UnitsKey(UNITS_QUEUE).U32(nHouseID), UnitsKey(), SIZE_MAX)) {
            const std::vector<unsigned char>& k = p.first.v;
            if (k.size() != 9)
                continue;
            const uint32_t h = ((uint32_t)k[5] << 24) | ((uint32_t)k[6] << 16) | ((uint32_t)k[7] << 8) | (uint32_t)k[8];
            if (h >= nDemandHeight)
                break;
            uint64_t n = 0;
            try {
                CDataStream ss(p.second, SER_DISK, CLIENT_VERSION);
                ss >> n;
            } catch (const std::exception&) {
                continue;
            }
            nTotal += n;
        }
    };
    if (g_pUnitsCheckView) {
        fnScan(*g_pUnitsCheckView);
    } else {
        CUnitsView view(punitsdb.get());
        fnScan(view);
    }
    return nTotal;
}

uint32_t UnpricedBlocksForChecks(int nFrom, int nTo)
{
    if (g_nPayoutPriceTestOverride)
        return 0;   // unit tests: every block is priced
    if (g_pUnitsCheckView)
        return PriceFeedUnpricedBlocks(*g_pUnitsCheckView, nFrom, nTo);
    CUnitsView view(punitsdb.get());
    return PriceFeedUnpricedBlocks(view, nFrom, nTo);
}

bool GoldParEligible(const CHouse& house, int nHeight)
{
    if (HouseEffectiveStatus(house, nHeight) != HOUSE_STATUS_OPEN)
        return false;
    CGoldCount gold;
    HouseGoldForChecks(house, nHeight, gold);
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
    return (unsigned __int128)gold.nTillMg * 10000 >= (unsigned __int128)house.nMintedUnits * gp.nTillMinBps;
}

uint64_t g_nPayoutPriceTestOverride = 0;

bool PayoutPriceForChecks(int nPriceHeight, uint64_t& nSatsPerGram)
{
    if (g_nPayoutPriceTestOverride) {
        nSatsPerGram = g_nPayoutPriceTestOverride;
        return true;
    }
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nPriceHeight);
    if (g_pUnitsCheckView)
        return PayoutPrice(*g_pUnitsCheckView, nPriceHeight, gp, nSatsPerGram);
    CUnitsView view(punitsdb.get());
    return PayoutPrice(view, nPriceHeight, gp, nSatsPerGram);
}

void HouseGoldForChecks(const CHouse& house, int nHeight, CGoldCount& count)
{
    if (g_fnGoldForChecksTestOverride) {
        count = CGoldCount();
        g_fnGoldForChecksTestOverride(house, nHeight, count);
        return;
    }
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
    if (g_pUnitsCheckView) {
        HouseGoldCounted(*g_pUnitsCheckView, house, nHeight, gp, false, count);
    } else {
        CUnitsView view(punitsdb.get());
        HouseGoldCounted(view, house, nHeight, gp, false, count);
    }
}

void HouseGoldForChecksNoPriceGate(const CHouse& house, int nHeight, CGoldCount& count)
{
    if (g_fnGoldForChecksTestOverride) {
        count = CGoldCount();
        g_fnGoldForChecksTestOverride(house, nHeight, count);
        return;
    }
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nHeight);
    if (g_pUnitsCheckView) {
        HouseGoldCounted(*g_pUnitsCheckView, house, nHeight, gp, false, count, true);
    } else {
        CUnitsView view(punitsdb.get());
        HouseGoldCounted(view, house, nHeight, gp, false, count, true);
    }
}

void HouseGoldCounted(const CUnitsView& units, const CHouse& house, int nHeight, const Consensus::GramParams& gp,
                      bool fEquity, CGoldCount& count, bool fNoPriceGate)
{
    count = CGoldCount();
    struct Holding { uint64_t nCapital = 0, nTill = 0; };
    std::map<uint256, Holding> mapHold;
    for (const auto& v : HouseVaults(units, house.nHouseID)) {
        const uint8_t nKind = std::get<0>(v.first);
        const uint32_t nPartner = std::get<1>(v.first);
        if (nKind == VAULT_CAPITAL) {
            count.nCapitalRawMg += v.second;
            // Capital counts active partners only (a leaving partner's pledge is tail liability, not cap headroom).
            if (nPartner < house.vPartner.size() && house.vPartner[nPartner].status == HOUSE_PARTNER_ACTIVE)
                mapHold[std::get<2>(v.first)].nCapital += v.second;
        } else {
            count.nTillRawMg += v.second;
            mapHold[std::get<2>(v.first)].nTill += v.second;
        }
    }

    // Per token: backing, then the bond cap shared pro rata.
    struct Counted { uint64_t nCapital = 0, nTill = 0; std::string strContract, strUpstream; };
    std::map<uint256, Counted> mapCounted;
    for (const std::pair<const uint256, Holding>& h : mapHold) {
        CIssuedToken token;
        if (!units.Get(IssuedTokenKey(h.first), token) || token.nKind != ISSUED_KIND_GOLD_MG)
            continue;
        if (!fEquity && !(fNoPriceGate ? token.fTrusted : token.fBackingOk))
            continue;   // stale or short backing, or no price: counts zero for issuing (D-2026-11-01-6 item 3)
        unsigned __int128 nCap = (unsigned __int128)h.second.nCapital, nTil = (unsigned __int128)h.second.nTill;
        // R3-8: counted at the lower of its backing and its market - a token whose deep pool trades below the gold price
        // counts at the pool's 144-block average over the payout price.
        if (!fEquity && nHeight > 0) {
            uint64_t nView = 0, nGold = 0;
            bool fDeep = false;
            if (TokenPoolView(units, h.first, nHeight - 1, gp, nView, fDeep) && fDeep &&
                    PayoutPrice(units, nHeight - 1, gp, nGold) && nGold > 0 && nView < nGold) {
                nCap = nCap * nView / nGold;
                nTil = nTil * nView / nGold;
            }
        }
        // 5b: a freeze on the house's vault gold counts zero once its grace has run (decisions log 4), pro rata over
        // the house's units of the token.
        {
            CVaultFrozen f;
            if (units.Get(VaultFrozenKey(house.nHouseID, h.first), f) && f.nFrozen > 0 &&
                    (int64_t)nHeight >= (int64_t)f.nGraceStart + (int64_t)gp.nFreezeGraceBlocks) {
                const uint64_t nAll = HouseTokenVaultTotal(units, house.nHouseID, h.first);
                const uint64_t nFree = nAll > f.nFrozen ? nAll - f.nFrozen : 0;
                if (nAll > 0) {
                    nCap = nCap * nFree / nAll;
                    nTil = nTil * nFree / nAll;
                }
            }
        }
        // The bond cap: k x the bond's grams, shared across every house holding the token in proportion to holdings.
        if (!fEquity) {
            uint64_t nTotal = 0;
            units.Get(VaultTotalKey(h.first), nTotal);
            const unsigned __int128 nBondCap = token.nUnbondRequestHeight == 0 ? (unsigned __int128)token.nBondMgAtLock * token.nK : 0;
            const unsigned __int128 nHeld = nCap + nTil;
            if (nTotal > 0 && nHeld > 0) {
                const unsigned __int128 nShare = nBondCap * nHeld / nTotal;
                if (nShare < nHeld) {
                    nCap = nCap * nShare / nHeld;
                    nTil = nTil * nShare / nHeld;
                }
            } else if (nHeld > 0 && nBondCap == 0) {
                nCap = nTil = 0;
            }
        }
        Counted c;
        c.nCapital = (uint64_t)nCap;
        c.nTill = (uint64_t)nTil;
        c.strContract = HexStr(token.vchBackingContract);
        c.strUpstream = token.strUpstream;
        mapCounted[h.first] = c;
    }

    // The half limit, per upstream company, then per backing contract, then per token: a group above half of the
    // house's counted gold counts only up to the rest (D-2026-10-31-8 item 3, R2-ops-8, R2-sys-2).
    const auto fnLimit = [&](const std::function<std::string(const uint256&, const Counted&)>& fnGroup) {
        if (fEquity)
            return;
        std::map<std::string, unsigned __int128> mapGroup;
        unsigned __int128 nAll = 0;
        for (const auto& c : mapCounted) {
            mapGroup[fnGroup(c.first, c.second)] += (unsigned __int128)c.second.nCapital + c.second.nTill;
            nAll += (unsigned __int128)c.second.nCapital + c.second.nTill;
        }
        for (auto& c : mapCounted) {
            const unsigned __int128 nGroup = mapGroup[fnGroup(c.first, c.second)];
            const unsigned __int128 nRest = nAll - nGroup;
            if (nGroup > nRest && nGroup > 0) {
                c.second.nCapital = (uint64_t)((unsigned __int128)c.second.nCapital * nRest / nGroup);
                c.second.nTill = (uint64_t)((unsigned __int128)c.second.nTill * nRest / nGroup);
            }
        }
    };
    fnLimit([](const uint256&, const Counted& c) { return c.strUpstream; });
    fnLimit([](const uint256&, const Counted& c) { return c.strContract; });
    fnLimit([](const uint256& id, const Counted&) { return id.GetHex(); });

    for (const auto& c : mapCounted) {
        count.nCapitalMg += c.second.nCapital;
        count.nTillMg += c.second.nTill;
    }

    // The exit (D-2026-11-01-5; dormant until two years of daily medians): at step s (each 25%), sECX may count for
    // up to s quarters of capital and of till - the partners' sECX escrow in capital, the attested sECX till in the
    // till, valued at the payout price. At 100% gold is optional.
    const uint8_t nStep = PriceFeedExitStep(units);
    uint64_t nSatsPerGram = 0;
    if (!fEquity && nStep > 0 && nHeight > 0 && PayoutPrice(units, nHeight - 1, gp, nSatsPerGram) && nSatsPerGram > 0) {
        const auto fnAdd = [&](uint64_t& nGold, CAmount amountSats) {
            if (amountSats <= 0)
                return;
            const unsigned __int128 nMg = (unsigned __int128)(uint64_t)amountSats * 1000 / nSatsPerGram;
            // sECX <= s x (gold + sECX)  <=>  sECX <= gold x s / (4 - s) quarters
            const unsigned __int128 nCap = nStep >= 4 ? nMg : (unsigned __int128)nGold * nStep / (4 - nStep);
            nGold = (uint64_t)std::min<unsigned __int128>((unsigned __int128)nGold + std::min(nMg, nCap), (unsigned __int128)MAX_MONEY);
        };
        fnAdd(count.nCapitalMg, house.ActiveEscrow());
        fnAdd(count.nTillMg, house.amountLastAttestReserves);
    }
}


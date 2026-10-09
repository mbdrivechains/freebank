// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <settle.h>

#include <consensus/validation.h>
#include <hash.h>
#include <house.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <tinyformat.h>
#include <version.h>

#include <algorithm>
#include <string.h>

uint256 SettleHashPrevouts(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        ss << in.prevout;
    return ss.GetHash();
}

uint256 SettleExchangeSigHash(const SettleExchange& x, const uint256& hashPrevouts,
                              const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankSettle/exchange");
    ss << x.nHouseA;
    ss << x.nHouseB;
    ss << x.nMode;
    ss << x.nUnitsANotes;
    ss << x.nUnitsBNotes;
    ss << x.nCountANotes;
    ss << x.nCountBNotes;
    ss << x.vchPresentKeyOfANotes;
    ss << x.vchPresentKeyOfBNotes;
    ss << x.amountResidual;
    ss << x.nPrevMintedUnitsA;
    ss << x.nPrevMintedUnitsB;
    ss << x.nPrevLastSettleHeightA;
    ss << x.nPrevLastSettleHeightB;
    ss << x.nExpiryHeight;
    ss << hashPrevouts;   // coins consumed on connect - the MINT-replay lesson
    ss << hashOutputs;    // pins the residual destination + the whole output set
    return ss.GetHash();
}

bool SettleResidualInBand(uint64_t nUnitsANotes, uint64_t nUnitsBNotes,
                          uint8_t nMode, CAmount amountResidual)
{
    // Hard-bound the envelope regardless of caller discipline.
    if (nUnitsANotes > SETTLE_MAX_UNITS || nUnitsBNotes > SETTLE_MAX_UNITS)
        return false;
    if (amountResidual < 0 || amountResidual > MAX_MONEY)
        return false;

    const uint64_t dU = nUnitsANotes >= nUnitsBNotes ? nUnitsANotes - nUnitsBNotes
                                                     : nUnitsBNotes - nUnitsANotes;
    if (nMode == 0)
        return dU == 0 && amountResidual == 0;
    if (nMode != 1 || dU == 0)
        return false;
    if ((CAmount)dU < SETTLE_MIN_RESIDUAL)
        return false;

    // |dU|*(10^4 - band) <= residual*10^4 <= |dU|*(10^4 + band), all u128:
    // dU <= 3*MAX_MONEY < 2^53 and (10^4 + band) < 2^14, so each product
    // < 2^67 - far inside the 128-bit envelope (named ceiling: SETTLE_MAX_UNITS).
    const unsigned __int128 lo = (unsigned __int128)dU * (10000 - SETTLE_PAR_BAND_BPS);
    const unsigned __int128 hi = (unsigned __int128)dU * (10000 + SETTLE_PAR_BAND_BPS);
    const unsigned __int128 res = (unsigned __int128)(uint64_t)amountResidual * 10000;
    return lo <= res && res <= hi;
}

static bool IsValidSettlePubKey(const std::vector<unsigned char>& vch)
{
    if (vch.size() != CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        return false;
    CPubKey pubkey(vch);
    return pubkey.IsFullyValid();
}

static bool IsSettleSigShape(const std::vector<unsigned char>& vchSig)
{
    return !vchSig.empty() && vchSig.size() <= 80;
}

static bool IsSettleP2PKHShape(const CScript& script)
{
    return script.size() == 25 && script[0] == OP_DUP && script[1] == OP_HASH160 &&
           script[2] == 0x14 && script[23] == OP_EQUALVERIFY && script[24] == OP_CHECKSIG;
}

static bool CheckSettleApproverShape(const std::vector<uint32_t>& vIndex,
                                     const std::vector<std::vector<unsigned char>>& vSig)
{
    // Non-empty, parallel, strictly ascending, bounded, well-formed sigs
    // (the pool CREATE approver idiom; ranges vs the ACTUAL partner set are
    // contextual - CheckSettleOperation).
    if (vIndex.empty() || vIndex.size() != vSig.size())
        return false;
    if (vIndex.size() > MAX_HOUSE_PARTNERS)
        return false;
    for (size_t i = 0; i < vIndex.size(); i++) {
        if (vIndex[i] >= MAX_HOUSE_PARTNERS)
            return false;
        if (i > 0 && vIndex[i] <= vIndex[i - 1])
            return false;
        if (!IsSettleSigShape(vSig[i]))
            return false;
    }
    return true;
}

uint256 SettleNetSigHash(const SettleNet& n, const uint256& hashPrevouts, const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankSettle/net");
    ss << n.vHouseID;
    ss << n.vReceive;
    ss << n.vPrevMintedUnits;
    ss << n.vPrevLastSettleHeight;
    ss << n.vPresentKey;
    ss << n.vBundle;
    ss << n.nExpiryHeight;
    ss << hashPrevouts;
    ss << hashOutputs;
    return ss.GetHash();
}

bool SettleNetPositions(const SettleNet& n, std::vector<int64_t>& vNet, std::vector<uint64_t>& vBurn)
{
    const size_t nHouses = n.vHouseID.size();
    std::vector<uint64_t> vPresented(nHouses, 0);
    vBurn.assign(nHouses, 0);
    vNet.assign(nHouses, 0);
    auto fnIndex = [&n](uint32_t nID, size_t& i) {
        const auto it = std::lower_bound(n.vHouseID.begin(), n.vHouseID.end(), nID);
        if (it == n.vHouseID.end() || *it != nID) return false;
        i = it - n.vHouseID.begin();
        return true;
    };
    for (const SettleNetBundle& b : n.vBundle) {
        size_t p, q;
        if (!fnIndex(b.nPresenter, p) || !fnIndex(b.nIssuer, q) || p == q)
            return false;
        if (b.nUnits > SETTLE_MAX_UNITS || vPresented[p] > SETTLE_MAX_UNITS - b.nUnits ||
                vBurn[q] > SETTLE_MAX_UNITS - b.nUnits)
            return false;
        vPresented[p] += b.nUnits;
        vBurn[q] += b.nUnits;
    }
    // Both totals are <= SETTLE_MAX_UNITS < 2^53, so the difference fits an int64.
    for (size_t i = 0; i < nHouses; i++)
        vNet[i] = (int64_t)vPresented[i] - (int64_t)vBurn[i];
    return true;
}

bool SettleSlotHouses(const CTransaction& tx, std::vector<uint32_t>& vHouse)
{
    vHouse.clear();
    if (tx.nVersion != TRANSACTION_SETTLE_VERSION)
        return false;
    const std::vector<unsigned char>& p = tx.vchSettlePayload;
    if (tx.nSettleOp == SETTLE_OP_EXCHANGE) {
        if (p.size() < 8)
            return false;
        uint32_t nA = 0, nB = 0;
        memcpy(&nA, p.data(), 4);
        memcpy(&nB, p.data() + 4, 4);
        if (nA == 0 || nB == 0)
            return false;
        vHouse = {nA, nB};
        return true;
    }
    if (tx.nSettleOp == SETTLE_OP_NET) {
        // vHouseID leads the payload: a compact size, then the ids.
        if (p.empty())
            return false;
        uint64_t nCount = 0;
        size_t nOff = 0;
        if (p[0] < 253) {
            nCount = p[0];
            nOff = 1;
        } else if (p[0] == 253 && p.size() >= 3) {
            nCount = (uint64_t)p[1] | ((uint64_t)p[2] << 8);
            nOff = 3;
        } else if (p[0] == 254 && p.size() >= 5) {
            nCount = (uint64_t)p[1] | ((uint64_t)p[2] << 8) | ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24);
            nOff = 5;
        } else {
            return false;
        }
        if (nCount == 0 || (p.size() - nOff) / 4 < nCount)
            return false;
        vHouse.resize(nCount);
        for (size_t i = 0; i < nCount; i++) {
            memcpy(&vHouse[i], p.data() + nOff + 4 * i, 4);
            if (vHouse[i] == 0) {
                vHouse.clear();
                return false;
            }
        }
        return true;
    }
    return false;
}

/** Context-free rules for a NET round (no DB, no ECDSA). Eligibility, priors, destinations and every signature run
 * in CheckSettleNetOperation. */
static bool CheckSettleNetShape(const CTransaction& tx, CValidationState& state)
{
    // No payload cap of its own: the transaction's size bounds it (NETTING_DESIGN.md: no cap on houses).
    SettleNet n;
    if (!DecodeSettlePayload(tx.vchSettlePayload, n))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-payload");

    const size_t nHouses = n.vHouseID.size();
    if (nHouses < 2)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-houses");
    for (size_t i = 0; i < nHouses; i++) {
        if (n.vHouseID[i] == 0 || (i > 0 && n.vHouseID[i] <= n.vHouseID[i - 1]))
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-house-order");
    }
    if (n.vReceive.size() != nHouses || n.vPrevMintedUnits.size() != nHouses ||
            n.vPrevLastSettleHeight.size() != nHouses || n.vPresentKey.size() != nHouses ||
            n.vPresentSig.size() != nHouses || n.vApproverIndex.size() != nHouses ||
            n.vApproverSig.size() != nHouses)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-shape");

    for (size_t i = 0; i < nHouses; i++) {
        if (n.vReceive[i] < 0 || n.vReceive[i] > MAX_MONEY)
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-receive");
        if (n.vPresentKey[i].empty()) {
            if (!n.vPresentSig[i].empty())
                return state.DoS(100, false, REJECT_INVALID, "bad-settle-presenter-sig");
        } else {
            if (!IsValidSettlePubKey(n.vPresentKey[i]))
                return state.DoS(100, false, REJECT_INVALID, "bad-settle-presenter-key");
            if (!IsSettleSigShape(n.vPresentSig[i]))
                return state.DoS(100, false, REJECT_INVALID, "bad-settle-presenter-sig");
        }
        if (!CheckSettleApproverShape(n.vApproverIndex[i], n.vApproverSig[i]))
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-approvers");
    }

    // Bundles: strictly ascending (presenter, issuer) - unique pairs - inside the round, never self-presentment,
    // bounded, and only from a house that names a presentment key.
    if (n.vBundle.empty())
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-bundles");
    std::vector<bool> vPresents(nHouses, false), vIssues(nHouses, false);
    uint64_t nCoins = 0;
    for (size_t k = 0; k < n.vBundle.size(); k++) {
        const SettleNetBundle& b = n.vBundle[k];
        if (k > 0) {
            const SettleNetBundle& a = n.vBundle[k - 1];
            if (std::make_pair(b.nPresenter, b.nIssuer) <= std::make_pair(a.nPresenter, a.nIssuer))
                return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-bundle-order");
        }
        const auto itP = std::lower_bound(n.vHouseID.begin(), n.vHouseID.end(), b.nPresenter);
        const auto itI = std::lower_bound(n.vHouseID.begin(), n.vHouseID.end(), b.nIssuer);
        if (itP == n.vHouseID.end() || *itP != b.nPresenter || itI == n.vHouseID.end() || *itI != b.nIssuer ||
                b.nPresenter == b.nIssuer)
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-bundle-order");
        const size_t p = itP - n.vHouseID.begin();
        if (n.vPresentKey[p].empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-presenter-key");
        if (b.nUnits < 1 || b.nUnits > SETTLE_MAX_UNITS)
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-units-range");
        if (b.nCount < 1 || b.nCount > SETTLE_MAX_BUNDLE_INPUTS)
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-bundle-count");
        vPresents[p] = true;
        vIssues[itI - n.vHouseID.begin()] = true;
        nCoins += b.nCount;
    }
    // Every house takes part, and a presentment key belongs to a house that presents.
    for (size_t i = 0; i < nHouses; i++) {
        if (!vPresents[i] && !vIssues[i])
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-idle-house");
        if (!vPresents[i] && !n.vPresentKey[i].empty())
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-presenter-key");
    }
    if (tx.vin.size() < nCoins)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-vin-size");

    std::vector<int64_t> vNet;
    std::vector<uint64_t> vBurn;
    if (!SettleNetPositions(n, vNet, vBurn))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-units-range");

    // Payments: each net creditor in ascending house order at the front of the outputs, P2PKH, its exact amount,
    // inside the band (which also enforces the SETTLE_MIN_RESIDUAL floor); everyone else receives nothing. The exact
    // destination (the creditor's redemption key) is contextual.
    size_t nOut = 0;
    for (size_t i = 0; i < nHouses; i++) {
        if (vNet[i] <= 0) {
            if (n.vReceive[i] != 0)
                return state.DoS(100, false, REJECT_INVALID, "bad-settle-net-receive");
            continue;
        }
        if (!SettleResidualInBand((uint64_t)vNet[i], 0, 1, n.vReceive[i]))
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-band");
        if (nOut >= tx.vout.size() || !IsSettleP2PKHShape(tx.vout[nOut].scriptPubKey) ||
                tx.vout[nOut].nValue != n.vReceive[i])
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-residual-out");
        nOut++;
    }
    return true;
}

bool CheckSettleTransactionShape(const CTransaction& tx, CValidationState& state)
{
    // Context-free only (no DB, no ECDSA): payload decode + structural rules.
    // Priors, eligibility, cadence, approver-set ranges and all signatures run
    // contextually in CheckSettleOperation (T-s3).
    if (tx.nSettleOp == SETTLE_OP_NET)
        return CheckSettleNetShape(tx, state);
    if (tx.nSettleOp != SETTLE_OP_EXCHANGE)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-op");
    if (tx.vchSettlePayload.size() > MAX_SETTLE_PAYLOAD)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-payload-size");

    SettleExchange x;
    if (!DecodeSettlePayload(tx.vchSettlePayload, x))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-payload");

    // Canonical house ordering: bans self-exchange structurally and gives the
    // ATMP guards one canonical (A, B) key per pair.
    if (x.nHouseA == 0 || x.nHouseA >= x.nHouseB)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-house-order");

    // Units: both sides present something real, inside the shared envelope.
    if (x.nUnitsANotes < 1 || x.nUnitsANotes > SETTLE_MAX_UNITS ||
            x.nUnitsBNotes < 1 || x.nUnitsBNotes > SETTLE_MAX_UNITS)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-units-range");

    // Bundles: bounded, and the fixed positions must exist.
    if (x.nCountANotes < 1 || x.nCountANotes > SETTLE_MAX_BUNDLE_INPUTS ||
            x.nCountBNotes < 1 || x.nCountBNotes > SETTLE_MAX_BUNDLE_INPUTS)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-bundle-count");
    if (tx.vin.size() < (size_t)x.nCountANotes + (size_t)x.nCountBNotes)
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-vin-size");

    // Presentment keys + holder sigs (well-formedness; verification is contextual).
    if (!IsValidSettlePubKey(x.vchPresentKeyOfANotes) || !IsValidSettlePubKey(x.vchPresentKeyOfBNotes))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-presenter-key");
    if (!IsSettleSigShape(x.vchPresentSigOfANotes) || !IsSettleSigShape(x.vchPresentSigOfBNotes))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-presenter-sig");

    // Approver arrays, both houses.
    if (!CheckSettleApproverShape(x.vApproverIndexA, x.vApproverSigA) ||
            !CheckSettleApproverShape(x.vApproverIndexB, x.vApproverSigB))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-approvers");

    // Mode discipline + the payload-pure band arithmetic (par is 1:1 - no DB).
    const uint64_t dU = x.nUnitsANotes >= x.nUnitsBNotes ? x.nUnitsANotes - x.nUnitsBNotes
                                                         : x.nUnitsBNotes - x.nUnitsANotes;
    if (x.nMode > 1 || (x.nMode == 1) != (dU != 0) ||
            (x.nMode == 0 && x.amountResidual != 0))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-mode");
    if (!SettleResidualInBand(x.nUnitsANotes, x.nUnitsBNotes, x.nMode, x.amountResidual))
        return state.DoS(100, false, REJECT_INVALID, "bad-settle-band");

    // Mode 1: the residual output is pinned at vout[0], P2PKH, exact value.
    // (The EXACT destination P2PKH(creditor.vchRedemptionDestPK) is contextual.)
    if (x.nMode == 1) {
        if (tx.vout.empty() || !IsSettleP2PKHShape(tx.vout[0].scriptPubKey) ||
                tx.vout[0].nValue != x.amountResidual)
            return state.DoS(100, false, REJECT_INVALID, "bad-settle-residual-out");
    }

    return true;
}

template <typename T>
bool DecodeSettlePayload(const std::vector<unsigned char>& vch, T& payload)
{
    try {
        CDataStream ss(vch, SER_NETWORK, PROTOCOL_VERSION);
        ss >> payload;
        if (!ss.empty())
            return false;   // trailing bytes: decode must be exact
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

template bool DecodeSettlePayload<SettleExchange>(const std::vector<unsigned char>&, SettleExchange&);
template bool DecodeSettlePayload<SettleNet>(const std::vector<unsigned char>&, SettleNet&);

bool SettleNetRoundBundles(const SettleNetRoundV1& r, SettleNet& n, std::vector<int64_t>& vNet, std::string& strFail)
{
    n = SettleNet();
    vNet.clear();
    n.vHouseID = r.vHouseID;
    for (size_t i = 0; i < r.vHouseID.size(); i++) {
        if (r.vHouseID[i] == 0 || (i > 0 && r.vHouseID[i] <= r.vHouseID[i - 1])) {
            strFail = "The round's houses are not in ascending order!";
            return false;
        }
    }
    n.vPresentKey.assign(r.vHouseID.size(), std::vector<unsigned char>());
    for (size_t k = 0; k < r.vPart.size(); k++) {
        const SettleNetRoundPart& part = r.vPart[k];
        if (k > 0 && part.nHouseID <= r.vPart[k - 1].nHouseID) {
            strFail = "The round's parts are not in ascending order!";
            return false;
        }
        const auto it = std::lower_bound(r.vHouseID.begin(), r.vHouseID.end(), part.nHouseID);
        if (it == r.vHouseID.end() || *it != part.nHouseID) {
            strFail = strprintf("House %u joined but is not in the round!", part.nHouseID);
            return false;
        }
        if (part.vBundle.empty() != part.vchPresentKey.empty()) {
            strFail = strprintf("House %u's presentment key and bundles disagree!", part.nHouseID);
            return false;
        }
        n.vPresentKey[it - r.vHouseID.begin()] = part.vchPresentKey;
        for (size_t b = 0; b < part.vBundle.size(); b++) {
            const SettleNetRoundBundle& rb = part.vBundle[b];
            if ((b > 0 && rb.nIssuer <= part.vBundle[b - 1].nIssuer) || rb.nIssuer == part.nHouseID ||
                    rb.nUnits == 0 || rb.vCoin.empty() || rb.vCoin.size() > SETTLE_MAX_BUNDLE_INPUTS) {
                strFail = strprintf("House %u has a malformed bundle!", part.nHouseID);
                return false;
            }
            SettleNetBundle nb;
            nb.nPresenter = part.nHouseID;
            nb.nIssuer = rb.nIssuer;
            nb.nUnits = rb.nUnits;
            nb.nCount = (uint16_t)rb.vCoin.size();
            n.vBundle.push_back(nb);
        }
    }
    std::vector<uint64_t> vBurn;
    if (!SettleNetPositions(n, vNet, vBurn)) {
        strFail = "A bundle names a house outside the round, or its units are out of range!";
        return false;
    }
    return true;
}

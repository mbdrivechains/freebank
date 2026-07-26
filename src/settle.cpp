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
#include <version.h>

// Per-house settlement cadence (blocks). 144 mainnet-notional; the signet demo
// runs 12. Runtime-set at init (HOUSE_ATTEST_CADENCE precedent); wiring lands
// with the contextual checks. PROVISIONAL (P-2).
uint32_t SETTLE_CADENCE_BLOCKS = 144;

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

bool CheckSettleTransactionShape(const CTransaction& tx, CValidationState& state)
{
    // Context-free only (no DB, no ECDSA): payload decode + structural rules.
    // Priors, eligibility, cadence, approver-set ranges and all signatures run
    // contextually in CheckSettleOperation.
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

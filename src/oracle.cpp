// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <oracle.h>

#include <consensus/validation.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <version.h>

#include <algorithm>

uint256 OracleHashPrevouts(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        ss << in.prevout;
    return ss.GetHash();
}

uint256 OracleSubmitSigHash(const OracleSubmit& x, const uint256& hashPrevouts,
                            const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankOracle/submit");
    ss << x.nSubmitterID;
    ss << x.nTargetHeight;
    ss << x.vObs;
    ss << x.nPrevOwnLastSubmitHeight;
    ss << x.hashPrevBlockBind;   // branch bind [C-5]: a reorg invalidates the sig
    ss << hashPrevouts;          // R-i6: bind prevouts wherever a payload sig authorizes
    ss << hashOutputs;
    return ss.GetHash();
}

uint256 OracleBondSigHash(const OracleBond& x, const uint256& hashPrevouts,
                          const uint256& hashOutputs)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankOracle/bond");
    ss << x.nSubmitterID;
    ss << x.nTargetHeight;
    ss << x.vchSubmitterPubKey;
    ss << x.nPrevBondHeight;
    ss << x.nPrevLastSubmitHeight;
    ss << x.nPrevUnbondRequestHeight;
    ss << x.outPrevBond;
    ss << hashPrevouts;
    ss << hashOutputs;
    return ss.GetHash();
}

uint64_t OracleLowerMedian(std::vector<uint64_t> vPrices)
{
    // Element (n-1)/2 of the sorted value multiset [A-2]: deterministic,
    // duplicate-proof, no averaging (u64 averaging wraps), conservative
    // direction consistent with the brake's asymmetry.
    std::sort(vPrices.begin(), vPrices.end());
    return vPrices[(vPrices.size() - 1) / 2];
}

uint64_t OracleBrakedNext(uint64_t nPrevBraked, uint64_t nRaw,
                          uint32_t nElapsedBlocks, uint32_t nBrakePpmPerBlock,
                          uint32_t nElapsedCap)
{
    if (nPrevBraked == 0)
        return nRaw;              // first fix ever: braked := raw [C-4]
    if (nRaw >= nPrevBraked)
        return nRaw;              // rises track spot freely - never opens the arb
    // Falls: bounded per elapsed block, elapsed capped [B-1]. u128 under the
    // 2^53 envelope: braked * ppm * cap < 2^53 * 2^20 * 2^8 = 2^81.
    const uint64_t nElapsed = std::min<uint64_t>(std::max<uint32_t>(nElapsedBlocks, 1), nElapsedCap);
    unsigned __int128 step = (unsigned __int128)nPrevBraked * nBrakePpmPerBlock * nElapsed / 1000000;
    if (step < 1)
        step = 1;                 // min-step: integer floor must never freeze the view [B-2]
    uint64_t nFloor = (nPrevBraked > (uint64_t)step) ? nPrevBraked - (uint64_t)step : ORACLE_PRICE_MIN;
    return std::max(nRaw, nFloor);
}

template <typename T>
bool DecodeOraclePayload(const std::vector<unsigned char>& vch, T& payload)
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

template bool DecodeOraclePayload<OracleSubmit>(const std::vector<unsigned char>&, OracleSubmit&);
template bool DecodeOraclePayload<OracleBond>(const std::vector<unsigned char>&, OracleBond&);

CScript OracleBondScript(const std::vector<unsigned char>& vchPubKey)
{
    return CScript() << vchPubKey << OP_DROP << OP_TRUE;
}

bool IsOracleBondScript(const CScript& script)
{
    // <33-byte push> OP_DROP OP_TRUE: 1 + 33 + 1 + 1 = 36 bytes.
    return script.size() == 36 && script[0] == 33 &&
           script[34] == OP_DROP && script[35] == OP_TRUE;
}

static bool IsCompressedPubKey(const std::vector<unsigned char>& vch)
{
    return vch.size() == 33 && (vch[0] == 0x02 || vch[0] == 0x03);
}

static bool IsWellFormedSig(const std::vector<unsigned char>& vch)
{
    return !vch.empty() && vch.size() <= 72;
}

bool CheckOracleTransactionShape(const CTransaction& tx, CValidationState& state)
{
    if (tx.nOracleOp != ORACLE_OP_BOND && tx.nOracleOp != ORACLE_OP_SUBMIT)
        return state.DoS(100, false, REJECT_INVALID, "bad-oracle-op");
    if (tx.vchOraclePayload.empty() || tx.vchOraclePayload.size() > MAX_ORACLE_PAYLOAD)
        return state.DoS(100, false, REJECT_INVALID, "bad-oracle-payload-size");

    if (tx.nOracleOp == ORACLE_OP_SUBMIT) {
        OracleSubmit x;
        if (!DecodeOraclePayload(tx.vchOraclePayload, x))
            return state.DoS(100, false, REJECT_INVALID, "bad-oracle-payload");
        if (x.nSubmitterID == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-oracle-submitter-id");
        if (x.nTargetHeight == 0)
            return state.DoS(100, false, REJECT_INVALID, "bad-oracle-target-height");
        // Gram-notes release: the observations. At least one, at most MAX_ORACLE_OBS, sorted by (stream, subject)
        // with no repeat; a price stream has no subject and its value is in the price envelope; a token stream names
        // its token.
        if (x.vObs.empty() || x.vObs.size() > MAX_ORACLE_OBS)
            return state.DoS(100, false, REJECT_INVALID, "bad-oracle-obs-count");
        for (size_t k = 0; k < x.vObs.size(); k++) {
            const COracleObs& o = x.vObs[k];
            if (k > 0) {
                const COracleObs& p = x.vObs[k - 1];
                if (o.nStream < p.nStream || (o.nStream == p.nStream && !(p.subject < o.subject)))
                    return state.DoS(100, false, REJECT_INVALID, "bad-oracle-obs-order");
            }
            switch (o.nStream) {
            case ORACLE_STREAM_GOLD_ECX:
            case ORACLE_STREAM_GOLD_USD:
                if (!o.subject.IsNull() || o.nValue < ORACLE_PRICE_MIN || o.nValue > ORACLE_PRICE_MAX || o.nAux || o.nAux2)
                    return state.DoS(100, false, REJECT_INVALID, "bad-oracle-price-range");
                break;
            case ORACLE_STREAM_BACKING:
                if (o.subject.IsNull() || o.nValue > (uint64_t)MAX_MONEY || o.nAux == 0)
                    return state.DoS(100, false, REJECT_INVALID, "bad-oracle-backing-obs");
                break;
            case ORACLE_STREAM_CLAIM:
                if (o.subject.IsNull() || o.nValue != 1 || o.nAux == 0 || o.nAux2)
                    return state.DoS(100, false, REJECT_INVALID, "bad-oracle-claim-obs");
                break;
            default:
                return state.DoS(100, false, REJECT_INVALID, "bad-oracle-obs-stream");
            }
        }
        if (!IsWellFormedSig(x.vchSig))
            return state.DoS(100, false, REJECT_INVALID, "bad-oracle-sig");
        return true;
    }

    OracleBond x;
    if (!DecodeOraclePayload(tx.vchOraclePayload, x))
        return state.DoS(100, false, REJECT_INVALID, "bad-oracle-payload");
    if (x.nTargetHeight == 0)
        return state.DoS(100, false, REJECT_INVALID, "bad-oracle-target-height");
    if (!IsCompressedPubKey(x.vchSubmitterPubKey))
        return state.DoS(100, false, REJECT_INVALID, "bad-oracle-pubkey");
    // Fresh registration (id 0) binds zero priors; a returning id binds the
    // record it overwrites [C-3].
    if (x.nSubmitterID == 0 &&
        (x.nPrevBondHeight != 0 || x.nPrevLastSubmitHeight != 0 ||
         x.nPrevUnbondRequestHeight != 0 || !x.outPrevBond.IsNull()))
        return state.DoS(100, false, REJECT_INVALID, "bad-oracle-fresh-priors");
    if (!IsWellFormedSig(x.vchSig))
        return state.DoS(100, false, REJECT_INVALID, "bad-oracle-sig");
    return true;
}

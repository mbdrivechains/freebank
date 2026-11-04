// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <issued.h>

#include <asset.h>
#include <bill.h>
#include <coins.h>
#include <consensus/validation.h>
#include <hash.h>
#include <deposit.h>
#include <token.h>
#include <house.h>
#include <note.h>
#include <oracle.h>   // IsOracleBondScript
#include <pool.h>
#include <pubkey.h>
#include <script/script.h>
#include <streams.h>
#include <version.h>

#include <map>
#include <tuple>
#include <set>

template <typename T>
bool DecodeIssuedPayload(const std::vector<unsigned char>& vch, T& payload)
{
    if (vch.size() > MAX_ISSUED_PAYLOAD)
        return false;
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

template bool DecodeIssuedPayload<IssuedCreate>(const std::vector<unsigned char>&, IssuedCreate&);
template bool DecodeIssuedPayload<IssuedMint>(const std::vector<unsigned char>&, IssuedMint&);
template bool DecodeIssuedPayload<IssuedBurn>(const std::vector<unsigned char>&, IssuedBurn&);
template bool DecodeIssuedPayload<IssuedFreeze>(const std::vector<unsigned char>&, IssuedFreeze&);
template bool DecodeIssuedPayload<IssuedBond>(const std::vector<unsigned char>&, IssuedBond&);
template bool DecodeIssuedPayload<IssuedUnbond>(const std::vector<unsigned char>&, IssuedUnbond&);
template bool DecodeIssuedPayload<IssuedPoolCreate>(const std::vector<unsigned char>&, IssuedPoolCreate&);
template bool DecodeIssuedPayload<IssuedPoolAdd>(const std::vector<unsigned char>&, IssuedPoolAdd&);
template bool DecodeIssuedPayload<IssuedPoolRemove>(const std::vector<unsigned char>&, IssuedPoolRemove&);
template bool DecodeIssuedPayload<IssuedPoolSwap>(const std::vector<unsigned char>&, IssuedPoolSwap&);

static const unsigned char ISSUED_POOL_TAG[4] = {'F', 'B', 'T', 'P'};

CScript TokenPoolScript(const uint256& tokenID)
{
    std::vector<unsigned char> v(ISSUED_POOL_TAG, ISSUED_POOL_TAG + 4);
    v.insert(v.end(), tokenID.begin(), tokenID.end());
    return CScript() << v << OP_DROP << OP_TRUE;
}

CScript CreationBurnScript()
{
    return CScript() << OP_RETURN << std::vector<unsigned char>{'F', 'B', 'C', 'F'};
}

CAmount CreationBurnSats(uint64_t nSatsPerGram, uint64_t nCreateFeeMg)
{
    const unsigned __int128 n = ((unsigned __int128)nCreateFeeMg * nSatsPerGram + 999) / 1000;
    return n > (unsigned __int128)MAX_MONEY ? MAX_MONEY : (CAmount)n;
}

bool IsTokenPoolScript(const CScript& script, uint256* pTokenID)
{
    if (script.size() != 39 || script[0] != 0x24 || script[37] != OP_DROP || script[38] != OP_TRUE)
        return false;
    if (!std::equal(ISSUED_POOL_TAG, ISSUED_POOL_TAG + 4, script.begin() + 1))
        return false;
    if (pTokenID)
        std::copy(script.begin() + 5, script.begin() + 37, pTokenID->begin());
    return true;
}

uint256 LpTokenID(const uint256& tokenID)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBank token pool LP") << tokenID;
    return ss.GetHash();
}

uint256 IssuedPoolOpToken(const CTransaction& tx)
{
    if (tx.nVersion != TRANSACTION_TOKEN_VERSION)
        return uint256();
    switch (tx.nIssuedOp) {
    case ISSUED_OP_POOL_CREATE: { IssuedPoolCreate x; return DecodeIssuedPayload(tx.vchIssuedPayload, x) ? x.tokenID : uint256(); }
    case ISSUED_OP_POOL_ADD: { IssuedPoolAdd x; return DecodeIssuedPayload(tx.vchIssuedPayload, x) ? x.tokenID : uint256(); }
    case ISSUED_OP_POOL_REMOVE: { IssuedPoolRemove x; return DecodeIssuedPayload(tx.vchIssuedPayload, x) ? x.tokenID : uint256(); }
    case ISSUED_OP_POOL_SWAP: { IssuedPoolSwap x; return DecodeIssuedPayload(tx.vchIssuedPayload, x) ? x.tokenID : uint256(); }
    }
    return uint256();
}

static const unsigned char ISSUED_BOND_TAG[4] = {'F', 'B', 'I', 'B'};

CScript IssuedBondScript(const uint256& tokenID)
{
    std::vector<unsigned char> v(ISSUED_BOND_TAG, ISSUED_BOND_TAG + 4);
    v.insert(v.end(), tokenID.begin(), tokenID.end());
    return CScript() << v << OP_DROP << OP_TRUE;
}

bool IsIssuedBondScript(const CScript& script, uint256* pTokenID)
{
    // 0x24 <36 bytes> OP_DROP OP_TRUE
    if (script.size() != 39 || script[0] != 0x24 || script[37] != OP_DROP || script[38] != OP_TRUE)
        return false;
    if (!std::equal(ISSUED_BOND_TAG, ISSUED_BOND_TAG + 4, script.begin() + 1))
        return false;
    if (pTokenID)
        std::copy(script.begin() + 5, script.begin() + 37, pTokenID->begin());
    return true;
}

namespace {

bool IsCompressedKey(const std::vector<unsigned char>& vch)
{
    return vch.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE && CPubKey(vch).IsFullyValid();
}

/** Upstream id: 1-32 characters, a-z, 0-9 and '-'. */
bool IsValidUpstream(const std::string& str)
{
    if (str.empty() || str.size() > ISSUED_UPSTREAM_MAX)
        return false;
    for (char c : str)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return false;
    return true;
}

/** The payload with its signature emptied, re-encoded: what IssuedSigHash binds. */
std::vector<unsigned char> IssuedPayloadSigForm(const CTransaction& tx)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    switch (tx.nIssuedOp) {
    case ISSUED_OP_CREATE: {
        IssuedCreate x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) return tx.vchIssuedPayload;
        x.vchIssuerSig.clear();
        ss << x;
        break;
    }
    case ISSUED_OP_MINT: {
        IssuedMint x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) return tx.vchIssuedPayload;
        x.vchIssuerSig.clear();
        ss << x;
        break;
    }
    case ISSUED_OP_FREEZE:
    case ISSUED_OP_UNFREEZE: {
        IssuedFreeze x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) return tx.vchIssuedPayload;
        x.vchFreezeSig.clear();
        ss << x;
        break;
    }
    case ISSUED_OP_BOND: {
        IssuedBond x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) return tx.vchIssuedPayload;
        x.vchIssuerSig.clear();
        ss << x;
        break;
    }
    case ISSUED_OP_UNBOND: {
        IssuedUnbond x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) return tx.vchIssuedPayload;
        x.vchIssuerSig.clear();
        ss << x;
        break;
    }
    default:
        return tx.vchIssuedPayload;
    }
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

} // namespace

bool IssuedSumAnnex(const CTransaction& tx, std::map<uint256, uint64_t>& mapUnits, std::map<uint256, uint64_t>& mapFrozen)
{
    for (const CIssuedOut& o : tx.vIssuedOut) {
        uint64_t& nUnits = mapUnits[o.tokenID];
        uint64_t& nFrozen = mapFrozen[o.tokenID];
        if (o.nUnits > (uint64_t)MAX_MONEY || nUnits > (uint64_t)MAX_MONEY - o.nUnits)
            return false;
        nUnits += o.nUnits;
        nFrozen += o.nFrozen;   // <= nUnits per entry (shape), so no overflow past the units sum
    }
    return true;
}

uint256 IssuedSigHash(const CTransaction& tx)
{
    CHashWriter hPrevouts(SER_GETHASH, 0);
    for (const CTxIn& in : tx.vin)
        hPrevouts << in.prevout;
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBank issued token op v1");
    ss << tx.nIssuedOp;
    ss << IssuedPayloadSigForm(tx);
    ss << hPrevouts.GetHash();
    ss << BillHashOutputs(tx);
    ss << tx.vIssuedOut;
    return ss.GetHash();
}

const CIssuedOut* FindIssuedOut(const CTransaction& tx, uint32_t n)
{
    for (const CIssuedOut& o : tx.vIssuedOut) {
        if (o.nOut == n)
            return &o;
        if (o.nOut > n)
            break;
    }
    return nullptr;
}

void ApplyIssuedCoinTags(const CTransaction& tx, uint32_t n, Coin& coin)
{
    if (!HasIssuedAnnex(tx.nVersion))
        return;
    const CIssuedOut* p = FindIssuedOut(tx, n);
    if (p)
        coin.SetIssued(p->tokenID, p->nUnits, p->nFrozen);
}

/** Which transactions may carry issued units. The v18 ops, for now; each credit op that holds or pays tokens is added
 *  here when its own rules learn them (docs-local/GOLD_USD_SCOPE.md steps 4-6). */
static bool IssuedAnnexAllowed(const CTransaction& tx)
{
    if (tx.nVersion != TRANSACTION_TOKEN_VERSION)
        return false;
    return tx.nIssuedOp == ISSUED_OP_MINT || tx.nIssuedOp == ISSUED_OP_BURN || tx.nIssuedOp == ISSUED_OP_TRANSFER ||
           IsIssuedPoolOp(tx.nIssuedOp);
}

/** A pool op's positional outputs: vout[0] the token custody (an annex entry of the token, nothing frozen), vout[1] the
 *  sats custody (no annex entry), both at the token's pool script; no other output at any pool script. */
static bool CheckPoolCustodyShape(const CTransaction& tx, const uint256& token, std::string& strReason)
{
    if (tx.vout.size() < 2 || tx.vout[0].scriptPubKey != TokenPoolScript(token) ||
            tx.vout[1].scriptPubKey != TokenPoolScript(token) || tx.vout[1].nValue <= 0) {
        strReason = "bad-issued-pool-custody"; return false;
    }
    const CIssuedOut* p0 = FindIssuedOut(tx, 0);
    if (!p0 || p0->tokenID != token || p0->nFrozen != 0 || FindIssuedOut(tx, 1)) {
        strReason = "bad-issued-pool-custody"; return false;
    }
    for (size_t o = 2; o < tx.vout.size(); o++)
        if (IsTokenPoolScript(tx.vout[o].scriptPubKey)) { strReason = "bad-issued-pool-stray"; return false; }
    return true;
}

/** An LP-share output at vout[2] carrying exactly nLp of the pool's LP token. */
static bool CheckPoolLpOut(const CTransaction& tx, const uint256& token, uint64_t nLp, std::string& strReason)
{
    const CIssuedOut* p2 = FindIssuedOut(tx, 2);
    if (tx.vout.size() < 3 || !p2 || p2->tokenID != LpTokenID(token) || p2->nUnits != nLp || p2->nFrozen != 0) {
        strReason = "bad-issued-pool-lp-out"; return false;
    }
    return true;
}

/** Which transactions may move gold into or out of house vaults (step 5): a partner's TOPUP (in) and RECLAIM (out),
 *  the house's TILL (both). The house section checks each move against the op (CheckHouseVaultMoves). */
static bool VaultMovesAllowed(const CTransaction& tx)
{
    return (tx.nVersion == TRANSACTION_HOUSE_VERSION &&
            (tx.nHouseOp == HOUSE_OP_TOPUP || tx.nHouseOp == HOUSE_OP_RECLAIM || tx.nHouseOp == HOUSE_OP_TILL)) ||
           // step 6: a redemption paid in gold from the till (the REDEEM check holds it to the house's till, out)
           (tx.nVersion == TRANSACTION_NOTE_VERSION && tx.nNoteOp == NOTE_OP_REDEEM) ||
           // 5b: a failed house's gold paid out in kind - note claims, and CLOSE sending the rest to the fund
           (tx.nVersion == TRANSACTION_NOTE_VERSION && tx.nNoteOp == NOTE_OP_CLAIM) ||
           (tx.nVersion == TRANSACTION_DEPOSIT_VERSION && tx.nDepositOp == DEPOSIT_OP_CLAIM) ||
           (tx.nVersion == TRANSACTION_NOTE_VERSION && tx.nNoteOp == NOTE_OP_TOKEN_COLLECT) ||
           (tx.nVersion == TRANSACTION_HOUSE_VERSION && tx.nHouseOp == HOUSE_OP_CLOSE);
}

bool CheckIssuedShape(const CTransaction& tx, std::string& strReason)
{
    if (!HasIssuedAnnex(tx.nVersion))
        return true;
    // Review round 1 (G5): a coinbase never carries an annex or vault moves - it skips the input-side checks, so it
    // would create units from nothing.
    if (tx.IsCoinBase()) { strReason = "bad-issued-coinbase"; return false; }

    if (!tx.vVaultMove.empty()) {
        if (!VaultMovesAllowed(tx)) { strReason = "bad-vault-move-op"; return false; }
        if (tx.vVaultMove.size() > MAX_ISSUED_OUTS) { strReason = "bad-vault-move-size"; return false; }
        std::set<uint256> setToken;
        for (size_t k = 0; k < tx.vVaultMove.size(); k++) {
            const CVaultMove& m = tx.vVaultMove[k];
            if (m.nHouseID == 0 || m.nKind > VAULT_TILL || (m.nKind == VAULT_TILL && m.nPartner != 0) ||
                    m.tokenID.IsNull() || m.nDelta == 0 || m.nDelta > MAX_MONEY || m.nDelta < -MAX_MONEY) {
                strReason = "bad-vault-move"; return false;
            }
            if (k > 0) {
                const CVaultMove& p = tx.vVaultMove[k - 1];
                const auto a = std::make_tuple(p.nHouseID, p.nKind, p.nPartner, p.tokenID);
                const auto b = std::make_tuple(m.nHouseID, m.nKind, m.nPartner, m.tokenID);
                if (!(a < b)) { strReason = "bad-vault-move-order"; return false; }
            }
            setToken.insert(m.tokenID);
        }
        if (setToken.size() > MAX_ISSUED_TOKENS_PER_TX) { strReason = "bad-vault-move-tokens"; return false; }
    }

    if (!tx.vIssuedOut.empty()) {
        if (!IssuedAnnexAllowed(tx) && !VaultMovesAllowed(tx)) { strReason = "bad-issued-annex-op"; return false; }
        if (tx.vIssuedOut.size() > MAX_ISSUED_OUTS) { strReason = "bad-issued-annex-size"; return false; }
        std::set<uint256> setToken;
        for (size_t k = 0; k < tx.vIssuedOut.size(); k++) {
            const CIssuedOut& o = tx.vIssuedOut[k];
            if (k > 0 && o.nOut <= tx.vIssuedOut[k - 1].nOut) { strReason = "bad-issued-annex-order"; return false; }
            if (o.nOut >= tx.vout.size()) { strReason = "bad-issued-annex-out"; return false; }
            if (o.tokenID.IsNull() || o.nUnits == 0 || o.nUnits > (uint64_t)MAX_MONEY || o.nFrozen > o.nUnits) {
                strReason = "bad-issued-annex-units"; return false;
            }
            // Units leave only by a BURN, never into an unspendable output.
            const CScript& scriptOut = tx.vout[o.nOut].scriptPubKey;
            if (scriptOut.IsUnspendable()) { strReason = "bad-issued-annex-unspendable"; return false; }
            // Review round 1 (G4): never onto another family's tagged output (a dual-tagged coin is refused by every
            // later op of that family: 1 mg on a claim's escrow change would lock the pot from all later claims). A
            // pool's own custody output is the pool op's to place (checked there).
            if (IsGoldUnpayableScript(scriptOut) && !(IsIssuedPoolOp(tx.nIssuedOp) && tx.nVersion == TRANSACTION_TOKEN_VERSION &&
                                                     IsTokenPoolScript(scriptOut))) {
                strReason = "bad-issued-annex-tagged-output"; return false;
            }
            setToken.insert(o.tokenID);
        }
        if (setToken.size() > MAX_ISSUED_TOKENS_PER_TX) { strReason = "bad-issued-annex-tokens"; return false; }
    }

    if (tx.nVersion != TRANSACTION_TOKEN_VERSION)
        return true;

    if (tx.vchIssuedPayload.size() > MAX_ISSUED_PAYLOAD) { strReason = "bad-issued-payload-size"; return false; }
    switch (tx.nIssuedOp) {
    case ISSUED_OP_CREATE: {
        IssuedCreate x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-create-payload"; return false; }
        if (x.nKind != ISSUED_KIND_GOLD_MG && x.nKind != ISSUED_KIND_USD_CENTS) { strReason = "bad-issued-create-kind"; return false; }
        if (!IsValidAssetTicker(x.strTicker)) { strReason = "bad-issued-create-ticker"; return false; }
        if (!IsCompressedKey(x.vchIssuerKey)) { strReason = "bad-issued-create-issuer-key"; return false; }
        if (!x.vchFreezeKey.empty() && !IsCompressedKey(x.vchFreezeKey)) { strReason = "bad-issued-create-freeze-key"; return false; }
        if (x.vchBackingContract.size() != 20 || x.vchBackingAddress.size() != 20) {
            strReason = "bad-issued-create-backing"; return false;
        }
        if (!IsValidUpstream(x.strUpstream)) { strReason = "bad-issued-create-upstream"; return false; }
        // The house link arrives with the house machine (GOLD_USD_SCOPE.md step 5).
        if (x.nIssuerHouseID != 0) { strReason = "bad-issued-create-house"; return false; }
        if (!tx.vIssuedOut.empty()) { strReason = "bad-issued-annex-op"; return false; }
        break;
    }
    case ISSUED_OP_MINT: {
        IssuedMint x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-mint-payload"; return false; }
        if (x.tokenID.IsNull() || x.nUnits == 0 || x.nUnits > (uint64_t)MAX_MONEY) { strReason = "bad-issued-mint-units"; return false; }
        break;
    }
    case ISSUED_OP_BURN: {
        IssuedBurn x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-burn-payload"; return false; }
        if (x.tokenID.IsNull() || x.nUnits == 0 || x.nUnits > (uint64_t)MAX_MONEY) { strReason = "bad-issued-burn-units"; return false; }
        if (x.vchEthDest.size() != 20) { strReason = "bad-issued-burn-dest"; return false; }
        // D-2026-11-04-1 (3d, review 11-04): no burn the issuer can never pay to the zero address, and none so small
        // that its Ethereum transfer costs more than it pays (a gram, or ten dollars).
        if (std::all_of(x.vchEthDest.begin(), x.vchEthDest.end(), [](unsigned char c) { return c == 0; })) {
            strReason = "bad-issued-burn-dest-zero"; return false;
        }
        if (x.nUnits < ISSUED_BURN_MIN_UNITS) { strReason = "bad-issued-burn-small"; return false; }
        break;
    }
    case ISSUED_OP_TRANSFER:
        if (!tx.vchIssuedPayload.empty()) { strReason = "bad-issued-transfer-payload"; return false; }
        if (tx.vIssuedOut.empty()) { strReason = "bad-issued-transfer-empty"; return false; }
        break;
    case ISSUED_OP_FREEZE:
    case ISSUED_OP_UNFREEZE: {
        IssuedFreeze x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-freeze-payload"; return false; }
        if (x.tokenID.IsNull() || (x.vOutpoint.empty() && x.vVault.empty()) ||
                x.vOutpoint.size() + x.vVault.size() > MAX_ISSUED_FREEZE_OUTPOINTS || x.vFrozen.size() != x.vOutpoint.size()) {
            strReason = "bad-issued-freeze-shape"; return false;
        }
        std::set<COutPoint> setSeen;
        for (const COutPoint& o : x.vOutpoint)
            if (!setSeen.insert(o).second) { strReason = "bad-issued-freeze-duplicate"; return false; }
        std::set<uint32_t> setHouse;
        for (const CVaultFreezeTarget& v : x.vVault)
            if (v.nHouseID == 0 || !setHouse.insert(v.nHouseID).second) { strReason = "bad-issued-freeze-duplicate"; return false; }
        if (!tx.vIssuedOut.empty()) { strReason = "bad-issued-annex-op"; return false; }
        break;
    }
    case ISSUED_OP_BOND: {
        IssuedBond x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x) || x.tokenID.IsNull()) { strReason = "bad-issued-bond-payload"; return false; }
        if (!tx.vIssuedOut.empty()) { strReason = "bad-issued-annex-op"; return false; }
        if (tx.vout.empty() || tx.vout[0].nValue <= 0 || tx.vout[0].scriptPubKey != IssuedBondScript(x.tokenID)) {
            strReason = "bad-issued-bond-out"; return false;
        }
        // Only vout[0] carries the bond script: any other would enter the UTXO set untagged and anyone-can-spend.
        for (size_t o = 1; o < tx.vout.size(); o++)
            if (IsIssuedBondScript(tx.vout[o].scriptPubKey)) { strReason = "bad-issued-bond-stray"; return false; }
        break;
    }
    case ISSUED_OP_POOL_CREATE: {
        IssuedPoolCreate x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x) || x.tokenID.IsNull()) { strReason = "bad-issued-pool-payload"; return false; }
        if (x.nFeeBps < POOL_FEE_BPS_MIN || x.nFeeBps > POOL_FEE_BPS_MAX || x.nInitUnits == 0 || x.nInitSats <= 0 ||
                x.nInitSats > MAX_MONEY || x.nLpOut == 0) {
            strReason = "bad-issued-pool-amounts"; return false;
        }
        if (!CheckPoolCustodyShape(tx, x.tokenID, strReason) || !CheckPoolLpOut(tx, x.tokenID, x.nLpOut, strReason))
            return false;
        if (FindIssuedOut(tx, 0)->nUnits != x.nInitUnits || tx.vout[1].nValue != x.nInitSats) {
            strReason = "bad-issued-pool-custody-amount"; return false;
        }
        break;
    }
    case ISSUED_OP_POOL_ADD: {
        IssuedPoolAdd x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x) || x.tokenID.IsNull()) { strReason = "bad-issued-pool-payload"; return false; }
        if (x.nAddUnits == 0 || x.nAddSats <= 0 || x.nAddSats > MAX_MONEY || x.nLpMinted == 0) {
            strReason = "bad-issued-pool-amounts"; return false;
        }
        if (!CheckPoolCustodyShape(tx, x.tokenID, strReason) || !CheckPoolLpOut(tx, x.tokenID, x.nLpMinted, strReason))
            return false;
        break;
    }
    case ISSUED_OP_POOL_REMOVE: {
        IssuedPoolRemove x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x) || x.tokenID.IsNull()) { strReason = "bad-issued-pool-payload"; return false; }
        if (x.nBurnLp == 0 || x.nSatsOut < 0 || x.nSatsOut > MAX_MONEY || (x.nUnitsOut == 0 && x.nSatsOut == 0)) {
            strReason = "bad-issued-pool-amounts"; return false;
        }
        if (!CheckPoolCustodyShape(tx, x.tokenID, strReason))
            return false;
        break;
    }
    case ISSUED_OP_POOL_SWAP: {
        IssuedPoolSwap x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x) || x.tokenID.IsNull() || x.fSellTokens > 1) {
            strReason = "bad-issued-pool-payload"; return false;
        }
        if (x.nAmountIn == 0 || x.nAmountOut == 0 || x.nAmountIn > (uint64_t)MAX_MONEY || x.nAmountOut > (uint64_t)MAX_MONEY) {
            strReason = "bad-issued-pool-amounts"; return false;
        }
        if (!CheckPoolCustodyShape(tx, x.tokenID, strReason))
            return false;
        break;
    }
    case ISSUED_OP_UNBOND: {
        IssuedUnbond x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x) || x.tokenID.IsNull() || x.fWithdraw > 1) {
            strReason = "bad-issued-unbond-payload"; return false;
        }
        if (!tx.vIssuedOut.empty()) { strReason = "bad-issued-annex-op"; return false; }
        for (const CTxOut& out : tx.vout)
            if (IsIssuedBondScript(out.scriptPubKey)) { strReason = "bad-issued-bond-stray"; return false; }
        break;
    }
    default:
        strReason = "bad-issued-op";
        return false;
    }
    return true;
}

bool CheckIssuedFlow(const CTransaction& tx, const std::vector<const Coin*>& vSpent, std::string& strReason)
{
    if (vSpent.size() != tx.vin.size()) { strReason = "bad-issued-internal-inputs"; return false; }

    std::map<uint256, uint64_t> mapIn;
    for (const Coin* coin : vSpent) {
        if (!coin || !coin->fIssued)
            continue;
        if (!HasIssuedAnnex(tx.nVersion) || (!IssuedAnnexAllowed(tx) && !VaultMovesAllowed(tx))) {
            strReason = "bad-issued-input-op"; return false;
        }
        uint64_t& n = mapIn[coin->assetID];
        if (coin->nIssuedUnits > (uint64_t)MAX_MONEY || n > (uint64_t)MAX_MONEY - coin->nIssuedUnits) {
            strReason = "bad-issued-input-units"; return false;
        }
        n += coin->nIssuedUnits;
    }
    if (!HasIssuedAnnex(tx.nVersion))
        return true;

    std::map<uint256, uint64_t> mapOut, mapFrozenOut;
    if (!IssuedSumAnnex(tx, mapOut, mapFrozenOut)) { strReason = "bad-issued-annex-units"; return false; }

    // What the op itself adds or removes: a MINT's units; a BURN's; the LP shares a pool CREATE / ADD mints and a
    // REMOVE burns.
    uint256 tokenDelta;
    uint64_t nMinted = 0, nBurned = 0;
    if (tx.nVersion == TRANSACTION_TOKEN_VERSION && tx.nIssuedOp == ISSUED_OP_MINT) {
        IssuedMint x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-mint-payload"; return false; }
        tokenDelta = x.tokenID;
        nMinted = x.nUnits;
    } else if (tx.nVersion == TRANSACTION_TOKEN_VERSION && tx.nIssuedOp == ISSUED_OP_BURN) {
        IssuedBurn x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-burn-payload"; return false; }
        tokenDelta = x.tokenID;
        nBurned = x.nUnits;
    } else if (tx.nVersion == TRANSACTION_TOKEN_VERSION && tx.nIssuedOp == ISSUED_OP_POOL_CREATE) {
        IssuedPoolCreate x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-pool-payload"; return false; }
        tokenDelta = LpTokenID(x.tokenID);
        nMinted = x.nLpOut;
    } else if (tx.nVersion == TRANSACTION_TOKEN_VERSION && tx.nIssuedOp == ISSUED_OP_POOL_ADD) {
        IssuedPoolAdd x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-pool-payload"; return false; }
        tokenDelta = LpTokenID(x.tokenID);
        nMinted = x.nLpMinted;
    } else if (tx.nVersion == TRANSACTION_TOKEN_VERSION && tx.nIssuedOp == ISSUED_OP_POOL_REMOVE) {
        IssuedPoolRemove x;
        if (!DecodeIssuedPayload(tx.vchIssuedPayload, x)) { strReason = "bad-issued-pool-payload"; return false; }
        tokenDelta = LpTokenID(x.tokenID);
        nBurned = x.nBurnLp;
    }

    // Vault moves: units into a vault leave the outputs' side, units out of one join the inputs' side.
    for (const CVaultMove& m : tx.vVaultMove) {
        uint64_t& n = m.nDelta > 0 ? mapOut[m.tokenID] : mapIn[m.tokenID];
        const uint64_t nAbs = m.nDelta > 0 ? (uint64_t)m.nDelta : (uint64_t)(-m.nDelta);
        if (n > (uint64_t)MAX_MONEY - nAbs) { strReason = "bad-vault-move-units"; return false; }
        n += nAbs;
    }

    std::set<uint256> setToken;
    for (const auto& p : mapIn) setToken.insert(p.first);
    for (const auto& p : mapOut) setToken.insert(p.first);
    if (!tokenDelta.IsNull()) setToken.insert(tokenDelta);
    for (const uint256& token : setToken) {
        const uint64_t nIn = mapIn.count(token) ? mapIn[token] : 0;
        const uint64_t nOut = mapOut.count(token) ? mapOut[token] : 0;
        if (token == tokenDelta) {
            if (nMinted && (nOut < nMinted || nOut - nMinted != nIn)) { strReason = "bad-issued-mint-flow"; return false; }
            if (nBurned && (nIn < nBurned || nIn - nBurned != nOut)) { strReason = "bad-issued-burn-flow"; return false; }
        } else if (nIn != nOut) {
            strReason = "bad-issued-flow";
            return false;
        }
    }
    return true;
}

uint256 CreditHashOutputs(const CTransaction& tx)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBank/credit-outputs");
    ss << BillHashOutputs(tx);
    ss << tx.vIssuedOut;
    ss << tx.vVaultMove;
    return ss.GetHash();
}

bool IsGoldUnpayableScript(const CScript& script)
{
    return script.IsUnspendable() || IsHouseEscrowScript(script) || IsBillEscrowScript(script) ||
           IsPoolEscrowScript(script) || IsIssuedBondScript(script) || IsOracleBondScript(script) ||
           IsNotePreAuthScript(script) || IsTokenPoolScript(script);
}

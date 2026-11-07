// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Issued tokens in the wallet (gram-notes release, issued.h, docs-local/GOLD_USD_SCOPE.md step 2): build, sign and
// send the v18 ops, list the wallet's token coins, and the RPCs over them.

#include <notices.h>
#include <wallet/wallet.h>

#include <base58.h>
#include <bill.h>
#include <houserate.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <house.h>
#include <issued.h>
#include <net.h>
#include <policy/policy.h>
#include <pool.h>
#include <txdb.h>
#include <txmempool.h>
#include <rpc/server.h>
#include <script/sign.h>
#include <units.h>

#include <limits>
#include <utilstrencodings.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>

#include <univalue.h>

namespace {

template <typename T>
std::vector<unsigned char> EncodeIssued(const T& payload)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

/** Frozen units of a coin: a FREEZE / UNFREEZE record if there is one, else what its annex said. */
uint64_t FrozenUnitsOf(const COutPoint& out, uint64_t nAnnexFrozen)
{
    uint64_t nFrozen = nAnnexFrozen;
    if (punitsdb) {
        CUnitsView view(punitsdb.get());
        view.Get(IssuedFrozenKey(out.hash, out.n), nFrozen);
    }
    return nFrozen;
}

} // namespace

void CWallet::ListIssuedCoins(const uint256& tokenID, std::vector<CIssuedWalletCoin>& vOut) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    vOut.clear();
    for (const std::pair<const uint256, CWalletTx>& entry : mapWallet) {
        const CWalletTx& wtx = entry.second;
        if (!HasIssuedAnnex(wtx.tx->nVersion) || wtx.tx->vIssuedOut.empty())
            continue;
        if (wtx.GetDepthInMainChain() < 0 || (wtx.GetDepthInMainChain() == 0 && !wtx.InMempool()))
            continue;
        for (const CIssuedOut& o : wtx.tx->vIssuedOut) {
            if (!tokenID.IsNull() && o.tokenID != tokenID)
                continue;
            if (IsSpent(entry.first, o.nOut) || !(IsMine(wtx.tx->vout[o.nOut]) & ISMINE_SPENDABLE))
                continue;
            CIssuedWalletCoin c;
            c.outpoint = COutPoint(entry.first, o.nOut);
            c.tokenID = o.tokenID;
            c.nUnits = o.nUnits;
            c.nFrozen = FrozenUnitsOf(c.outpoint, o.nFrozen);
            c.txout = wtx.tx->vout[o.nOut];
            c.nDepth = wtx.GetDepthInMainChain();
            vOut.push_back(c);
        }
    }
}

bool CWallet::CommitIssuedTx(std::string& strFail, uint256& txidOut, CMutableTransaction& mtx,
                             const std::vector<CIssuedWalletCoin>& vTokenIn, const CAmount& nFee,
                             const std::function<bool(const CTransaction&)>& fnPayload,
                             const std::vector<std::pair<COutPoint, CTxOut>>& vEscrowIn)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    if (mtx.nVersion != TRANSACTION_HOUSE_VERSION)   // the gold vault ops are house ops (step 5)
        mtx.nVersion = TRANSACTION_TOKEN_VERSION;

    // Fund the outputs' values and the fee from plain ECX; the token and escrow inputs bring their own value (a swap
    // that takes sats out of a pool's custody leaves nNeed negative: the difference is the swapper's change).
    CAmount nNeed = nFee;
    for (const CTxOut& o : mtx.vout)
        nNeed += o.nValue;
    for (const CIssuedWalletCoin& c : vTokenIn)
        nNeed -= c.txout.nValue;
    for (const std::pair<COutPoint, CTxOut>& e : vEscrowIn)
        nNeed -= e.second.nValue;
    std::vector<COutput> vAvailable;
    AvailableCoins(vAvailable, true);
    std::vector<COutput> vPlain;
    for (const COutput& out : vAvailable)
        if (out.fSpendable)
            vPlain.push_back(out);
    std::set<CInputCoin> setCoins;
    CAmount nIn = 0;
    // An op with no outputs of its own (FREEZE, UNBOND, CREATE) needs its change as its one output: select enough
    // that the change is never dust (an exact-fee coin would leave a transaction with no outputs at all).
    const bool fNeedChange = mtx.vout.empty();
    const CAmount nChangeMin = fNeedChange ? 2 * ISSUED_COIN_VALUE : 0;
    if (nNeed + nChangeMin > 0 && !SelectCoins(vPlain, nNeed + nChangeMin, setCoins, nIn)) {
        strFail = "Insufficient plain funds for the outputs and fee";
        return false;
    }
    CReserveKey reserveKey(this);
    const CAmount nChange = nIn - nNeed;
    if (nChange > 0) {
        CPubKey pubChange;
        if (!reserveKey.GetReservedKey(pubChange)) { strFail = "Keypool ran out"; return false; }
        CTxOut outChange(nChange, GetScriptForDestination(pubChange.GetID()));
        if (!IsDust(outChange, ::dustRelayFee))
            mtx.vout.push_back(outChange);   // after every annex output, so the annex's indices stand
    }
    // Escrow inputs first (a pool's custody pair at vin[0] / vin[1]); their script needs no signature.
    std::vector<CTxOut> vSpentOut;
    for (const std::pair<COutPoint, CTxOut>& e : vEscrowIn) {
        mtx.vin.push_back(CTxIn(e.first));
        vSpentOut.push_back(e.second);
    }
    for (const CIssuedWalletCoin& c : vTokenIn) {
        mtx.vin.push_back(CTxIn(c.outpoint));
        vSpentOut.push_back(c.txout);
    }
    for (const CInputCoin& coin : setCoins) {
        mtx.vin.push_back(CTxIn(coin.outpoint));
        vSpentOut.push_back(coin.txout);
    }
    if (mtx.vin.empty()) { strFail = "No inputs"; return false; }

    // The token key's payload signature binds the prevouts, outputs and annex: inputs and outputs are final now.
    if (fnPayload && !fnPayload(CTransaction(mtx))) {
        strFail = "Failed to sign the token op";
        return false;
    }

    const CTransaction txToSign(mtx);
    for (unsigned int nInput = vEscrowIn.size(); nInput < mtx.vin.size(); nInput++) {
        SignatureData sigdata;
        if (!ProduceSignature(TransactionSignatureCreator(this, &txToSign, nInput, vSpentOut[nInput].nValue, SIGHASH_ALL),
                              vSpentOut[nInput].scriptPubKey, sigdata)) {
            strFail = "Signing the inputs failed";
            return false;
        }
        UpdateTransaction(mtx, nInput, sigdata);
    }

    CWalletTx walletTx;
    walletTx.fTimeReceivedIsTxTime = true;
    walletTx.fFromMe = true;
    walletTx.BindWallet(this);
    walletTx.SetTx(MakeTransactionRef(std::move(mtx)));
    CValidationState state;
    if (!CommitTransaction(walletTx, reserveKey, g_connman.get(), state)) {
        strFail = "Commit failed: " + FormatStateMessage(state);
        return false;
    }
    // CommitTransaction keeps a transaction the pool refused and still returns true; a token op the pool refuses is
    // a rule failure, not a relay delay, so say so and abandon it.
    if (!state.IsValid()) {
        AbandonTransaction(walletTx.tx->GetHash());
        strFail = "Refused: " + FormatStateMessage(state);
        return false;
    }
    txidOut = walletTx.tx->GetHash();
    return true;
}

namespace {

/** Pick the wallet's coins of a token until their unfrozen units cover nUnits. */
bool PickTokenCoins(const std::vector<CIssuedWalletCoin>& vCoins, uint64_t nUnits, std::vector<CIssuedWalletCoin>& vPick,
                    uint64_t& nUnitsIn, uint64_t& nFrozenIn)
{
    vPick.clear();
    nUnitsIn = nFrozenIn = 0;
    uint64_t nFree = 0;
    for (const CIssuedWalletCoin& c : vCoins) {
        if (c.nUnits == c.nFrozen)
            continue;
        vPick.push_back(c);
        nUnitsIn += c.nUnits;
        nFrozenIn += c.nFrozen;
        nFree += c.nUnits - c.nFrozen;
        if (nFree >= nUnits)
            return true;
    }
    return false;
}

/** D-2026-11-04-1 (3b), Gold B: a token or pool creation burns nCreateFeeSats of sECX. */
bool AddCreationBurn(CMutableTransaction& mtx, std::string& strFail)
{
    const int nNext = chainActive.Height() + 1;
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nNext);
    if (gp.nCreateFeeSats <= 0)
        return true;
    mtx.vout.push_back(CTxOut(gp.nCreateFeeSats, CreationBurnScript()));
    return true;
}

CIssuedOut AnnexOut(uint32_t n, const uint256& token, uint64_t nUnits, uint64_t nFrozen)
{
    CIssuedOut o;
    o.nOut = n;
    o.tokenID = token;
    o.nUnits = nUnits;
    o.nFrozen = nFrozen;
    return o;
}

} // namespace

bool CWallet::CreateIssuedToken(std::string& strFail, uint256& tokenIDOut, IssuedCreate& create, bool fFreezeKey,
                                const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    CPubKey pubIssuer, pubFreeze;
    if (!GetKeyFromPool(pubIssuer, false) || (fFreezeKey && !GetKeyFromPool(pubFreeze, false))) {
        strFail = "Keypool ran out";
        return false;
    }
    create.vchIssuerKey = ToByteVector(pubIssuer);
    create.vchFreezeKey = fFreezeKey ? ToByteVector(pubFreeze) : std::vector<unsigned char>();
    CKey keyIssuer;
    if (!GetKey(pubIssuer.GetID(), keyIssuer)) { strFail = "Issuer key not in the wallet"; return false; }

    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_CREATE;
    mtx.vchIssuedPayload = EncodeIssued(create);
    if (!AddCreationBurn(mtx, strFail))
        return false;
    if (!CommitIssuedTx(strFail, tokenIDOut, mtx, {}, nFee, [&](const CTransaction& tx) {
            CMutableTransaction m(tx);
            m.vchIssuedPayload = EncodeIssued(create);
            if (!keyIssuer.Sign(IssuedSigHash(CTransaction(m)), create.vchIssuerSig))
                return false;
            mtx.vchIssuedPayload = EncodeIssued(create);
            return true;
        }))
        return false;
    return true;
}

bool CWallet::MintIssued(std::string& strFail, uint256& txidOut, const uint256& tokenID, uint64_t nUnits,
                         const CTxDestination& dest, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    CIssuedToken token;
    {
        CUnitsView view(punitsdb.get());
        if (!view.Get(IssuedTokenKey(tokenID), token)) { strFail = "Unknown token"; return false; }
    }
    CKey keyIssuer;
    if (!GetKey(CPubKey(token.vchIssuerKey).GetID(), keyIssuer)) { strFail = "This wallet doesn't hold the token's issuer key"; return false; }

    IssuedMint mint;
    mint.tokenID = tokenID;
    mint.nUnits = nUnits;
    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_MINT;
    mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(dest)));
    mtx.vIssuedOut = {AnnexOut(0, tokenID, nUnits, 0)};
    mtx.vchIssuedPayload = EncodeIssued(mint);
    return CommitIssuedTx(strFail, txidOut, mtx, {}, nFee, [&](const CTransaction& tx) {
        if (!keyIssuer.Sign(IssuedSigHash(tx), mint.vchIssuerSig))
            return false;
        mtx.vchIssuedPayload = EncodeIssued(mint);
        return true;
    });
}

bool CWallet::SendIssued(std::string& strFail, uint256& txidOut, const uint256& tokenID, uint64_t nUnits,
                         const CTxDestination& dest, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    std::vector<CIssuedWalletCoin> vCoins, vPick;
    ListIssuedCoins(tokenID, vCoins);
    uint64_t nUnitsIn = 0, nFrozenIn = 0;
    if (!PickTokenCoins(vCoins, nUnits, vPick, nUnitsIn, nFrozenIn)) { strFail = "Insufficient unfrozen token units"; return false; }

    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_TRANSFER;
    mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(dest)));
    mtx.vIssuedOut = {AnnexOut(0, tokenID, nUnits, 0)};
    if (nUnitsIn > nUnits) {
        // Token change, with every frozen unit the inputs carried.
        CPubKey pubChange;
        if (!GetKeyFromPool(pubChange, true)) { strFail = "Keypool ran out"; return false; }
        mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubChange.GetID())));
        mtx.vIssuedOut.push_back(AnnexOut(1, tokenID, nUnitsIn - nUnits, nFrozenIn));
    }
    return CommitIssuedTx(strFail, txidOut, mtx, vPick, nFee, nullptr);
}

bool CWallet::BurnIssued(std::string& strFail, uint256& txidOut, const uint256& tokenID, uint64_t nUnits,
                         const std::vector<unsigned char>& vchEthDest, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    std::vector<CIssuedWalletCoin> vCoins, vPick;
    ListIssuedCoins(tokenID, vCoins);
    uint64_t nUnitsIn = 0, nFrozenIn = 0;
    if (!PickTokenCoins(vCoins, nUnits, vPick, nUnitsIn, nFrozenIn)) { strFail = "Insufficient unfrozen token units"; return false; }

    IssuedBurn burn;
    burn.tokenID = tokenID;
    burn.nUnits = nUnits;
    burn.vchEthDest = vchEthDest;
    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_BURN;
    mtx.vchIssuedPayload = EncodeIssued(burn);
    if (nUnitsIn > nUnits) {
        CPubKey pubChange;
        if (!GetKeyFromPool(pubChange, true)) { strFail = "Keypool ran out"; return false; }
        mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubChange.GetID())));
        mtx.vIssuedOut = {AnnexOut(0, tokenID, nUnitsIn - nUnits, nFrozenIn)};
    }
    return CommitIssuedTx(strFail, txidOut, mtx, vPick, nFee, nullptr);
}

bool CWallet::FreezeIssued(std::string& strFail, uint256& txidOut, const uint256& tokenID,
                           const std::vector<COutPoint>& vOutpoint, const std::vector<uint64_t>& vFrozen, bool fFreeze,
                           const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    CIssuedToken token;
    {
        CUnitsView view(punitsdb.get());
        if (!view.Get(IssuedTokenKey(tokenID), token)) { strFail = "Unknown token"; return false; }
    }
    if (token.vchFreezeKey.empty()) { strFail = "The token has no freeze key"; return false; }
    CKey keyFreeze;
    if (!GetKey(CPubKey(token.vchFreezeKey).GetID(), keyFreeze)) { strFail = "This wallet doesn't hold the token's freeze key"; return false; }

    IssuedFreeze fz;
    fz.tokenID = tokenID;
    fz.vOutpoint = vOutpoint;
    fz.vFrozen = vFrozen;
    CMutableTransaction mtx;
    mtx.nIssuedOp = fFreeze ? ISSUED_OP_FREEZE : ISSUED_OP_UNFREEZE;
    mtx.vchIssuedPayload = EncodeIssued(fz);
    return CommitIssuedTx(strFail, txidOut, mtx, {}, nFee, [&](const CTransaction& tx) {
        if (!keyFreeze.Sign(IssuedSigHash(tx), fz.vchFreezeSig))
            return false;
        mtx.vchIssuedPayload = EncodeIssued(fz);
        return true;
    });
}

// ---- Token pools ---------------------------------------------------------------------------------------------------

namespace {

/** The pool's current custody pair: the record's, followed along any pending pool ops in the mempool (each spends the
 *  pair and makes the next), with the units and sats each coin holds. */
bool PoolCustodyTip(const uint256& tokenID, CTokenPool& pool, std::pair<COutPoint, CTxOut>& token,
                    std::pair<COutPoint, CTxOut>& sats, uint64_t& nUnits, std::string& strFail)
{
    AssertLockHeld(cs_main);
    {
        CUnitsView view(punitsdb.get());
        if (!view.Get(TokenPoolKey(tokenID), pool)) { strFail = "The token has no pool"; return false; }
    }
    COutPoint outToken = pool.outToken, outSats = pool.outSats;
    nUnits = pool.nUnits;
    CAmount nSats = pool.nSats;
    {
        LOCK(mempool.cs);
        for (;;) {
            auto it = mempool.mapNextTx.find(outToken);
            if (it == mempool.mapNextTx.end())
                break;
            const CTransaction& next = *it->second;
            if (next.nVersion != TRANSACTION_TOKEN_VERSION || !IsIssuedPoolOp(next.nIssuedOp) || next.vout.size() < 2)
                break;
            const CIssuedOut* p0 = FindIssuedOut(next, 0);
            if (!p0)
                break;
            outToken = COutPoint(next.GetHash(), 0);
            outSats = COutPoint(next.GetHash(), 1);
            nUnits = p0->nUnits;
            nSats = next.vout[1].nValue;
        }
    }
    const CScript script = TokenPoolScript(tokenID);
    token = std::make_pair(outToken, CTxOut(0, script));
    sats = std::make_pair(outSats, CTxOut(nSats, script));
    // The token custody coin's own dust value: read it from wherever it is.
    Coin coin;
    {
        LOCK(mempool.cs);
        CCoinsViewMemPool viewMempool(pcoinsTip.get(), mempool);
        if (!viewMempool.GetCoin(outToken, coin) || coin.IsSpent()) { strFail = "The pool's custody coin is missing"; return false; }
    }
    token.second.nValue = coin.out.nValue;
    pool.nUnits = nUnits;
    pool.nSats = nSats;
    return true;
}

} // namespace

bool CWallet::CreateTokenPool(std::string& strFail, uint256& txidOut, const uint256& tokenID, uint64_t nUnits,
                              const CAmount& nSats, uint32_t nFeeBps, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    std::vector<CIssuedWalletCoin> vCoins, vPick;
    ListIssuedCoins(tokenID, vCoins);
    uint64_t nUnitsIn = 0, nFrozenIn = 0;
    if (!PickTokenCoins(vCoins, nUnits, vPick, nUnitsIn, nFrozenIn)) { strFail = "Insufficient unfrozen token units"; return false; }
    uint64_t nLpOut = 0, nLpSupply = 0;
    if (!PoolLpMintInitial(nUnits, nSats, nLpOut, nLpSupply)) { strFail = "Pool too small (sqrt(units * sats) must exceed 1000)"; return false; }
    CPubKey pubLp, pubChange;
    if (!GetKeyFromPool(pubLp, true) || !GetKeyFromPool(pubChange, true)) { strFail = "Keypool ran out"; return false; }

    IssuedPoolCreate x;
    x.tokenID = tokenID;
    x.nFeeBps = nFeeBps;
    x.nInitUnits = nUnits;
    x.nInitSats = nSats;
    x.nLpOut = nLpOut;
    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_POOL_CREATE;
    mtx.vchIssuedPayload = EncodeIssued(x);
    mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, TokenPoolScript(tokenID)));
    mtx.vout.push_back(CTxOut(nSats, TokenPoolScript(tokenID)));
    mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubLp.GetID())));
    mtx.vIssuedOut = {AnnexOut(0, tokenID, nUnits, 0), AnnexOut(2, LpTokenID(tokenID), nLpOut, 0)};
    if (nUnitsIn > nUnits) {
        mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubChange.GetID())));
        mtx.vIssuedOut.push_back(AnnexOut(3, tokenID, nUnitsIn - nUnits, nFrozenIn));
    } else if (nFrozenIn) {
        strFail = "Frozen units can't enter a pool";
        return false;
    }
    if (!AddCreationBurn(mtx, strFail))   // after every annex output, so the annex's indices stand
        return false;
    return CommitIssuedTx(strFail, txidOut, mtx, vPick, nFee, nullptr);
}

bool CWallet::AddTokenLiquidity(std::string& strFail, uint256& txidOut, const uint256& tokenID, uint64_t nUnits,
                                const CAmount& nFee, const CAmount& nMaxSats)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    CTokenPool pool;
    std::pair<COutPoint, CTxOut> cToken, cSats;
    uint64_t nReserveUnits = 0;
    if (!PoolCustodyTip(tokenID, pool, cToken, cSats, nReserveUnits, strFail))
        return false;
    const CAmount nSats = (CAmount)(((unsigned __int128)nUnits * pool.nSats + pool.nUnits - 1) / pool.nUnits);   // ceil
    // The app's bound (11-04): the pool's ratio follows its pending transactions, so a buy pushed into the mempool
    // first could raise the sats this add takes. max_sats refuses to build above it.
    if (nMaxSats > 0 && nSats > nMaxSats) {
        strFail = strprintf("The pool's ratio now asks %d sats for these units, above max_sats %d", nSats, nMaxSats);
        return false;
    }
    uint64_t nMinted = 0;
    if (!PoolLpMintProportional(nUnits, nSats, pool.nUnits, pool.nSats, pool.nLpSupply, nMinted)) {
        strFail = "Liquidity too small to mint a share";
        return false;
    }
    std::vector<CIssuedWalletCoin> vCoins, vPick;
    ListIssuedCoins(tokenID, vCoins);
    uint64_t nUnitsIn = 0, nFrozenIn = 0;
    if (!PickTokenCoins(vCoins, nUnits, vPick, nUnitsIn, nFrozenIn)) { strFail = "Insufficient unfrozen token units"; return false; }
    CPubKey pubLp, pubChange;
    if (!GetKeyFromPool(pubLp, true) || !GetKeyFromPool(pubChange, true)) { strFail = "Keypool ran out"; return false; }

    IssuedPoolAdd x;
    x.tokenID = tokenID;
    x.nPriorLpSupply = pool.nLpSupply;
    x.nAddUnits = nUnits;
    x.nAddSats = nSats;
    x.nLpMinted = nMinted;
    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_POOL_ADD;
    mtx.vchIssuedPayload = EncodeIssued(x);
    mtx.vout.push_back(CTxOut(cToken.second.nValue, TokenPoolScript(tokenID)));
    mtx.vout.push_back(CTxOut(pool.nSats + nSats, TokenPoolScript(tokenID)));
    mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubLp.GetID())));
    mtx.vIssuedOut = {AnnexOut(0, tokenID, pool.nUnits + nUnits, 0), AnnexOut(2, LpTokenID(tokenID), nMinted, 0)};
    if (nUnitsIn > nUnits) {
        mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubChange.GetID())));
        mtx.vIssuedOut.push_back(AnnexOut(3, tokenID, nUnitsIn - nUnits, nFrozenIn));
    }
    return CommitIssuedTx(strFail, txidOut, mtx, vPick, nFee, nullptr, {cToken, cSats});
}

bool CWallet::RemoveTokenLiquidity(std::string& strFail, uint256& txidOut, const uint256& tokenID, uint64_t nLp,
                                   const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    CTokenPool pool;
    std::pair<COutPoint, CTxOut> cToken, cSats;
    uint64_t nReserveUnits = 0;
    if (!PoolCustodyTip(tokenID, pool, cToken, cSats, nReserveUnits, strFail))
        return false;
    uint64_t nUnitsOut = 0;
    CAmount nSatsOut = 0;
    if (!PoolLpRedeemAmounts(nLp, pool.nUnits, pool.nSats, pool.nLpSupply, nUnitsOut, nSatsOut)) {
        strFail = "That many shares can't be removed (the pool keeps its floor)";
        return false;
    }
    const uint256 lpID = LpTokenID(tokenID);
    std::vector<CIssuedWalletCoin> vCoins, vPick;
    ListIssuedCoins(lpID, vCoins);
    uint64_t nLpIn = 0, nFrozenIn = 0;
    if (!PickTokenCoins(vCoins, nLp, vPick, nLpIn, nFrozenIn)) { strFail = "Insufficient LP shares"; return false; }
    CPubKey pubOut, pubChange;
    if (!GetKeyFromPool(pubOut, true) || !GetKeyFromPool(pubChange, true)) { strFail = "Keypool ran out"; return false; }

    IssuedPoolRemove x;
    x.tokenID = tokenID;
    x.nPriorLpSupply = pool.nLpSupply;
    x.nBurnLp = nLp;
    x.nUnitsOut = nUnitsOut;
    x.nSatsOut = nSatsOut;
    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_POOL_REMOVE;
    mtx.vchIssuedPayload = EncodeIssued(x);
    mtx.vout.push_back(CTxOut(cToken.second.nValue, TokenPoolScript(tokenID)));
    mtx.vout.push_back(CTxOut(pool.nSats - nSatsOut, TokenPoolScript(tokenID)));
    mtx.vIssuedOut = {AnnexOut(0, tokenID, pool.nUnits - nUnitsOut, 0)};
    uint32_t n = 2;
    if (nUnitsOut > 0) {
        mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubOut.GetID())));
        mtx.vIssuedOut.push_back(AnnexOut(n++, tokenID, nUnitsOut, 0));
    }
    if (nLpIn > nLp) {
        mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubChange.GetID())));
        mtx.vIssuedOut.push_back(AnnexOut(n++, lpID, nLpIn - nLp, nFrozenIn));
    }
    return CommitIssuedTx(strFail, txidOut, mtx, vPick, nFee, nullptr, {cToken, cSats});
}

bool CWallet::SwapToken(std::string& strFail, uint256& txidOut, const uint256& tokenID, bool fSell, uint64_t nAmountIn,
                        const CAmount& nFee, uint64_t nMinOut)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    CTokenPool pool;
    std::pair<COutPoint, CTxOut> cToken, cSats;
    uint64_t nReserveUnits = 0;
    if (!PoolCustodyTip(tokenID, pool, cToken, cSats, nReserveUnits, strFail))
        return false;
    uint64_t nOut = 0;
    const bool fOk = fSell ? PoolSwapOut(nAmountIn, pool.nUnits, (uint64_t)pool.nSats, pool.nFeeBps, nOut)
                           : PoolSwapOut(nAmountIn, (uint64_t)pool.nSats, pool.nUnits, pool.nFeeBps, nOut);
    if (!fOk) { strFail = "Swap out of range for the pool"; return false; }
    // The app's bound (11-04): the exact output follows the pool's pending transactions; min_out refuses to build below
    // it (the chain then holds the swap to that exact output, decision 14).
    if (nMinOut > 0 && nOut < nMinOut) {
        strFail = strprintf("The pool now gives %u for this swap, below min_out %u", nOut, nMinOut);
        return false;
    }

    IssuedPoolSwap x;
    x.tokenID = tokenID;
    x.fSellTokens = fSell ? 1 : 0;
    x.nAmountIn = nAmountIn;
    x.nAmountOut = nOut;
    CMutableTransaction mtx;
    mtx.nIssuedOp = ISSUED_OP_POOL_SWAP;
    mtx.vchIssuedPayload = EncodeIssued(x);
    mtx.vout.push_back(CTxOut(cToken.second.nValue, TokenPoolScript(tokenID)));
    std::vector<CIssuedWalletCoin> vPick;
    if (fSell) {
        // Token units in; the sats out come back as this wallet's change (the custody coin shrinks).
        mtx.vout.push_back(CTxOut(pool.nSats - (CAmount)nOut, TokenPoolScript(tokenID)));
        mtx.vIssuedOut = {AnnexOut(0, tokenID, pool.nUnits + nAmountIn, 0)};
        std::vector<CIssuedWalletCoin> vCoins;
        ListIssuedCoins(tokenID, vCoins);
        uint64_t nUnitsIn = 0, nFrozenIn = 0;
        if (!PickTokenCoins(vCoins, nAmountIn, vPick, nUnitsIn, nFrozenIn)) { strFail = "Insufficient unfrozen token units"; return false; }
        if (nUnitsIn > nAmountIn) {
            CPubKey pubChange;
            if (!GetKeyFromPool(pubChange, true)) { strFail = "Keypool ran out"; return false; }
            mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubChange.GetID())));
            mtx.vIssuedOut.push_back(AnnexOut(2, tokenID, nUnitsIn - nAmountIn, nFrozenIn));
        }
    } else {
        mtx.vout.push_back(CTxOut(pool.nSats + (CAmount)nAmountIn, TokenPoolScript(tokenID)));
        mtx.vIssuedOut = {AnnexOut(0, tokenID, pool.nUnits - nOut, 0)};
        CPubKey pubOut;
        if (!GetKeyFromPool(pubOut, true)) { strFail = "Keypool ran out"; return false; }
        mtx.vout.push_back(CTxOut(ISSUED_COIN_VALUE, GetScriptForDestination(pubOut.GetID())));
        mtx.vIssuedOut.push_back(AnnexOut(2, tokenID, nOut, 0));
    }
    return CommitIssuedTx(strFail, txidOut, mtx, vPick, nFee, nullptr, {cToken, cSats});
}

static bool HouseApproverKeys(const CWallet& wallet, const CHouse& house, std::vector<uint32_t>& vIdx, std::vector<CKey>& vKey)
{
    vIdx.clear();
    vKey.clear();
    for (uint32_t i = 0; i < house.vPartner.size() && vIdx.size() < house.nThresholdM; i++) {
        if (house.vPartner[i].status != HOUSE_PARTNER_ACTIVE)
            continue;
        CKey k;
        if (wallet.GetKey(CPubKey(house.vPartner[i].vchPubKey).GetID(), k)) {
            vIdx.push_back(i);
            vKey.push_back(k);
        }
    }
    return vIdx.size() >= house.nThresholdM;
}

// ---- Gold B: the house's rate (HOUSE_OP_RATE) and charter (HOUSE_OP_CHARTER) ----

static bool CommitHouseOp(CWallet* pwallet, std::string& strFail, uint256& txidOut, uint8_t nOp, const CAmount& nFee,
                          const std::function<bool(const CTransaction&, CMutableTransaction&)>& fnSign)
{
    CMutableTransaction mtx;
    mtx.nVersion = TRANSACTION_HOUSE_VERSION;
    mtx.nHouseOp = nOp;
    return pwallet->CommitIssuedTx(strFail, txidOut, mtx, std::vector<CIssuedWalletCoin>(), nFee,
                                   [&](const CTransaction& tx) { return fnSign(tx, mtx); });
}

static bool WalletPostHouseRate(CWallet* pwallet, std::string& strFail, uint256& txidOut, uint32_t nHouseID, uint64_t nBid,
                                uint64_t nAsk, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pwallet->cs_wallet);
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(chainActive.Height() + 1);
    if (!HouseRateShapeOK(nBid, nAsk, gp.nRateSpreadBps)) {
        strFail = strprintf("Need 0 < bid <= ask <= bid x %.2f", 1.0 + gp.nRateSpreadBps / 10000.0); return false;
    }
    std::vector<unsigned char> vchKey;
    if (!HouseRateKeyForChecks(nHouseID, vchKey)) { strFail = "The house has no rate key yet (sethouseratekey)"; return false; }
    CKey key;
    if (!pwallet->GetKey(CPubKey(vchKey).GetID(), key)) { strFail = "This wallet doesn't hold the house's rate key"; return false; }
    HouseRate rate;
    rate.nHouseID = nHouseID;
    rate.nKind = HOUSE_RATE_POST;
    rate.nBid = nBid;
    rate.nAsk = nAsk;
    return CommitHouseOp(pwallet, strFail, txidOut, HOUSE_OP_RATE, nFee, [&](const CTransaction& tx, CMutableTransaction& m) {
        if (!key.Sign(HouseRateSigHash(nHouseID, tx, rate), rate.vchRateSig))
            return false;
        m.vchHousePayload = EncodeIssued(rate);
        return true;
    });
}

static bool WalletHouseApproved(CWallet* pwallet, std::string& strFail, const CHouse& house, std::vector<uint32_t>& vIdx,
                                std::vector<CKey>& vKey)
{
    if (!HouseApproverKeys(*pwallet, house, vIdx, vKey)) {
        strFail = strprintf("This wallet holds fewer than %u of the house's partner keys", house.nThresholdM); return false;
    }
    return true;
}

static bool WalletSetHouseRateKey(CWallet* pwallet, std::string& strFail, uint256& txidOut, uint32_t nHouseID,
                                  const CPubKey& pubKey, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pwallet->cs_wallet);
    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house)) { strFail = "Unknown house"; return false; }
    std::vector<uint32_t> vIdx;
    std::vector<CKey> vKey;
    if (!WalletHouseApproved(pwallet, strFail, house, vIdx, vKey)) return false;
    if (!pubKey.IsCompressed()) { strFail = "The rate key must be a compressed public key"; return false; }
    HouseRate rate;
    rate.nHouseID = nHouseID;
    rate.nKind = HOUSE_RATE_SETKEY;
    rate.vchRatePubKey = std::vector<unsigned char>(pubKey.begin(), pubKey.end());
    return CommitHouseOp(pwallet, strFail, txidOut, HOUSE_OP_RATE, nFee, [&](const CTransaction& tx, CMutableTransaction& m) {
        const uint256 h = HouseRateSigHash(nHouseID, tx, rate);
        rate.vApproverIndex = vIdx;
        rate.vApproverSig.assign(vKey.size(), {});
        for (size_t i = 0; i < vKey.size(); i++)
            if (!vKey[i].Sign(h, rate.vApproverSig[i]))
                return false;
        m.vchHousePayload = EncodeIssued(rate);
        return true;
    });
}

static bool WalletHouseCharter(CWallet* pwallet, std::string& strFail, uint256& txidOut, HouseCharter op, const CAmount& nFee)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pwallet->cs_wallet);
    CHouse house;
    if (!phousetree->GetHouse(op.nHouseID, house)) { strFail = "Unknown house"; return false; }
    std::vector<uint32_t> vIdx;
    std::vector<CKey> vKey;
    if (!WalletHouseApproved(pwallet, strFail, house, vIdx, vKey)) return false;
    return CommitHouseOp(pwallet, strFail, txidOut, HOUSE_OP_CHARTER, nFee, [&](const CTransaction& tx, CMutableTransaction& m) {
        const uint256 h = HouseCharterSigHash(op.nHouseID, tx, op);
        op.vApproverIndex = vIdx;
        op.vApproverSig.assign(vKey.size(), {});
        for (size_t i = 0; i < vKey.size(); i++)
            if (!vKey[i].Sign(h, op.vApproverSig[i]))
                return false;
        m.vchHousePayload = EncodeIssued(op);
        return true;
    });
}

// ---- RPCs ----------------------------------------------------------------------------------------------------------

namespace {

uint256 ParseTokenID(const UniValue& v)
{
    const uint256 id = ParseHashV(v, "token_id");
    if (id.IsNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "token_id is null");
    return id;
}

uint64_t ParseUnits(const UniValue& v)
{
    const int64_t n = v.get_int64();
    if (n <= 0 || n > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "units out of range");
    return (uint64_t)n;
}

std::vector<unsigned char> ParseBytes20(const UniValue& v, const std::string& strName)
{
    std::string str = v.get_str();
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
        str = str.substr(2);
    if (str.size() != 40 || !IsHex(str))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strName + " must be 20 bytes of hex (an Ethereum address)");
    return ParseHex(str);
}

CAmount ParseFee(const JSONRPCRequest& request, size_t nIndex)
{
    if (request.params.size() > nIndex && !request.params[nIndex].isNull())
        return AmountFromValue(request.params[nIndex]);
    return 100000;
}

CWallet* WalletOrThrow(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return nullptr;
    return pwallet;
}

UniValue TokenToUniv(const CIssuedToken& t)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("token_id", t.tokenID.GetHex());
    o.pushKV("kind", t.nKind == ISSUED_KIND_GOLD_MG ? "gold_mg_retired" : t.nKind == ISSUED_KIND_USD_CENTS ? "usd_cents" :
                     t.nKind == ISSUED_KIND_POOL_LP ? "pool_lp" : "unknown");   // v1.1.1: pool_lp (was "unknown")
    o.pushKV("ticker", t.strTicker);
    o.pushKV("issuer_key", HexStr(t.vchIssuerKey));
    o.pushKV("freeze_key", HexStr(t.vchFreezeKey));
    o.pushKV("backing_contract", "0x" + HexStr(t.vchBackingContract));
    o.pushKV("backing_address", "0x" + HexStr(t.vchBackingAddress));
    o.pushKV("upstream", t.strUpstream);
    o.pushKV("issuer_house", (uint64_t)t.nIssuerHouseID);
    o.pushKV("create_height", t.nCreateHeight);
    o.pushKV("supply", (uint64_t)t.nSupply);
    o.pushKV("burns_queued", (uint64_t)t.nBurnSeq);
    return o;
}

UniValue createissuedtoken(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 5 || request.params.size() > 7)
        throw std::runtime_error(
            "createissuedtoken \"kind\" \"ticker\" \"backing_contract\" \"backing_address\" \"upstream\" ( freeze_key fee )\n"
            HELP_ROLE_TOKEN_ISSUER
            "\nCreate an issued token: a dollar token in cents,\n"
            "minted by this wallet's new issuer key. Its id is the transaction id. Burns the fixed creation fee (0.1 ECX,\n"
            "GramParams::nCreateFeeSats). Gold B: gold is held on Ethereum, so only dollar tokens are created here.\n"
            "\nArguments:\n"
            "1. kind              (string) \"usd_cents\" (\"gold_mg\" is refused under Gold B)\n"
            "2. ticker            (string) 1-12 characters, A-Z and 0-9\n"
            "3. backing_contract  (string) the Ethereum token contract held as backing, 0x + 20 bytes\n"
            "4. backing_address   (string) the Ethereum account that holds it, 0x + 20 bytes\n"
            "5. upstream          (string) the company behind the contract, 1-32 of a-z, 0-9, '-'\n"
            "6. freeze_key        (boolean, optional, default false) also take a freeze key (declared now or never)\n"
            "7. fee               (numeric, optional, default 0.001)\n"
            + HelpExampleCli("createissuedtoken", "usd_cents USDA 0xdac17f958d2ee523a2206206994597c13d831ec7 0x1111111111111111111111111111111111111111 tether"));
    IssuedCreate create;
    const std::string strKind = request.params[0].get_str();
    if (strKind == "gold_mg")
        create.nKind = ISSUED_KIND_GOLD_MG;
    else if (strKind == "usd_cents")
        create.nKind = ISSUED_KIND_USD_CENTS;
    else
        throw JSONRPCError(RPC_INVALID_PARAMETER, "kind must be usd_cents");
    create.strTicker = request.params[1].get_str();
    create.vchBackingContract = ParseBytes20(request.params[2], "backing_contract");
    create.vchBackingAddress = ParseBytes20(request.params[3], "backing_address");
    create.strUpstream = request.params[4].get_str();
    const bool fFreeze = request.params.size() > 5 && !request.params[5].isNull() && request.params[5].get_bool();
    const CAmount nFee = ParseFee(request, 6);

    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 tokenID;
    std::string strFail;
    if (!pwallet->CreateIssuedToken(strFail, tokenID, create, fFreeze, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    UniValue r(UniValue::VOBJ);
    r.pushKV("token_id", tokenID.GetHex());
    r.pushKV("issuer_key", HexStr(create.vchIssuerKey));
    r.pushKV("freeze_key", HexStr(create.vchFreezeKey));
    return r;
}

UniValue mintissued(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
            "mintissued \"token_id\" units \"address\" ( fee )\n"
            HELP_ROLE_TOKEN_ISSUER
            "\nMint units of a token this wallet issues, to an address.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    const uint64_t nUnits = ParseUnits(request.params[1]);
    const CTxDestination dest = DecodeDestination(request.params[2].get_str());
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    const CAmount nFee = ParseFee(request, 3);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->MintIssued(strFail, txid, tokenID, nUnits, dest, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

UniValue sendissued(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
            "sendissued \"token_id\" units \"address\" ( fee )\n"
            "\nSend units of a token from this wallet (unfrozen units only; frozen units stay with the change).\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    const uint64_t nUnits = ParseUnits(request.params[1]);
    const CTxDestination dest = DecodeDestination(request.params[2].get_str());
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    const CAmount nFee = ParseFee(request, 3);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->SendIssued(strFail, txid, tokenID, nUnits, dest, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

UniValue burnissued(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
            "burnissued \"token_id\" units \"eth_address\" ( fee )\n"
            HELP_ROLE_TOKEN_ISSUER
            "\nBurn units of a token and ask its issuer to pay them out on Ethereum at eth_address.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    const uint64_t nUnits = ParseUnits(request.params[1]);
    const std::vector<unsigned char> vchDest = ParseBytes20(request.params[2], "eth_address");
    const CAmount nFee = ParseFee(request, 3);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->BurnIssued(strFail, txid, tokenID, nUnits, vchDest, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

UniValue FreezeRPC(const JSONRPCRequest& request, bool fFreeze)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            std::string(fFreeze ? "freezeissued" : "unfreezeissued") +
            " \"token_id\" [{\"txid\":\"hex\",\"vout\":n,\"frozen\":units},...] ( fee )\n"
            "\nSet the frozen units of coins of a token whose freeze key this wallet holds (freeze raises, unfreeze\n"
            "lowers). A freeze zeroes value for counting, never spendability.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    std::vector<COutPoint> vOut;
    std::vector<uint64_t> vFrozen;
    for (const UniValue& e : request.params[1].get_array().getValues()) {
        const int64_t n = find_value(e, "frozen").get_int64();
        if (n < 0 || n > MAX_MONEY)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "frozen out of range");
        vOut.push_back(COutPoint(ParseHashO(e, "txid"), find_value(e, "vout").get_int()));
        vFrozen.push_back((uint64_t)n);
    }
    const CAmount nFee = ParseFee(request, 2);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->FreezeIssued(strFail, txid, tokenID, vOut, vFrozen, fFreeze, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

UniValue freezeissued(const JSONRPCRequest& request) { return FreezeRPC(request, true); }
UniValue unfreezeissued(const JSONRPCRequest& request) { return FreezeRPC(request, false); }

UniValue listissued(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "listissued ( \"token_id\" )\n"
            "\nThe wallet's unspent issued-token coins (confirmed, or unconfirmed in the pool), with units and frozen units.\n");
    uint256 tokenID;
    if (request.params.size() > 0 && !request.params[0].isNull())
        tokenID = ParseTokenID(request.params[0]);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    std::vector<CIssuedWalletCoin> vCoins;
    pwallet->ListIssuedCoins(tokenID, vCoins);
    UniValue arr(UniValue::VARR);
    for (const CIssuedWalletCoin& c : vCoins) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("txid", c.outpoint.hash.GetHex());
        o.pushKV("vout", (uint64_t)c.outpoint.n);
        o.pushKV("token_id", c.tokenID.GetHex());
        o.pushKV("units", (uint64_t)c.nUnits);
        o.pushKV("frozen", (uint64_t)c.nFrozen);
        o.pushKV("confirmations", c.nDepth);
        CTxDestination dest;
        if (ExtractDestination(c.txout.scriptPubKey, dest))
            o.pushKV("address", EncodeDestination(dest));
        arr.push_back(o);
    }
    return arr;
}

UniValue getissuedtoken(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getissuedtoken \"token_id\"\n"
            "\nAn issued token's chain record: kind, keys, backing (declared, not checked), supply.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    LOCK(cs_main);
    CIssuedToken token;
    CUnitsView view(punitsdb.get());
    if (!view.Get(IssuedTokenKey(tokenID), token))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown token");
    return TokenToUniv(token);
}

UniValue gethousecapital(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "gethousecapital houseid\n"
            "\nA house's rate and capital as the chain counts them (Gold B, D-2026-11-07-1 and -3). FreeBank doesn't check\n"
            "what a house holds; it shows whether the house pays.\n"
            "\nResult: the rate in effect for the next block (bid, ask, sats per gram), its highest ask of the last 30 days\n"
            "(the floors, the ramp and bill repayment use it) and highest bid of the last 90 days (the waterfall's); the\n"
            "sECX escrow and the attested till (sECX the house showed it controls at a recent block; it can spend it\n"
            "afterwards), in sats and in mg at the 30-day ask; the issuing caps (capital_cap_mg on the ramp: each escrow\n"
            "tranche counts 1x, doubling per 180 clean days up to 10x; a protest restarts it; an issue is checked against both caps less\n"
            "pending_swaps_mg, the notes still owed by open swaps); rate_fresh (issuing needs a rate posted within 24 h of the chain clock;\n"
            "rate_posted_time and rate_fresh_until are on that clock, median-time based); and overdue_bills_seen, the bills in its\n"
            "book the chain sees as overdue. That count is never complete: a house can repay a bill for its borrower, so not\n"
            "every bad loan shows. A house closes only when it doesn't pay a demand (D-2026-11-07-3).\n");
    const uint32_t nHouseID = request.params[0].get_int();
    LOCK(cs_main);
    CHouse house;
    if (!phousetree->GetHouse(nHouseID, house))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown house");
    const int nNext = chainActive.Height() + 1;
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nNext);
    UniValue o(UniValue::VOBJ);
    uint64_t nBid = 0, nAsk = 0, nBid90 = 0, nAsk30 = 0, nUnused = 0;
    if (HouseRateForChecks(nHouseID, nNext, nBid, nAsk)) {
        o.pushKV("bid", nBid);
        o.pushKV("ask", nAsk);
    } else {
        o.pushKV("bid", NullUniValue);
        o.pushKV("ask", NullUniValue);
    }
    // Issuing needs a rate posted within nRateRefreshSecs (24 h) of the chain clock (monotone, median-time based).
    {
        CHouseRate rate;
        if (HouseRateRecordForChecks(nHouseID, rate)) {
            o.pushKV("rate_posted_height", (uint64_t)rate.nPostHeight);
            o.pushKV("rate_posted_time", rate.nPostTime);
            o.pushKV("rate_fresh_until", rate.nPostTime + (int64_t)gp.nRateRefreshSecs);
        }
        o.pushKV("rate_fresh", HouseRateFreshForChecks(nHouseID, (int64_t)gp.nRateRefreshSecs));
    }
    o.pushKV("ask_30d_high", HouseRateMaxForChecks(nHouseID, nNext, 30, nUnused, nAsk30) ? UniValue(nAsk30) : NullUniValue);
    o.pushKV("bid_90d_high", HouseRateMaxForChecks(nHouseID, nNext, 90, nBid90, nUnused) ? UniValue(nBid90) : NullUniValue);
    const CAmount amountTill = HouseAttestedTillSats(house, nNext);
    CHouseCapital cap;
    const bool fCap = HouseCapitalForChecks(house, nNext, amountTill, cap);
    o.pushKV("escrow_sats", (int64_t)house.ActiveEscrow());
    o.pushKV("escrow_mg", fCap ? UniValue(cap.nEscrowMg) : NullUniValue);
    o.pushKV("till_attested_sats", (int64_t)amountTill);
    o.pushKV("till_mg", fCap ? UniValue(cap.nTillMg) : NullUniValue);
    o.pushKV("notes_mg", (uint64_t)house.nMintedUnits);
    o.pushKV("deposits_mg", (uint64_t)house.nDepositUnits);
    // Notes still owed by open swaps (units 'W'): the issue checks take them off both caps (GOLD_B §4); the caps shown are gross.
    o.pushKV("pending_swaps_mg", HousePendingSwapUnitsForChecks(nHouseID));
    // The ramp (GOLD_B §5): each escrow tranche at 1x, doubling per 180 clean days, up to the 10% floor's 10x.
    o.pushKV("capital_cap_mg", fCap ? UniValue(cap.nCapacityMg) : NullUniValue);
    o.pushKV("capital_cap_at_full_ramp_mg", (uint64_t)((unsigned __int128)cap.nEscrowMg * 10000 / gp.nCapitalMinBps));
    o.pushKV("till_cap_mg", (uint64_t)((unsigned __int128)cap.nTillMg * 10000 / gp.nTillMinBps));
    o.pushKV("demand_interest_mg", HouseDemandInterestForChecks(house, nNext));
    // The bills the chain sees as overdue - never complete (a house can repay a bill for its borrower, D-2026-11-07-3).
    {
        const std::vector<uint32_t> vOverdue = HouseOverdueBills(house, nNext);   // judged on the chain clock
        o.pushKV("overdue_bills_seen", (uint64_t)vOverdue.size());
        UniValue ids(UniValue::VARR);
        for (uint32_t id : vOverdue)
            ids.push_back((uint64_t)id);
        o.pushKV("overdue_bill_ids", ids);   // never complete as a measure of loan quality (D-2026-11-07-3)
    }
    return o;
}


// ---- Gold B RPCs: rate, charter, swap ----

uint8_t ParseRelated(const UniValue& v)
{
    const std::string str = v.get_str();
    if (str == "undeclared") return HOUSE_RELATED_UNDECLARED;
    if (str == "no") return HOUSE_RELATED_NO;
    if (str == "yes") return HOUSE_RELATED_YES;
    throw JSONRPCError(RPC_INVALID_PARAMETER, "related must be \"yes\", \"no\" or \"undeclared\"");
}

const char* RelatedName(uint8_t n)
{
    return n == HOUSE_RELATED_YES ? "yes" : n == HOUSE_RELATED_NO ? "no" : "undeclared";
}

UniValue TxidResult(const uint256& txid)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("txid", txid.GetHex());
    return o;
}

UniValue posthouserate(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
            "posthouserate houseid bid ask ( fee )\n"
            "\nPost the house's binding rate in sats per gram (Gold B, D-2026-11-07-1), signed by its rate key, which this\n"
            "wallet must hold. It takes effect from the next block. The ask is at most 2% above the bid; the bid may rise\n"
            "at most 25% in 24 hours, and may fall any amount.\n");
    const uint32_t nHouseID = request.params[0].get_int();
    const int64_t nBid = request.params[1].get_int64(), nAsk = request.params[2].get_int64();
    if (nBid <= 0 || nAsk <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "bid and ask must be positive");
    const CAmount nFee = ParseFee(request, 3);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!WalletPostHouseRate(pwallet, strFail, txid, nHouseID, (uint64_t)nBid, (uint64_t)nAsk, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue sethouseratekey(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "sethouseratekey houseid ( \"pubkey\" fee )\n"
            "\nRegister the key that signs the house's rate postings, approved by the house's M-of-N partner keys in this\n"
            "wallet. Without a pubkey, a new key of this wallet is used.\n"
            "\nResult: {\"txid\", \"pubkey\"}\n");
    const uint32_t nHouseID = request.params[0].get_int();
    const CAmount nFee = ParseFee(request, 2);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    CPubKey pubKey;
    if (request.params.size() > 1 && !request.params[1].isNull() && !request.params[1].get_str().empty()) {
        const std::vector<unsigned char> v = ParseHex(request.params[1].get_str());
        pubKey = CPubKey(v.begin(), v.end());
        if (!pubKey.IsFullyValid())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid public key");
    } else if (!pwallet->GetKeyFromPool(pubKey)) {
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Keypool ran out");
    }
    uint256 txid;
    std::string strFail;
    if (!WalletSetHouseRateKey(pwallet, strFail, txid, nHouseID, pubKey, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    UniValue o = TxidResult(txid);
    o.pushKV("pubkey", HexStr(pubKey.begin(), pubKey.end()));
    return o;
}

UniValue addchartertoken(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 7 || request.params.size() > 8)
        throw std::runtime_error(
            "addchartertoken houseid chain_id \"contract\" decimals grams_num grams_den \"related\" ( fee )\n"
            "\nAdd a gold token (on an Ethereum chain) to the house's charter: the tokens it pays in kind on a swap demand\n"
            "(GOLD_B.md §2). One token = grams_num / grams_den grams. related: \"yes\", \"no\" or \"undeclared\", the\n"
            "partners' declaration whether the token's issuer is related to them. Approved by the M-of-N in this wallet.\n"
            "The chain checks nothing on Ethereum: the charter is the house's statement.\n");
    HouseCharter op;
    op.nHouseID = request.params[0].get_int();
    op.nKind = HOUSE_CHARTER_ADD;
    const int64_t nChain = request.params[1].get_int64();
    if (nChain <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must be positive");
    op.nChainID = (uint64_t)nChain;
    op.vchContract = ParseBytes20(request.params[2], "contract");
    const int nDecimals = request.params[3].get_int();
    if (nDecimals < 0 || nDecimals > 36)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "decimals 0-36");
    op.nDecimals = (uint8_t)nDecimals;
    const int64_t nNum = request.params[4].get_int64(), nDen = request.params[5].get_int64();
    if (nNum <= 0 || nDen <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "grams_num and grams_den must be positive");
    op.nGramsNum = (uint64_t)nNum;
    op.nGramsDen = (uint64_t)nDen;
    op.nRelated = ParseRelated(request.params[6]);
    const CAmount nFee = ParseFee(request, 7);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!WalletHouseCharter(pwallet, strFail, txid, op, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue removechartertoken(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "removechartertoken houseid index ( fee )\n"
            "\nRemove the charter entry at index (gethousecharter). It stops counting 30 days after this, so demands already\n"
            "named against it stand. The house's last entry can't be removed. Approved by the M-of-N in this wallet.\n");
    HouseCharter op;
    op.nHouseID = request.params[0].get_int();
    op.nKind = HOUSE_CHARTER_REMOVE;
    op.nIndex = request.params[1].get_int();
    const CAmount nFee = ParseFee(request, 2);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!WalletHouseCharter(pwallet, strFail, txid, op, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue setcharterrelated(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
            "setcharterrelated houseid index \"related\" ( fee )\n"
            "\nRestate the partners' related-issuer declaration (\"yes\", \"no\", \"undeclared\") for the charter entry at\n"
            "index. Approved by the M-of-N in this wallet.\n");
    HouseCharter op;
    op.nHouseID = request.params[0].get_int();
    op.nKind = HOUSE_CHARTER_RELATED;
    op.nIndex = request.params[1].get_int();
    op.nRelated = ParseRelated(request.params[2]);
    const CAmount nFee = ParseFee(request, 3);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!WalletHouseCharter(pwallet, strFail, txid, op, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue gethousecharter(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "gethousecharter houseid\n"
            "\nThe house's charter: the gold tokens it pays in kind, by index. remove_at is the time an entry stops counting\n"
            "(0 = not being removed). A statement by the house; the chain checks nothing on Ethereum.\n");
    const uint32_t nHouseID = request.params[0].get_int();
    LOCK(cs_main);
    CHouseCharter charter;
    UniValue arr(UniValue::VARR);
    if (HouseCharterForChecks(nHouseID, charter)) {
        for (size_t i = 0; i < charter.vToken.size(); i++) {
            const CCharterToken& t = charter.vToken[i];
            UniValue o(UniValue::VOBJ);
            o.pushKV("index", (uint64_t)i);
            o.pushKV("chain_id", t.nChainID);
            o.pushKV("contract", "0x" + HexStr(t.vchContract));
            o.pushKV("decimals", (int)t.nDecimals);
            o.pushKV("grams_num", t.nGramsNum);
            o.pushKV("grams_den", t.nGramsDen);
            o.pushKV("related", RelatedName(t.nRelated));
            o.pushKV("related_height", (uint64_t)t.nRelatedHeight);
            o.pushKV("added_time", t.nAddedTime);
            o.pushKV("remove_at", t.nRemoveAt);
            arr.push_back(o);
        }
    }
    return arr;
}

/** A hash lock as the plain hex of sha256(s), byte for byte - what an Ethereum HTLC and the app print. (ParseHashV would
 *  reverse it, txid-style, and no preimage would ever match.) */
uint256 ParseHashLock(const UniValue& v)
{
    std::string str = v.get_str();
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'))
        str = str.substr(2);
    if (str.size() != 64 || !IsHex(str))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_lock must be 32 bytes of hex (sha256 of the secret)");
    const std::vector<unsigned char> v32 = ParseHex(str);
    uint256 h;
    std::copy(v32.begin(), v32.end(), h.begin());
    if (h.IsNull())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "hash_lock is null");
    return h;
}

std::string HashLockHex(const uint256& h) { return HexStr(h.begin(), h.end()); }

UniValue swapnotes(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 7 || request.params.size() > 8)
        throw std::runtime_error(
            "swapnotes houseid units chain_id \"contract\" \"eth_address\" \"hash_lock\" \"payout_address\" ( fee )\n"
            "\nDemand units mg (at least 10 g) of the house's notes in a gold token on its charter (GOLD_B.md §4). The notes\n"
            "leave circulation. The house locks the tokens for eth_address under hash_lock = sha256(s); revealing s claims\n"
            "them and settles the swap (swapdone). Unsettled after 72 hours of chain time, the house owes it in sECX at the\n"
            "lower of its bid at the demand and its highest bid in the day before the deadline, paid to payout_address\n"
            "(swappay); unpaid a day later it can be\n"
            "protested (swapprotest). One holder's plain coins summing to exactly units are handed in.\n");
    const uint32_t nHouseID = request.params[0].get_int();
    const uint64_t nUnits = ParseUnits(request.params[1]);
    const int64_t nChain = request.params[2].get_int64();
    if (nChain <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "chain_id must be positive");
    const std::vector<unsigned char> vchContract = ParseBytes20(request.params[3], "contract");
    const std::vector<unsigned char> vchEth = ParseBytes20(request.params[4], "eth_address");
    const uint256 hashLock = ParseHashLock(request.params[5]);
    const CTxDestination dest = DecodeDestination(request.params[6].get_str());
    if (!IsValidDestination(dest))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid payout address");
    const CAmount nFee = ParseFee(request, 7);
    EnsureWalletIsUnlocked(pwallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->SwapNotesInKind(strFail, txid, nHouseID, nUnits, (uint64_t)nChain, vchContract, vchEth, hashLock,
                                  GetScriptForDestination(dest), nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue swapdone(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "swapdone \"hash_lock\" \"preimage\" ( fee )\n"
            "\nSettle a swap as delivered: post s (hex) with sha256(s) = hash_lock before its deadline. Anyone may; the house\n"
            "normally does, copying s from Ethereum once the holder has claimed the tokens. A holder who posts s before\n"
            "claiming the tokens gives up the notes: claim on Ethereum first.\n");
    const uint256 hashLock = ParseHashLock(request.params[0]);
    const std::vector<unsigned char> vchPre = ParseHex(request.params[1].get_str());
    const CAmount nFee = ParseFee(request, 2);
    EnsureWalletIsUnlocked(pwallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->SwapDone(strFail, txid, hashLock, vchPre, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue swappay(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "swappay \"hash_lock\" ( fee )\n"
            "\nPay a swap in sECX from this wallet to its payout address: before its deadline at the house's bid at the\n"
            "demand; after it at the lower of that and the house's highest bid in the day before the deadline (any shortfall\n"
            "is kept in grams). Anyone may; it is how the house settles a swap it doesn't deliver. Run from the holder's own\n"
            "wallet it pays the holder from the holder's coins and closes the swap: the house's wallet runs it.\n"
            "\nResult: {\"txid\", \"paid_sats\"}\n");
    const uint256 hashLock = ParseHashLock(request.params[0]);
    const CAmount nFee = ParseFee(request, 1);
    EnsureWalletIsUnlocked(pwallet);
    uint256 txid;
    std::string strFail;
    CAmount amountPaid = 0;
    if (!pwallet->SwapPay(strFail, txid, hashLock, nFee, amountPaid))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    UniValue o = TxidResult(txid);
    o.pushKV("paid_sats", amountPaid);
    return o;
}

UniValue swapprotest(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "swapprotest \"hash_lock\" ( fee )\n"
            "\nProtest a swap still unpaid a day after its deadline: an unpaid demand, which starts the house's 7-day cure\n"
            "(or, within 180 days of its last cure, fails it). Anyone may.\n");
    const uint256 hashLock = ParseHashLock(request.params[0]);
    const CAmount nFee = ParseFee(request, 1);
    EnsureWalletIsUnlocked(pwallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->SwapProtest(strFail, txid, hashLock, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue swapexpire(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "swapexpire \"hash_lock\" ( fee )\n"
            "\nAt or after a swap's deadline, fix its rate at the house's bid then. Optional: any later swap op fixes it.\n");
    const uint256 hashLock = ParseHashLock(request.params[0]);
    const CAmount nFee = ParseFee(request, 1);
    EnsureWalletIsUnlocked(pwallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->SwapExpire(strFail, txid, hashLock, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return TxidResult(txid);
}

UniValue swapclaim(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "swapclaim \"hash_lock\" ( fee )\n"
            "\nAt a failed house (after its bills are collected), claim a pending swap, or a shortfall the house paid within\n"
            "90 days before it failed, at the noteholders' rank: its exact pro-rata share of the escrow pot goes to the\n"
            "swap's payout address. Anyone may; this wallet pays the fee.\n"
            "\nResult: {\"txid\", \"paid_sats\"}\n");
    const uint256 hashLock = ParseHashLock(request.params[0]);
    const CAmount nFee = ParseFee(request, 1);
    EnsureWalletIsUnlocked(pwallet);
    uint256 txid;
    std::string strFail;
    CAmount amountPaid = 0;
    if (!pwallet->SwapClaimFromEscrow(strFail, txid, hashLock, nFee, amountPaid))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    UniValue o = TxidResult(txid);
    o.pushKV("paid_sats", amountPaid);
    return o;
}

UniValue getswap(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "getswap \"hash_lock\"\n"
            "\nA swap's record: house, units (mg), the token, the Ethereum address, the house's bid at the demand, the\n"
            "deadline (chain active time), status (pending, done, paid, protested), any shortfall in mg, and the bid at the\n"
            "deadline once fixed.\n");
    const uint256 hashLock = ParseHashLock(request.params[0]);
    LOCK(cs_main);
    CSwapRecord r;
    if (!SwapRecordForChecks(hashLock, r))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown swap");
    CChainClock clock;
    const bool fClock = ChainClockForChecks(clock);
    UniValue o(UniValue::VOBJ);
    o.pushKV("hash_lock", HashLockHex(hashLock));
    o.pushKV("houseid", (uint64_t)r.nHouseID);
    o.pushKV("units_mg", r.nUnits);
    o.pushKV("chain_id", r.nChainID);
    o.pushKV("contract", "0x" + HexStr(r.vchContract));
    o.pushKV("eth_address", "0x" + HexStr(r.vchEthAddress));
    o.pushKV("bid_at_demand", r.nBid0);
    o.pushKV("demand_height", (uint64_t)r.nDemandHeight);
    o.pushKV("deadline_active", r.nDeadlineActive);
    o.pushKV("active_now", fClock ? UniValue(clock.nActiveTime) : NullUniValue);
    o.pushKV("status", r.nStatus == SWAP_DONE ? "done" : r.nStatus == SWAP_PAID ? "paid" :
                       r.nStatus == SWAP_PROTESTED ? "protested" : r.nStatus == SWAP_CLAIMED ? "claimed" : "pending");
    o.pushKV("shortfall_mg", r.nShortfallMg);
    o.pushKV("settle_time", r.nSettleTime);
    o.pushKV("bid_at_deadline", r.nBidT ? UniValue(r.nBidT) : NullUniValue);
    return o;
}

UniValue createtokenpool(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "createtokenpool \"token_id\" units sats ( fee_bps fee )\n"
            HELP_ROLE_POOL
            "\nCreate the token/sECX pool of a dollar token (one per token) with this wallet's units and sats; the LP\n"
            "shares come back to the wallet. fee_bps 1-100, default 30. Burns the fixed creation fee (0.1 ECX). Dollar\n"
            "pools open at the later-rules time (getblockchaininfo dollar_pools_open).\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    const uint64_t nUnits = ParseUnits(request.params[1]);
    const CAmount nSats = request.params[2].get_int64();
    if (nSats <= 0 || nSats > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "sats out of range");
    const uint32_t nFeeBps = request.params.size() > 3 && !request.params[3].isNull() ? request.params[3].get_int() : 30;
    const CAmount nFee = ParseFee(request, 4);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->CreateTokenPool(strFail, txid, tokenID, nUnits, nSats, nFeeBps, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

UniValue addtokenliquidity(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
            "addtokenliquidity \"token_id\" units ( fee max_sats )\n"
            HELP_ROLE_POOL
            "\nAdd units, and the sats that match the pool's ratio, to a token pool; LP shares come back. max_sats\n"
            "(optional): refuse if the ratio, which follows the pool's pending transactions, asks more sats than this.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    const uint64_t nUnits = ParseUnits(request.params[1]);
    const CAmount nFee = ParseFee(request, 2);
    const CAmount nMaxSats = request.params.size() > 3 && !request.params[3].isNull() ? request.params[3].get_int64() : 0;
    if (nMaxSats < 0 || nMaxSats > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "max_sats out of range");
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->AddTokenLiquidity(strFail, txid, tokenID, nUnits, nFee, nMaxSats))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

UniValue removetokenliquidity(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "removetokenliquidity \"token_id\" lp_units ( fee )\n"
            "\nBurn LP shares for their part of a token pool's units and sats.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    const uint64_t nLp = ParseUnits(request.params[1]);
    const CAmount nFee = ParseFee(request, 2);
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->RemoveTokenLiquidity(strFail, txid, tokenID, nLp, nFee))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

UniValue swaptoken(const JSONRPCRequest& request)
{
    CWallet* const pwallet = WalletOrThrow(request);
    if (!pwallet)
        return NullUniValue;
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
            "swaptoken \"token_id\" \"sell|buy\" amount_in ( fee min_out )\n"
            "\nSwap through a token pool: sell token units for sats, or buy units with sats (amount_in in sats). min_out\n"
            "(optional): refuse if the pool, which follows its pending transactions, gives less than this.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    const std::string strDir = request.params[1].get_str();
    if (strDir != "sell" && strDir != "buy")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "direction must be sell or buy");
    const uint64_t nIn = ParseUnits(request.params[2]);
    const CAmount nFee = ParseFee(request, 3);
    const int64_t nMinOutRaw = request.params.size() > 4 && !request.params[4].isNull() ? request.params[4].get_int64() : 0;
    if (nMinOutRaw < 0 || nMinOutRaw > MAX_MONEY)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "min_out out of range");
    const uint64_t nMinOut = (uint64_t)nMinOutRaw;   // 0 = no bound
    EnsureWalletIsUnlocked(pwallet);
    pwallet->BlockUntilSyncedToCurrentChain();
    LOCK2(cs_main, pwallet->cs_wallet);
    uint256 txid;
    std::string strFail;
    if (!pwallet->SwapToken(strFail, txid, tokenID, strDir == "sell", nIn, nFee, nMinOut))
        throw JSONRPCError(RPC_WALLET_ERROR, strFail);
    return txid.GetHex();
}

/** One token pool as JSON (gettokenpool, listtokenpools). cs_main held. */
static UniValue TokenPoolToJSON(const CUnitsView& view, const uint256& tokenID, const CTokenPool& pool, int nTip,
                                const Consensus::GramParams& gp)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("token_id", tokenID.GetHex());
    CIssuedToken token;
    if (view.Get(IssuedTokenKey(tokenID), token))
        o.pushKV("ticker", token.strTicker);
    o.pushKV("lp_token_id", LpTokenID(tokenID).GetHex());
    o.pushKV("fee_bps", (uint64_t)pool.nFeeBps);
    o.pushKV("units", (uint64_t)pool.nUnits);
    o.pushKV("sats", (int64_t)pool.nSats);
    o.pushKV("lp_supply", (uint64_t)pool.nLpSupply);
    o.pushKV("create_height", pool.nCreateHeight);
    o.pushKV("custody_txid", pool.outSats.hash.GetHex());   // vout 0 = token side, vout 1 = sats side
    // Spot price from the reserves (sats per token unit x 1000): a market, never a price the chain uses (Gold B).
    if (pool.nUnits > 0)
        o.pushKV("spot_sats_per_1000_units", (int64_t)((unsigned __int128)pool.nSats * 1000 / pool.nUnits));
    return o;
}

UniValue gettokenpool(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "gettokenpool \"token_id\"\n"
            "\nA token pool (confirmed): reserves, LP supply, fee and spot price. A market; the chain uses no pool price.\n");
    const uint256 tokenID = ParseTokenID(request.params[0]);
    LOCK(cs_main);
    CUnitsView view(punitsdb.get());
    CTokenPool pool;
    if (!view.Get(TokenPoolKey(tokenID), pool))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "The token has no pool");
    const int nTip = chainActive.Height();
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nTip);
    return TokenPoolToJSON(view, tokenID, pool, nTip, gp);
}

UniValue listtokenpools(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "listtokenpools\n"
            "\nEvery token pool (confirmed), in token-id order, with the fields of gettokenpool.\n"
            "\nResult: {\"pools\": [ {token_id, ticker, lp_token_id, fee_bps, units, sats, lp_supply, create_height,\n"
            "custody_txid, spot_sats_per_1000_units}, ... ]}\n");
    LOCK(cs_main);
    CUnitsView view(punitsdb.get());
    const int nTip = chainActive.Height();
    const Consensus::GramParams& gp = Params().GetConsensus().GramAt(nTip);
    UniValue arr(UniValue::VARR);
    const UnitsKey prefix(UNITS_TOKEN_POOL);
    for (const std::pair<UnitsKey, UnitsValue>& kv : view.Scan(prefix, prefix, std::numeric_limits<size_t>::max())) {
        CTokenPool pool;
        try {
            CDataStream ss(kv.second, SER_DISK, CLIENT_VERSION);
            ss >> pool;
        } catch (const std::exception&) {
            continue;
        }
        arr.push_back(TokenPoolToJSON(view, pool.tokenID, pool, nTip, gp));
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("pools", arr);
    return o;
}

const CRPCCommand issuedCommands[] = {
    //  category              name                      actor (function)         argNames
    { "token",            "createissuedtoken",      &createissuedtoken,      {"kind", "ticker", "backing_contract", "backing_address", "upstream", "freeze_key", "fee"} },
    { "token",            "mintissued",             &mintissued,             {"token_id", "units", "address", "fee"} },
    { "token",            "sendissued",             &sendissued,             {"token_id", "units", "address", "fee"} },
    { "token",            "burnissued",             &burnissued,             {"token_id", "units", "eth_address", "fee"} },
    { "token",            "freezeissued",           &freezeissued,           {"token_id", "coins", "fee"} },
    { "token",            "unfreezeissued",         &unfreezeissued,         {"token_id", "coins", "fee"} },
    { "token",            "listissued",             &listissued,             {"token_id"} },
    { "token",            "createtokenpool",        &createtokenpool,        {"token_id", "units", "sats", "fee_bps", "fee"} },
    { "token",            "addtokenliquidity",      &addtokenliquidity,      {"token_id", "units", "fee", "max_sats"} },
    { "token",            "removetokenliquidity",   &removetokenliquidity,   {"token_id", "lp_units", "fee"} },
    { "token",            "swaptoken",              &swaptoken,              {"token_id", "direction", "amount_in", "fee", "min_out"} },
    { "house",            "posthouserate",          &posthouserate,          {"houseid", "bid", "ask", "fee"} },
    { "house",            "sethouseratekey",        &sethouseratekey,        {"houseid", "pubkey", "fee"} },
    { "house",            "addchartertoken",        &addchartertoken,        {"houseid", "chain_id", "contract", "decimals", "grams_num", "grams_den", "related", "fee"} },
    { "house",            "removechartertoken",     &removechartertoken,     {"houseid", "index", "fee"} },
    { "house",            "setcharterrelated",      &setcharterrelated,      {"houseid", "index", "related", "fee"} },
    { "notes",            "swapnotes",              &swapnotes,              {"houseid", "units", "chain_id", "contract", "eth_address", "hash_lock", "payout_address", "fee"} },
    { "notes",            "swapdone",               &swapdone,               {"hash_lock", "preimage", "fee"} },
    { "notes",            "swappay",                &swappay,                {"hash_lock", "fee"} },
    { "notes",            "swapprotest",            &swapprotest,            {"hash_lock", "fee"} },
    { "notes",            "swapexpire",             &swapexpire,             {"hash_lock", "fee"} },
    { "notes",            "swapclaim",              &swapclaim,              {"hash_lock", "fee"} },
};

// v1.1.1: the read-only ones never touch a wallet, so they are registered with the node's commands, also under
// -disablewallet (a seed or an explorer's node runs without one; v1.1.0 answered them "Method not found" there).
const CRPCCommand issuedNodeCommands[] = {
    //  category              name                      actor (function)         argNames
    { "token",            "getissuedtoken",         &getissuedtoken,         {"token_id"} },
    { "token",            "gethousecapital",        &gethousecapital,        {"houseid"} },
    { "house",            "gethousecharter",        &gethousecharter,        {"houseid"} },
    { "notes",            "getswap",                &getswap,                {"hash_lock"} },
    { "token",            "gettokenpool",           &gettokenpool,           {"token_id"} },
    { "token",            "listtokenpools",         &listtokenpools,         {} },
};

} // namespace

void RegisterIssuedRPCCommands(CRPCTable& t)
{
    for (const CRPCCommand& c : issuedCommands)
        t.appendCommand(c.name, &c);
}

void RegisterIssuedNodeRPCCommands(CRPCTable& t)
{
    for (const CRPCCommand& c : issuedNodeCommands)
        t.appendCommand(c.name, &c);
}

// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ISSUED_H
#define BITCOIN_ISSUED_H

// Issued tokens (tx v18), gram-notes release (docs-local/GOLD_USD_SCOPE.md call 1, step 2; design draft 9 "Tokens and
// backing"; D-2026-10-31-2). A gold token (milligrams) or a dollar token (cents) minted and burned by its issuer and
// backed by a balance on Ethereum. "Issued" because the v0.2.20 token records (token.h) already use "token".
//  - Units sit on the coin (Coin::nIssuedUnits on a dust output), like notes; not v10 assets, whose supply is fixed and
//    which lock one sat per unit.
//  - Which outputs of a transaction carry which token's units is stated once, in the transaction's issued-units annex
//    (CTransaction::vIssuedOut, versions 11-18), checked against the inputs by one rule (CheckIssuedFlow) and bound by
//    every input signature (CreditBindingHash). Op transactions (house, note, deposit, pool) carry tokens through the
//    same annex, so no op needs its own colour rule.
//  - Frozen units are chain state (units DB, by outpoint), not a coin field: a freeze doesn't spend the coin it
//    freezes. A transaction spending frozen units states where they go (CIssuedOut::nFrozen); they stay frozen.

#include <amount.h>
#include <primitives/transaction.h>   // CIssuedOut, TRANSACTION_TOKEN_VERSION
#include <serialize.h>
#include <uint256.h>

#include <algorithm>
#include <functional>
#include <tuple>
#include <map>
#include <string>
#include <vector>

class CTransaction;
class Coin;

static const uint8_t ISSUED_OP_CREATE = 1;     // a new token: kind, keys, backing contract and address
static const uint8_t ISSUED_OP_MINT = 2;       // the issuer adds units
static const uint8_t ISSUED_OP_BURN = 3;       // a holder burns units, naming where on Ethereum to be paid
static const uint8_t ISSUED_OP_TRANSFER = 4;   // units move; nothing else
static const uint8_t ISSUED_OP_FREEZE = 5;     // the freeze key zeroes the value of some coins (never spendability)
static const uint8_t ISSUED_OP_UNFREEZE = 6;
static const uint8_t ISSUED_OP_BOND = 7;       // the issuer locks or tops up its sECX bond
static const uint8_t ISSUED_OP_UNBOND = 8;     // the issuer takes its bond back, after a delay
// Token pools (step 4): a token/sECX constant-product pool per gold token, owned by no house.
static const uint8_t ISSUED_OP_POOL_CREATE = 9;
static const uint8_t ISSUED_OP_POOL_ADD = 10;
static const uint8_t ISSUED_OP_POOL_REMOVE = 11;
static const uint8_t ISSUED_OP_POOL_SWAP = 12;

static const uint8_t ISSUED_KIND_GOLD_MG = 1;      // one unit = one milligram of gold
static const uint8_t ISSUED_KIND_USD_CENTS = 2;    // one unit = one US cent
static const uint8_t ISSUED_KIND_POOL_LP = 3;      // a token pool's LP shares (never created by CREATE)

/** Most outputs one annex may name (also bounds the per-token sums). */
static const size_t MAX_ISSUED_OUTS = 64;
/** Most distinct tokens one transaction may move (a closing house pays out each token it holds). */
static const size_t MAX_ISSUED_TOKENS_PER_TX = 8;
/** Most outpoints one FREEZE / UNFREEZE names. */
static const size_t MAX_ISSUED_FREEZE_OUTPOINTS = 64;
static const size_t MAX_ISSUED_PAYLOAD = 4096;
static const size_t ISSUED_TICKER_MAX = 12;
static const size_t ISSUED_UPSTREAM_MAX = 32;
/** The dust value an issued-token output carries (policy; consensus only needs nValue > 0 off OP_RETURN). */
static const CAmount ISSUED_COIN_VALUE = 1000;

/** CREATE: a new token. Its id is this transaction's txid. The issuer key signs MINT, the freeze key (optional, declared
 *  here or never; legal condition 10) signs FREEZE / UNFREEZE. The backing contract is the Ethereum token held as
 *  backing, the backing address the Ethereum account holding it; the upstream id names the company behind the
 *  contract, so the half limit can apply per company (R2-ops-8, R2-sys-2). */
struct IssuedCreate
{
    uint8_t nKind = 0;
    std::string strTicker;
    std::vector<unsigned char> vchIssuerKey;        // 33-byte compressed key
    std::vector<unsigned char> vchFreezeKey;        // empty, or a 33-byte compressed key
    std::vector<unsigned char> vchBackingContract;  // 20 bytes
    std::vector<unsigned char> vchBackingAddress;   // 20 bytes
    std::string strUpstream;
    uint32_t nIssuerHouseID = 0;                    // 0: no house issues it (the house link comes with the house machine)
    std::vector<unsigned char> vchIssuerSig;        // the issuer key over IssuedSigHash

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nKind);
        READWRITE(LIMITED_STRING(strTicker, ISSUED_TICKER_MAX));
        READWRITE(vchIssuerKey);
        READWRITE(vchFreezeKey);
        READWRITE(vchBackingContract);
        READWRITE(vchBackingAddress);
        READWRITE(LIMITED_STRING(strUpstream, ISSUED_UPSTREAM_MAX));
        READWRITE(nIssuerHouseID);
        READWRITE(vchIssuerSig);
    }
};

/** MINT: nUnits new units of tokenID, placed by the annex. */
struct IssuedMint
{
    uint256 tokenID;
    uint64_t nUnits = 0;
    std::vector<unsigned char> vchIssuerSig;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(nUnits);
        READWRITE(vchIssuerSig);
    }
};

/** BURN: the holder (whose inputs' signatures authorise it) burns nUnits of tokenID and asks to be paid on Ethereum
 *  at vchEthDest. The burn joins the token's queue; an issuer that leaves burns unpaid loses its count (R2-ops-7). */
struct IssuedBurn
{
    uint256 tokenID;
    uint64_t nUnits = 0;
    std::vector<unsigned char> vchEthDest;   // 20 bytes

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(nUnits);
        READWRITE(vchEthDest);
    }
};

/** FREEZE / UNFREEZE: the freeze key sets the frozen units of each named coin of tokenID (FREEZE may only raise them,
 *  UNFREEZE only lower them). A freeze zeroes value for counting, never spendability (R2-int-4). */
/** A FREEZE / UNFREEZE target in a house's vaults (5b): the new frozen units of the token across the house's capital and
 *  till. Frozen vault gold stays in the vault (no payout or move may take it) until unfrozen, or until CLOSE carries it,
 *  still frozen, into the fund; it counts zero once the grace has run (CVaultFrozen). */
struct CVaultFreezeTarget
{
    uint32_t nHouseID = 0;
    uint64_t nFrozen = 0;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nHouseID);
        READWRITE(nFrozen);
    }
};

struct IssuedFreeze
{
    uint256 tokenID;
    std::vector<COutPoint> vOutpoint;
    std::vector<uint64_t> vFrozen;           // the new frozen units, parallel to vOutpoint
    std::vector<unsigned char> vchFreezeSig;
    std::vector<CVaultFreezeTarget> vVault;  // 5b: house vaults (after the signature: the sighash clears only the sig)

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(vOutpoint);
        READWRITE(vFrozen);
        READWRITE(vchFreezeSig);
        READWRITE(vVault);
    }
};

/** A house's frozen units of one token (units DB 'G'), and its grace clock (decisions log 4): the freeze counts zero
 *  from nGraceStart + nFreezeGraceBlocks; nGraceStart moves only when a freeze starts after nFreezeClearBlocks with
 *  nothing frozen (nClearSince = when it last went to zero; 0 = frozen now, or never frozen). */
struct CVaultFrozen
{
    uint64_t nFrozen = 0;
    uint32_t nGraceStart = 0;
    uint32_t nClearSince = 0;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nFrozen);
        READWRITE(nGraceStart);
        READWRITE(nClearSince);
    }
};

/** BOND: lock or top up the issuer's sECX bond at vout[0] (IssuedBondScript), consolidating the bond coin it already
 *  has. UNBOND: fWithdraw 0 asks to unbond (the bond stops counting at once); 1, at least nIssuerUnbondDelay blocks
 *  later, spends the bond coin back to the issuer. The issuer key signs both. A token counts in houses' capital and
 *  tills only up to k x its bond in grams, chain-wide (design draft 9 "Issuer bonds", R3-2, D-2026-11-01-5). */
struct IssuedBond
{
    uint256 tokenID;
    std::vector<unsigned char> vchIssuerSig;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(vchIssuerSig);
    }
};

struct IssuedUnbond
{
    uint256 tokenID;
    uint8_t fWithdraw = 0;
    std::vector<unsigned char> vchIssuerSig;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(fWithdraw);
        READWRITE(vchIssuerSig);
    }
};

/** Blocks between an unbond request and the withdrawal (about 30 days). */
static const uint32_t ISSUED_UNBOND_DELAY = 4320;
/** Blocks an issuer has to top up a bond whose gram value fell below its value when locked (about 30 days). */
static const uint32_t ISSUED_BOND_TOPUP_BLOCKS = 4320;
/** The k ladder (D-2026-11-01-5): k doubles every this many blocks of clean reports (about 180 days) up to
 *  ISSUED_K_MAX, while the token's pool is deep; any shortfall, stale report or shallow pool sets it back to 1. */
static const uint32_t ISSUED_K_STEP_BLOCKS = 25920;
static const uint32_t ISSUED_K_MAX = 8;

/** Token pools (step 4; GOLD_USD_SCOPE.md call 3; D-2026-11-01-6 items 1 and 4). The pool's reserves ARE its two
 *  custody coins at TokenPoolScript: vout[0] carries the token units (annex), vout[1] the sats. Every pool op spends
 *  the current pair at vin[0] / vin[1] and re-creates it at vout[0] / vout[1], so a swap is checked from the coins it
 *  spends and swaps chain within a block (7a). Amounts out are exact (the inputs fix the reserves). */
struct IssuedPoolCreate
{
    uint256 tokenID;
    uint32_t nFeeBps = 0;
    uint64_t nInitUnits = 0;
    int64_t nInitSats = 0;
    uint64_t nLpOut = 0;       // the creator's LP shares: floor(sqrt(units * sats)) - POOL_MIN_LIQUIDITY, at vout[2]

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(nFeeBps);
        READWRITE(nInitUnits);
        READWRITE(nInitSats);
        READWRITE(nLpOut);
    }
};

struct IssuedPoolAdd
{
    uint256 tokenID;
    uint64_t nPriorLpSupply = 0;   // checked against the pool record at connect
    uint64_t nAddUnits = 0;
    int64_t nAddSats = 0;
    uint64_t nLpMinted = 0;        // at vout[2]

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(nPriorLpSupply);
        READWRITE(nAddUnits);
        READWRITE(nAddSats);
        READWRITE(nLpMinted);
    }
};

struct IssuedPoolRemove
{
    uint256 tokenID;
    uint64_t nPriorLpSupply = 0;
    uint64_t nBurnLp = 0;
    uint64_t nUnitsOut = 0;
    int64_t nSatsOut = 0;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(nPriorLpSupply);
        READWRITE(nBurnLp);
        READWRITE(nUnitsOut);
        READWRITE(nSatsOut);
    }
};

struct IssuedPoolSwap
{
    uint256 tokenID;
    uint8_t fSellTokens = 0;   // 1: token units in, sats out; 0: sats in, token units out
    uint64_t nAmountIn = 0;
    uint64_t nAmountOut = 0;   // == PoolSwapOut on the reserves the inputs carry

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(fSellTokens);
        READWRITE(nAmountIn);
        READWRITE(nAmountOut);
    }
};

/** The pool record (units DB, UNITS_TOKEN_POOL + token id): what the custody pair holds, and the LP supply. */
struct CTokenPool
{
    uint256 tokenID;
    uint32_t nFeeBps = 0;
    uint64_t nLpSupply = 0;        // including the locked POOL_MIN_LIQUIDITY
    uint64_t nUnits = 0;           // = the token custody coin's units
    int64_t nSats = 0;             // = the sats custody coin's value
    COutPoint outToken;
    COutPoint outSats;
    int32_t nCreateHeight = 0;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(nFeeBps);
        READWRITE(nLpSupply);
        READWRITE(nUnits);
        READWRITE(nSats);
        READWRITE(outToken);
        READWRITE(outSats);
        READWRITE(nCreateHeight);
    }
};

/** One block's sample of a pool (UNITS_POOL_SAMPLE + token + height), for its 144-block averages. */
struct CPoolSample
{
    uint64_t nSatsPerGram = 0;
    uint64_t nUnits = 0;
    // Review round 1 (G1c): fixed when the sample is taken, so the price at a height never changes later.
    uint64_t nSupply = 0;     // the token's supply then (depth is judged against it)
    uint8_t fCounts = 0;      // the token was trusted (CIssuedToken::fTrusted) and held in houses' vaults then

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nSatsPerGram);
        READWRITE(nUnits);
        READWRITE(nSupply);
        READWRITE(fCounts);
    }
};

/** The token's chain record (units DB, key UNITS_ISSUED_TOKEN + id). */
struct CIssuedToken
{
    uint256 tokenID;
    uint8_t nKind = 0;
    std::string strTicker;
    std::vector<unsigned char> vchIssuerKey;
    std::vector<unsigned char> vchFreezeKey;
    std::vector<unsigned char> vchBackingContract;
    std::vector<unsigned char> vchBackingAddress;
    std::string strUpstream;
    uint32_t nIssuerHouseID = 0;
    int32_t nCreateHeight = 0;
    uint64_t nSupply = 0;          // units minted less units burned
    uint64_t nBurnSeq = 0;         // burns queued so far (the next burn's sequence number)
    // The issuer bond (step 3b).
    COutPoint bondOutpoint;        // null: no bond
    int64_t nBondSats = 0;
    uint64_t nBondMgAtLock = 0;    // the bond's value in milligrams of gold when last locked or topped up
    int32_t nBondTopUpDeadline = 0;  // 0: none; set when the bond's gram value falls below nBondMgAtLock
    int32_t nUnbondRequestHeight = 0;
    // The k ladder (dormant until the token's pool is deep).
    uint32_t nK = 1;
    int32_t nKSince = 0;           // the height k last changed, or the clean run began
    uint8_t fKClean = 0;           // was the last block clean (deep pool, fresh full backing, no shortfall)?
    uint8_t fBackingOk = 0;        // at the last block's end: trusted (below) and a payout price exists (issuing
                                   //   against the token counts it only while this holds; D-2026-11-01-6 item 3)
    // Review round 1 (G1): trusted as gold at the last block's end - gold kind, bonded and not unbonding, no bond
    // shortfall past its deadline, a fresh backing report covering its supply. Only a trusted token enters a vault or
    // counts for the pool price; a token that stops being trusted still counts in equity and claims for a grace.
    uint8_t fTrusted = 0;
    int32_t nUntrustedSince = 0;   // the height it stopped being trusted (0: trusted now, or never was)

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(nKind);
        READWRITE(LIMITED_STRING(strTicker, ISSUED_TICKER_MAX));
        READWRITE(vchIssuerKey);
        READWRITE(vchFreezeKey);
        READWRITE(vchBackingContract);
        READWRITE(vchBackingAddress);
        READWRITE(LIMITED_STRING(strUpstream, ISSUED_UPSTREAM_MAX));
        READWRITE(nIssuerHouseID);
        READWRITE(nCreateHeight);
        READWRITE(nSupply);
        READWRITE(nBurnSeq);
        READWRITE(bondOutpoint);
        READWRITE(nBondSats);
        READWRITE(nBondMgAtLock);
        READWRITE(nBondTopUpDeadline);
        READWRITE(nUnbondRequestHeight);
        READWRITE(nK);
        READWRITE(nKSince);
        READWRITE(fKClean);
        READWRITE(fBackingOk);
        READWRITE(fTrusted);
        READWRITE(nUntrustedSince);
    }
};

/** Does a vault's unit of this token still count as a milligram of gold at nHeight (equity, the insolvency snapshot,
 *  claims)? Trusted now, or it stopped being trusted less than nGrace blocks ago (the design's 30-day grace for a
 *  backing fall). */
inline bool IssuedTokenValuedAt(const CIssuedToken& t, int nHeight, uint32_t nGrace)
{
    return t.nKind == ISSUED_KIND_GOLD_MG &&
           (t.fTrusted || (t.nUntrustedSince != 0 && (int64_t)nHeight < (int64_t)t.nUntrustedSince + (int64_t)nGrace));
}

class CScript;
/** The issuer bond escrow: <"FBIB" + token id> OP_DROP OP_TRUE. The 36-byte push sets it apart from the house escrow
 *  (32) and the oracle bond (33) forms; the coin is tagged fOracleBond (the bond-escrow tag) and only the token's own
 *  BOND / UNBOND may spend it (tx_verify). */
CScript IssuedBondScript(const uint256& tokenID);
bool IsIssuedBondScript(const CScript& script, uint256* pTokenID = nullptr);

/** A token pool's custody script: <"FBTP" + token id> OP_DROP OP_TRUE, tagged as escrow like the bonds. */
CScript TokenPoolScript(const uint256& tokenID);
/** D-2026-11-04-1 (3b): the unspendable output a token or pool creation burns its fee to (OP_RETURN "FBCF"). */
CScript CreationBurnScript();
/** D-2026-11-04-1 (3d, review 11-04): the smallest BURN: 1,000 units (a gram of a gold token, ten dollars of a dollar one). */
static const uint64_t ISSUED_BURN_MIN_UNITS = 1000;
class CUnitsView;
namespace Consensus { struct GramParams; }
/** D-2026-11-04-1 (3d, R2-ops-7): have the token's burns older than nBurnPayBlocks gone unpaid by more than the
 *  materiality threshold (max(nBurnUnpaidMinMg, nBurnUnpaidBps of its supply))? nPaidUnits is the backing fix's aux2:
 *  the units of the token's burns the reporters see paid out on Ethereum, in total. A threshold, not "any burn": a
 *  burn of a few mg to an address the issuer can't pay (the zero address, a blacklisted one) must not make every
 *  house that holds the token insolvent (review 11-04). */
bool IssuedBurnOverdue(const CUnitsView& units, const CIssuedToken& token, uint64_t nPaidUnits, int nHeight,
                       const Consensus::GramParams& gp);
/** The sats a creation must burn at a payout price of nSatsPerGram: nCreateFeeMg of gold, rounded up. */
CAmount CreationBurnSats(uint64_t nSatsPerGram, uint64_t nCreateFeeMg);
bool IsTokenPoolScript(const CScript& script, uint256* pTokenID = nullptr);
/** The pool's LP-share token id: SHA256d("FreeBank token pool LP" || token id). */
uint256 LpTokenID(const uint256& tokenID);
/** Is this a pool op (ISSUED_OP_POOL_*)? */
inline bool IsIssuedPoolOp(uint8_t nOp) { return nOp >= ISSUED_OP_POOL_CREATE && nOp <= ISSUED_OP_POOL_SWAP; }
/** The token a pool op names, from its payload (null if it doesn't decode). */
uint256 IssuedPoolOpToken(const CTransaction& tx);

/** One queued burn (units DB, key UNITS_ISSUED_BURN + token + sequence). */
struct CIssuedBurn
{
    uint64_t nUnits = 0;
    std::vector<unsigned char> vchEthDest;
    int32_t nHeight = 0;
    uint256 txid;
    uint64_t nCumUnits = 0;   // D-2026-11-04-1 (3d): this burn's units plus every earlier burn's of the token

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nUnits);
        READWRITE(vchEthDest);
        READWRITE(nHeight);
        READWRITE(txid);
        READWRITE(nCumUnits);
    }
};

template <typename T>
bool DecodeIssuedPayload(const std::vector<unsigned char>& vch, T& payload);

/** The digest a token key signs for a v18 op: the op, the payload with its signature emptied, the transaction's
 *  prevouts (so a signature can't be replayed in another transaction), its outputs and its annex. */
uint256 IssuedSigHash(const CTransaction& tx);

/** The units and frozen units a transaction's annex places, per token. False on a units overflow. */
bool IssuedSumAnnex(const CTransaction& tx, std::map<uint256, uint64_t>& mapUnits, std::map<uint256, uint64_t>& mapFrozen);

/** The annex entry for output n, or null. */
const CIssuedOut* FindIssuedOut(const CTransaction& tx, uint32_t n);
/** Review round 1 (G6): what a payload signature over "the outputs" binds on a credit transaction - the outputs
 *  (BillHashOutputs) AND the annex and vault moves, so a relayer can't move or drop the gold when no input is
 *  script-signed. Used by note CLAIM, deposit CLAIM and RECLAIM. */
uint256 CreditHashOutputs(const CTransaction& tx);
/** Review round 1b: a script gold can't be paid to - unspendable, or another family's tagged script (house / bill / pool
 *  escrow, issuer or oracle bond, pre-auth custody, a token pool's custody). Annex outputs, pre-auth demands' and token
 *  claims' payout scripts are all refused on these. */
bool IsGoldUnpayableScript(const CScript& script);

/** AddCoins / the mempool view: tag output n from the annex (payload-pure, so connect == rollforward == mempool). */
void ApplyIssuedCoinTags(const CTransaction& tx, uint32_t n, Coin& coin);

/** Context-free (CheckTransaction): the annex's shape (sorted, in range, units > 0, frozen <= units, at most
 *  MAX_ISSUED_TOKENS_PER_TX tokens, no OP_RETURN output), which transactions may carry one, and the shape of a v18
 *  payload. False with strReason set otherwise. */
bool CheckIssuedShape(const CTransaction& tx, std::string& strReason);

/** CheckTxInputs: issued units are conserved per token (a MINT adds, a BURN removes); issued inputs only in a
 *  transaction that may carry an annex; an annex token not among the inputs only as a MINT's. vSpent[i] is the coin
 *  vin[i] spends. */
bool CheckIssuedFlow(const CTransaction& tx, const std::vector<const Coin*>& vSpent, std::string& strReason);

class CCoinsViewCache;
class CUnitsView;
class CValidationState;
namespace Consensus { struct GramParams; }

/** Against and into the units state (ConnectBlock; the mempool on a throwaway view): the frozen units a transaction
 *  spends go where its annex says (a later FREEZE is read from the units DB); a v18 op's keys, token and effects. The
 *  inputs must still be unspent in `view`. */
struct CHouse;
bool ConnectIssuedTx(const CTransaction& tx, const CCoinsViewCache& view, CUnitsView& units, int nHeight,
                     CValidationState& state, const std::function<bool(uint32_t, CHouse&)>* pfnGetHouse = nullptr);

/** End of a block (after the price feed's): each bonded token's top-up deadline (set when the bond's gram value at the
 *  payout view falls below its value when locked, cleared when it recovers) and the k ladder (D-2026-11-01-5: clean =
 *  deep pool, fresh backing that covers the supply, no lapsed top-up, no unbond request; a dirty block sets k back to
 *  1; a clean run doubles it every ISSUED_K_STEP_BLOCKS to ISSUED_K_MAX). Writes a record only when it changes. */
/** The gold vaults' balances (ConnectIssuedTx applies the moves; a vault never goes below zero and holds gold tokens
 *  only). CheckHouseVaultMoves, in the house section with the house as the block sees it, checks each move against the
 *  op: TOPUP = the topping-up partner's capital, in, bringing the partner to HOUSE_MIN_GOLD_PLEDGE_MG; RECLAIM = the
 *  reclaimed partner's whole capital, out; TILL = the till, in or out (out only while the house is open or stressed). */
class CHouse;
bool CheckHouseVaultMoves(const CTransaction& tx, const CHouse& house, int nHeight, const CUnitsView& units,
                          CValidationState& state);

/** A house's gold, counted (design draft 9 "Houses: capital, till, issuing" and "Tokens and backing"; GOLD_USD_SCOPE.md
 *  step 5): per token, the vault units times the backing ratio (zero when the backing report is stale or below the
 *  supply, for issuing), within the token's bond cap shared pro rata across every house's vaults (k x the bond in
 *  grams); then no backing contract, upstream company or token above half of the house's counted gold (the excess
 *  doesn't count). Capital counts active partners only. fEquity: count for the equity test (frozen and stale-backed
 *  gold still count) instead of for issuing. */
struct CGoldCount {
    uint64_t nCapitalMg = 0;
    uint64_t nTillMg = 0;
    uint64_t nCapitalRawMg = 0;   // every partner's vault units, uncounted (the claims pot)
    uint64_t nTillRawMg = 0;
};
void HouseGoldCounted(const CUnitsView& units, const CHouse& house, int nHeight, const Consensus::GramParams& gp,
                      bool fEquity, CGoldCount& count, bool fNoPriceGate = false);

/** The units view the issuing checks count gold against: ConnectBlock's (the block so far) or the mempool's, set for
 *  the scope's life; outside any scope, the units DB at the tip. */
class UnitsCheckScope
{
public:
    UnitsCheckScope(const CUnitsView* pView);
    ~UnitsCheckScope();
private:
    const CUnitsView* pPrev;
};
/** Par-eligible for settlement (gram-notes release): effectively Open, and its counted gold till at least nTillMinBps of
 *  its notes (replaces HouseParEligible's attested ratio and recency, which the exact gold till makes moot). */
bool GoldParEligible(const CHouse& house, int nHeight);
/** v1.1.0 (D-2026-11-05-1): the redemption spread, basis points. Zero at an Open house (par while it pays) and at a house
 *  with no notes. Otherwise (Stressed, Deferred) the brassage curve (BrassageBpsAt) on the counted gold till / notes
 *  (both mg) against the till floor (nTillMinBps, 2%): par at or above the floor, rising to the full 4% at a quarter of
 *  it. Counted against the scope's view, as every issuing check. A REDEEM that binds a price pays it in sECX into the
 *  escrow pot; one that binds none keeps it in kind (validation.cpp: the gold it draws from the vaults is capped at the
 *  notes plus interest less the spread), so redemption never stops and the runner bears it either way. */
uint32_t GoldBrassageBps(const CHouse& house, int nHeight);
/** The counted gold till / notes ratio, basis points, capped at 10000 (10000 with no notes). */
uint32_t GoldTillRatioBps(const CHouse& house, int nHeight);

/** D-2026-11-04-1 (3c): the interest a house's demanded notes (plain and pre-auth) have accrued by nHeight, in mg,
 *  against the scope's view. HouseEquityMg counts it as a liability. */
uint64_t HouseDemandInterestForChecks(const CHouse& house, int nHeight);
/** A house's gold vault units per token (capital and till together), against the scope's view: the claims pot. */
std::map<uint256, uint64_t> HouseVaultTotalsForChecks(uint32_t nHouseID);
/** 5b: a house's vault units per token less everything frozen (what a payout or claim may take), and its frozen units
 *  that count zero at nHeight (past the grace), against the scope's view. */
std::map<uint256, uint64_t> HouseVaultFreeTotalsForChecks(uint32_t nHouseID, int nHeight);   // valued tokens only
std::map<uint256, uint64_t> HouseVaultFrozenForChecks(uint32_t nHouseID);
/** Against the scope's view: IssuedTokenValuedAt for a token id, and the token's fTrusted flag. */
bool IssuedTokenValuedForChecks(const uint256& tokenID, int nHeight, uint32_t nGrace);
bool IssuedTokenTrustedForChecks(const uint256& tokenID);
std::map<uint256, uint64_t> HouseVaultFrozenZeroForChecks(uint32_t nHouseID, int nHeight);
/** Every vault entry of a house (kind, partner, token, units), against the scope's view. */
struct CVaultEntry { uint8_t nKind; uint32_t nPartner; uint256 tokenID; uint64_t nUnits; };
std::vector<CVaultEntry> HouseVaultEntriesForChecks(uint32_t nHouseID);

/** R3-12, the queued-demand index: units of the house-dischargeable queue (pre-auth demands with the queue marker)
 *  per house and demand height, kept from the note coins each block spends (before its coins update) and creates
 *  (after). A suspended house pays from its partners' capital only the oldest demands first. */
class CCoinsViewCache;
void UnitsQueueSpend(CUnitsView& units, const CTransaction& tx, const CCoinsViewCache& view);
void UnitsQueueCreate(CUnitsView& units, const CTransaction& tx, const CCoinsViewCache& view);
/** Queued units of a house with a demand height below nDemandHeight, against the scope's view. */
uint64_t HouseQueueUnitsBeforeForChecks(uint32_t nHouseID, uint32_t nDemandHeight);
/** R3-12 / R2-int-2: a capital draw of nDraw units of one token, split over the partners holding it in the house's
 *  capital pro rata to their units (vEntry: partner, units, in partner order): floors, then the remainder one unit
 *  each to the entries in order. */
inline std::map<uint32_t, uint64_t> CapitalDrawSplit(uint64_t nDraw, const std::vector<std::pair<uint32_t, uint64_t>>& vEntry)
{
    std::map<uint32_t, uint64_t> m;
    unsigned __int128 nTotal = 0;
    for (const std::pair<uint32_t, uint64_t>& e : vEntry)
        nTotal += e.second;
    if (nTotal == 0 || nDraw == 0 || (unsigned __int128)nDraw > nTotal)
        return m;
    uint64_t nGiven = 0;
    for (const std::pair<uint32_t, uint64_t>& e : vEntry) {
        const uint64_t n = (uint64_t)((unsigned __int128)nDraw * e.second / nTotal);
        m[e.first] = n;
        nGiven += n;
    }
    for (const std::pair<uint32_t, uint64_t>& e : vEntry) {
        if (nGiven >= nDraw)
            break;
        if (m[e.first] < e.second) {
            m[e.first]++;
            nGiven++;
        }
    }
    for (auto it = m.begin(); it != m.end();)
        it = it->second == 0 ? m.erase(it) : std::next(it);
    return m;
}

/** 5b: what a claim of nUnits takes of a failed house's gold - each token, in token-id order, nUnits x what is left of
 *  it over the units outstanding, rounded down, at most nUnits in all; zero shares left out. The ratio is the same for
 *  every claim, so the order of claims doesn't matter. */
inline std::vector<std::pair<uint256, uint64_t>> GoldClaimShares(uint64_t nUnits, const std::map<uint256, uint64_t>& mapPot,
                                                                 uint64_t nOutstanding)
{
    std::vector<std::pair<uint256, uint64_t>> v;
    if (nOutstanding == 0)
        return v;
    // Each token's share; above par in all, every share scales down by the same factor (review round 1, G1e: no
    // token-id order decides which token fills par).
    unsigned __int128 nSum = 0;
    std::vector<std::pair<uint256, unsigned __int128>> vRaw;
    for (const std::pair<const uint256, uint64_t>& pot : mapPot) {
        const unsigned __int128 nShare = (unsigned __int128)nUnits * pot.second / nOutstanding;
        vRaw.push_back(std::make_pair(pot.first, nShare));
        nSum += nShare;
    }
    for (const std::pair<uint256, unsigned __int128>& r : vRaw) {
        const unsigned __int128 n = nSum > nUnits ? r.second * nUnits / nSum : r.second;
        if (n > 0)
            v.push_back(std::make_pair(r.first, (uint64_t)n));
    }
    return v;
}

/** Review round 1 (G3f): the gold deposits may take - per token, its share of what the vaults hold beyond the par the
 *  notes still outstanding can take in gold (the notes keep min(gold, notes) back, spread over the tokens pro rata). */
inline std::map<uint256, uint64_t> DepositGoldPot(const std::map<uint256, uint64_t>& mapFree, uint64_t nNotesLeft)
{
    unsigned __int128 nAll = 0;
    for (const std::pair<const uint256, uint64_t>& t : mapFree)
        nAll += t.second;
    std::map<uint256, uint64_t> m;
    if (nAll == 0 || nAll <= nNotesLeft)
        return m;
    const unsigned __int128 nExcess = nAll - nNotesLeft;
    for (const std::pair<const uint256, uint64_t>& t : mapFree) {
        const uint64_t n = (uint64_t)((unsigned __int128)t.second * nExcess / nAll);
        if (n > 0)
            m[t.first] = n;
    }
    return m;
}

/** The vault moves that take vShare's units out of a house's vault entries, entries in order, sorted as the shape check
 *  wants them. */
inline std::vector<CVaultMove> GoldClaimMoves(uint32_t nHouseID, const std::vector<CVaultEntry>& vEntry,
                                              const std::map<uint256, uint64_t>& mapDue)
{
    std::vector<CVaultMove> v;
    for (const std::pair<const uint256, uint64_t>& d : mapDue) {
        uint64_t nNeed = d.second;
        for (const CVaultEntry& e : vEntry) {
            if (e.tokenID != d.first || nNeed == 0)
                continue;
            const uint64_t nTake = std::min(nNeed, e.nUnits);
            CVaultMove m;
            m.nHouseID = nHouseID;
            m.nKind = e.nKind;
            m.nPartner = e.nPartner;
            m.tokenID = e.tokenID;
            m.nDelta = -(int64_t)nTake;
            v.push_back(m);
            nNeed -= nTake;
        }
    }
    std::sort(v.begin(), v.end(), [](const CVaultMove& a, const CVaultMove& b) {
        return std::make_tuple(a.nHouseID, a.nKind, a.nPartner, a.tokenID) < std::make_tuple(b.nHouseID, b.nKind, b.nPartner, b.tokenID);
    });
    return v;
}

/** The no-price path, against the scope's view: blocks in (nFrom, nTo] with no payout price. An overdue clock that
 *  started at nFrom reads nTo less this. */
uint32_t UnpricedBlocksForChecks(int nFrom, int nTo);
inline int64_t PricedHeightSince(int64_t nFrom, int nHeight)
{
    return (int64_t)nHeight - (int64_t)UnpricedBlocksForChecks((int)std::max<int64_t>(0, std::min<int64_t>(nFrom, nHeight)), nHeight);
}

/** PayoutPrice against the scope's view (see UnitsCheckScope). */
bool PayoutPriceForChecks(int nPriceHeight, uint64_t& nSatsPerGram);

/** HouseGoldCounted (for issuing) against the scope's view. */
void HouseGoldForChecks(const CHouse& house, int nHeight, CGoldCount& count);
/** As HouseGoldForChecks, but a token counts while trusted whether or not a payout price exists (review round 1b: the
 *  capital floor on EXIT and a tail RECLAIM must not hang on the price feed). */
void HouseGoldForChecksNoPriceGate(const CHouse& house, int nHeight, CGoldCount& count);
/** Unit tests only: when set, HouseGoldForChecks returns this instead (the test fixture emulates the pre-gram caps from
 *  a house's ECX fields, so the older cap tests keep their meaning). Never set by the node. */
extern std::function<void(const CHouse&, int, CGoldCount&)> g_fnGoldForChecksTestOverride;
/** Unit tests only: when set, PayoutPriceForChecks returns this price (the fixture sets 1000 sats per gram, so 1 mg is 1
 *  sat and the older payment tests keep their arithmetic), and a payload with no price height binds the block before.
 *  Never set by the node. */
extern uint64_t g_nPayoutPriceTestOverride;

/** End of a block: each token pool's sample (price in sats per gram, token reserve), and the samples older than the
 *  pool view needs pruned. */
void TokenPoolsEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp);

/** A pool's view at nHeight over the last nPoolViewBlocks blocks: the mean price (sats per gram) and whether it counts
 *  (the mean token reserve is at least nPoolDepthMinBps of the token's supply). False if it has no sample. */
bool TokenPoolView(const CUnitsView& units, const uint256& tokenID, int nHeight, const Consensus::GramParams& gp,
                   uint64_t& nSatsPerGram, bool& fDeep, bool* pfCounts);
bool TokenPoolView(const CUnitsView& units, const uint256& tokenID, int nHeight, const Consensus::GramParams& gp,
                   uint64_t& nSatsPerGram, bool& fDeep);

/** The payout price at nHeight, sats per gram (design draft 9 "Units, redemption and settlement"; R3-3, R3-6, R3-9;
 *  D-2026-11-01-6 item 4): the higher of the oracle's 144-block median and the pools' view (the lower median of every
 *  deep gold pool's mean), capped at the pools' view + nPayoutCapBps while a pool is deep. One side alone when the
 *  other is missing. False when neither exists: the payer pays in gold tokens, in kind. */
bool PayoutPrice(const CUnitsView& units, int nHeight, const Consensus::GramParams& gp, uint64_t& nSatsPerGram);

void IssuedTokensEndBlock(CUnitsView& units, int nHeight, const Consensus::GramParams& gp,
                          const std::function<bool(const CIssuedToken&)>& fnPoolDeep,
                          const std::function<bool(const CIssuedToken&)>& fnBackingClean);


#endif // BITCOIN_ISSUED_H

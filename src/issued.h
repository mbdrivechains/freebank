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
// 7 and 8 were the issuer bond's BOND / UNBOND: retired with gold tokens as reserves (Gold B, D-2026-11-07-1).
static const uint8_t ISSUED_OP_RETIRED_BOND = 7;
static const uint8_t ISSUED_OP_RETIRED_UNBOND = 8;
// Token pools (step 4): a token/sECX constant-product pool per gold token, owned by no house.
static const uint8_t ISSUED_OP_POOL_CREATE = 9;
static const uint8_t ISSUED_OP_POOL_ADD = 10;
static const uint8_t ISSUED_OP_POOL_REMOVE = 11;
static const uint8_t ISSUED_OP_POOL_SWAP = 12;

static const uint8_t ISSUED_KIND_GOLD_MG = 1;      // retired (Gold B): CREATE refuses it; gold tokens live on Ethereum
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
struct IssuedFreeze
{
    uint256 tokenID;
    std::vector<COutPoint> vOutpoint;
    std::vector<uint64_t> vFrozen;           // the new frozen units, parallel to vOutpoint
    std::vector<unsigned char> vchFreezeSig;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tokenID);
        READWRITE(vOutpoint);
        READWRITE(vFrozen);
        READWRITE(vchFreezeSig);
    }
};

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
    }
};

class CScript;
/** A token pool's custody script: <"FBTP" + token id> OP_DROP OP_TRUE, custody-tagged. */
CScript TokenPoolScript(const uint256& tokenID);
/** D-2026-11-04-1 (3b): the unspendable output a token or pool creation burns its fee to (OP_RETURN "FBCF"). */
CScript CreationBurnScript();
/** D-2026-11-04-1 (3d, review 11-04): the smallest BURN: 1,000 units (a gram of a gold token, ten dollars of a dollar one). */
static const uint64_t ISSUED_BURN_MIN_UNITS = 1000;
class CUnitsView;
namespace Consensus { struct GramParams; }
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

/** Gold B (D-2026-11-07-1; GOLD_B.md §5): a house's capital as the floors and the ramp count it, in mg at the house's
 *  highest ask of the last 30 days (so a lower quote can't raise it): its sECX escrow (the active partners' pledges) and
 *  its till - sECX it proved it controls, amountTillSats (the issuing transaction's own reserve proofs where it carries
 *  them, else its last attestation while fresh: HouseAttestedTillSats). False: the house has posted no rate, and so
 *  can't issue. Against the scope's view. */
struct CHouseCapital {
    uint64_t nEscrowMg = 0;
    uint64_t nTillMg = 0;
    uint64_t nCapacityMg = 0;   // the ramp (GOLD_B §5): notes + deposits may reach this (each tranche at its multiple)
};
class CHouse;
bool HouseCapitalForChecks(const CHouse& house, int nHeight, CAmount amountTillSats, CHouseCapital& cap);
/** The sECX the house last attested, while that attestation is fresh at nHeight (HOUSE_ATTEST_STALENESS); else 0. */
CAmount HouseAttestedTillSats(const CHouse& house, int nHeight);
/** Unit tests only: when set, HouseCapitalForChecks returns this instead (the fixture emulates the pre-gram caps). */
extern std::function<void(const CHouse&, int, CHouseCapital&)> g_fnCapitalForChecksTestOverride;

/** The units view the issuing checks count gold against: ConnectBlock's (the block so far) or the mempool's, set for
 *  the scope's life; outside any scope, the units DB at the tip. */
class UnitsCheckScope
{
public:
    UnitsCheckScope(const CUnitsView* pView);
    ~UnitsCheckScope();
    /** The view in scope, or null outside any scope (Gold B: the house-rate reads use it too). */
    static const CUnitsView* Current();
private:
    const CUnitsView* pPrev;
};
/** Par-eligible for settlement: effectively Open, and its till (attested sECX at A30, Gold B) at least nTillMinBps of
 *  its notes. */
bool GoldParEligible(const CHouse& house, int nHeight);
/** v1.1.0 (D-2026-11-05-1): the redemption spread, basis points. Zero at an Open house (par while it pays) and at a house
 *  with no notes. Otherwise (Stressed, Deferred) the brassage curve (BrassageBpsAt) on the till / notes (both mg; the
 *  till is attested sECX at A30, Gold B) against the till floor (nTillMinBps, 2%): par at or above the floor, rising to
 *  the full 4% at a quarter of it. Paid in sECX at the house's bid into the escrow pot. */
uint32_t GoldBrassageBps(const CHouse& house, int nHeight);
/** The till / notes ratio, basis points, capped at 10000 (10000 with no notes). */
uint32_t GoldTillRatioBps(const CHouse& house, int nHeight);

/** D-2026-11-04-1 (3c): the interest a house's demanded notes (plain and pre-auth) have accrued by nHeight, in mg,
 *  against the scope's view. */
uint64_t HouseDemandInterestForChecks(const CHouse& house, int nHeight);
/** D-2026-11-04-1 (3c): the demanded-notes index (units DB 'q': units of demanded notes per house and demand tag), kept
 *  from the note coins each block spends (before its coins update) and creates (after); HouseDemandInterestForChecks
 *  reads it. (Gold B dropped R3-12's queued-demand index with the partners' gold capital draw it served.) */
class CCoinsViewCache;
void UnitsQueueSpend(CUnitsView& units, const CTransaction& tx, const CCoinsViewCache& view);
void UnitsQueueCreate(CUnitsView& units, const CTransaction& tx, const CCoinsViewCache& view);


#endif // BITCOIN_ISSUED_H

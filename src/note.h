// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NOTE_H
#define BITCOIN_NOTE_H

#include <amount.h>
#include <house.h>            // AttestProof (the rho-at-mint reserve proof, R-i7)
#include <pubkey.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <string>
#include <vector>

class CValidationState;

//
// Notes (Phase 3.2) - the per-house named credit asset.
//
// A note is a CREDIT CLAIM, not a locked coin. A house mints up to lambda*E
// note-units against E escrow (CM-2; lambda up to 3x), so notes are NOT
// 100%-reserved - they cannot be modelled as colored sats (that would force a
// full reserve and defeat fractional credit). Instead each note UTXO carries
// its claim `nNoteUnits` as a SEPARATE coin field and holds only a dust
// base-value; minting creates claims (tracked in CHouse.nMintedUnits), never
// base-coin, and redemption pays real base-coin from the house's own reserves.
// Structurally this is the Bills model (dust UTXO + separate amount) made
// fungible and divisible.
//
// v1 is base-native 1:1 (1 note-unit redeems for 1 base-sat); the house's
// gold-unit denomination fields ride inert (the D14 oracle migration). Full
// transparency; holder identity = pubkey pseudonym.
//
// All constants PROVISIONAL (N-1) - revisit before real value.
//

// Note operations carried by TRANSACTION_NOTE_VERSION transactions
static const uint8_t NOTE_OP_MINT     = 1;
static const uint8_t NOTE_OP_TRANSFER = 2;
static const uint8_t NOTE_OP_REDEEM   = 3;
// Reserved INERT for the v1.5 Chaumian bearer layer (D8). Rejected in v1 shape
// (unreachable) so the op-codes are permanently claimed without behaviour.
static const uint8_t NOTE_OP_LOCK     = 4;
static const uint8_t NOTE_OP_UNLOCK   = 5;
// Phase 3.4 insolvency waterfall: holder claims pro-rata from the escrow pot
static const uint8_t NOTE_OP_CLAIM    = 6;
// Phase 3.5 option clause: the holder LODGES A DEMAND while the house is
// suspended, which starts their interest clock (5%/yr from the date of demand).
static const uint8_t NOTE_OP_DEMAND   = 7;
// Phase 3.5b / B3: a holder whose PRE-AUTHORISED demand has gone undischarged
// for HOUSE_DEMAND_WINDOW protests, putting the house on the stress cascade.
static const uint8_t NOTE_OP_PROTEST  = 8;

// PRE-AUTH MARKER (B3 D-i, operator-signed 2026-08-04: the HIGH BIT of the
// coin's nDemandHeight, NOT a new Coin field). A new bool would have changed
// the Coin serialization => a disk-format bump => a one-time -reindex on every
// datadir, which on the evidence chain is an F4-runbook operation rather than a
// binary swap. The high bit costs a mask at the read sites and is safe for
// ~40k years of heights. Revisit only at the next FORCED format bump.
//
// A pre-auth demanded coin is one whose holder has signed a STANDING
// redemption authorisation, so the house can discharge it UNILATERALLY. That
// is what makes the protest teeth just: "the demand went stale" can then only
// mean the house chose not to pay.
static const uint32_t NOTE_DEMAND_PREAUTH_BIT = 0x80000000;
// T-b3: the PROTESTED marker, stamped by NOTE_OP_PROTEST onto the re-issued
// coins. It exists because the D-v counter needs an EXACT decrement: CHouse
// carries only {count, oldest height}, so without a per-coin marker consensus
// could not tell whether a discharged demand was among the PROTESTED ones -
// the decrement would be a heuristic, and a heuristic on the insolvency clock
// is a hole. With the marker: discharge of a marked coin decrements, discharge
// of an unmarked pre-auth coin does not, and a second protest of a marked coin
// is idempotence-rejected for free. Same no-format-bump class as the pre-auth
// bit (D-i); plain heights stay safe below 2^30 (~20k years at 10 minutes).
static const uint32_t NOTE_DEMAND_PROTESTED_BIT = 0x40000000;
static const uint32_t NOTE_DEMAND_TAG_BITS = NOTE_DEMAND_PREAUTH_BIT | NOTE_DEMAND_PROTESTED_BIT;
// T-b3 CONSENSUS CUSTODY (build-level resolution of a contradiction inside the
// signed sheet, queued for ratification in SIGNOFF_QUEUE.md). The sheet
// requires the house to discharge UNILATERALLY, but note coins are real P2PKH:
// the house cannot produce the holder's scriptSig, so a pre-auth demand's
// re-issued coins CANNOT stay on the holder's P2PKH. Two candidate fixes were
// weighed: (A) a tag-keyed script-check skip inside CheckInputs (+ a policy
// mirror) - the first such skip in the codebase, core-path surgery; or (B) the
// pre-auth re-issue moves the coins onto a CUSTODY script - the proven escrow
// family (<push> OP_DROP OP_TRUE), script-level open, protected entirely by
// the consensus layers: the tx_verify holder pin (the embedded keyid), the
// contextual pre-auth digest, and the discharge floor. (B) is built: zero core
// surgery, and it makes the demand's meaning literal on-chain - the holder
// relinquished unilateral control the moment they signed the pre-auth. The
// holder's remaining rights (protest; voluntary redeem; insolvency claim) are
// all exercised through payload signatures, which never needed the scriptSig.
inline bool NoteDemandIsPreAuth(uint32_t nTag) { return (nTag & NOTE_DEMAND_PREAUTH_BIT) != 0; }
inline bool NoteDemandIsProtested(uint32_t nTag) { return (nTag & NOTE_DEMAND_PROTESTED_BIT) != 0; }
inline uint32_t NoteDemandHeightOf(uint32_t nTag) { return nTag & ~NOTE_DEMAND_TAG_BITS; }
inline uint32_t NoteDemandTag(uint32_t nHeight, bool fPreAuth)
{
    return fPreAuth ? (nHeight | NOTE_DEMAND_PREAUTH_BIT) : nHeight;
}

// Dust base-value each note UTXO carries (it holds the claim, not value).
static const CAmount NOTE_DUST_VALUE = 1000;

// B3: bound on a pre-auth payout script. Standard scripts are well under this
// (P2PKH 25, P2WSH 34, a large bare multisig ~200); the cap exists so a demand
// cannot carry an unbounded blob that every discharge must then compare.
static const size_t MAX_NOTE_PAYOUT_SCRIPT = 256;

// Max note outputs per MINT/TRANSFER (bounds payload + per-tx loops). PROVISIONAL (N-1).
static const size_t MAX_NOTE_OUTPUTS = 100;

/** MINT: a house mints note-units to holders. vout[0..vUnits.size()-1] are the
 * new note coins (P2PKH to holders), each carrying vUnits[i] claim units and
 * NOTE_DUST_VALUE sats (funded by the house). Approved by the house M-of-N over
 * the mint sighash (house_id + vUnits + hashOutputs). Cap:
 * nMintedUnits + sum(vUnits) <= (HOUSE_LAMBDA_X10[tier]/10) * ActiveEscrow(). */
struct NoteMint {
    uint32_t nHouseID;
    std::vector<uint64_t> vUnits;                         // parallel to the note outputs
    // R-i7 rho-at-mint LIVENESS gate (DR-1): the mint proves its liquid reserves
    // are still unspent AT MINT TIME, rather than the cap trusting a stored
    // attestation snapshot the house could have spent. Same proof primitive as
    // HOUSE_OP_ATTEST: declared outpoints + per-coin sigs over a recency
    // challenge at nAsOfHeight. The reserve cap uses the freshly-proven sum.
    uint32_t nAsOfHeight;
    std::vector<AttestProof> vReserveProofs;              // <= MAX_ATTEST_PROOFS
    std::vector<uint32_t> vApproverIndex;                 // strictly ascending
    std::vector<std::vector<unsigned char>> vApproverSig;

    NoteMint() : nHouseID(0), nAsOfHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vUnits);
        READWRITE(nAsOfHeight);
        READWRITE(vReserveProofs);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** TRANSFER: the current holder (single sender, v1) spends note coin(s) of one
 * house and re-issues note coin(s) to new holders at vout[0..vUnits.size()-1].
 * Conserves sum(in units) == sum(vUnits). Authorized by the sender's signature
 * over (house_id + vUnits + hashOutputs) - which is what binds the trailer
 * payload the legacy input sighash does NOT cover. */
struct NoteTransfer {
    uint32_t nHouseID;
    std::vector<uint64_t> vUnits;                         // parallel to the note outputs
    // The demand height carried by the notes being moved (0 = undemanded).
    // A DEMANDED note stays TRANSFERABLE and keeps its clock: consensus
    // requires every spent note input to carry exactly this height, and tags
    // the new outputs with it. That is what gives a queued holder a secondary
    // exit - sell at a market discount - rather than being trapped for the
    // whole window, and it is the only thing the record says legitimises a
    // private suspension (a suspension AT PAR is what it calls the crime).
    uint32_t nDemandHeight;
    std::vector<unsigned char> vchSenderPubKey;           // must hash to every spent note input
    std::vector<unsigned char> vchSenderSig;

    NoteTransfer() : nHouseID(0), nDemandHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vUnits);
        READWRITE(nDemandHeight);
        READWRITE(vchSenderPubKey);
        READWRITE(vchSenderSig);
    }
};

/** DEMAND (Phase 3.5, ARCH s7 Option (c) step 2): while the house is suspended,
 * the holder presents their notes for payment. The notes are NOT surrendered -
 * they are re-issued to the same holder, now stamped with the demand height, so
 * interest runs from the date of demand (the historical rule: "5% per annum
 * from the date of demand"). Valid ONLY at effective Deferred: while the house
 * is Open or Stressed the holder simply REDEEMS at par, and once Insolvent the
 * pro-rata waterfall replaces redemption entirely. Changes no house state -
 * outstanding units are unchanged (a demanded note is still a liability, and if
 * it left nMintedUnits the wind-down and escrow-reclaim gates would open under
 * the queued holders' feet). */
struct NoteDemand {
    uint32_t nHouseID;
    std::vector<uint64_t> vUnits;                         // parallel to the re-issued note outputs
    std::vector<unsigned char> vchHolderPubKey;           // must hash to every spent note input
    std::vector<unsigned char> vchHolderSig;
    // ---- B3 (Phase 3.5b): the PRE-AUTHORISED mode -------------------------
    // 1 => this demand carries a standing redemption authorisation so the house
    // can discharge it ALONE. REQUIRED at Open/Stressed (the states B3 opens
    // DEMAND to), FORBIDDEN at Deferred - where the option clause governs and
    // today's semantics are preserved byte-for-byte. One op, two modes, no
    // ambiguity.
    uint8_t fPreAuth;
    // Δ1b UPGRADE ONLY: the height the spent notes already carry, so the clock
    // is PRESERVED rather than reset. 0 on a fresh demand (AddCoins then stamps
    // the connect height). It lives in the PAYLOAD for the same reason
    // NoteTransfer::nDemandHeight does - AddCoins is self-contained, so connect
    // and rollforward tag identically with nothing threaded through; tx_verify
    // forces this to equal the spent coins' height, so a lie here cannot mint
    // or destroy an interest claim.
    uint32_t nPriorDemandHeight;
    // The script the discharge must pay. Bound by vchPreAuthSig, which is a
    // SEPARATE digest from vchHolderSig (NotePreAuthSigHash - domain-separated,
    // never a NoteDemandSigHash reuse), because the two authorise different
    // things: one the re-issue, one a future payout the holder will not be
    // present to sign.
    std::vector<unsigned char> vchPayoutScript;
    std::vector<unsigned char> vchPreAuthSig;

    NoteDemand() : nHouseID(0), fPreAuth(0), nPriorDemandHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vUnits);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
        READWRITE(fPreAuth);
        READWRITE(nPriorDemandHeight);
        READWRITE(vchPayoutScript);
        READWRITE(vchPreAuthSig);
    }
};

/** PROTEST (Phase 3.5b / B3, op 8): the holder of a PRE-AUTHORISED demand that
 * has sat undischarged for HOUSE_DEMAND_WINDOW blocks puts the house onto the
 * stress cascade. The demanded notes are spent and re-issued UNCHANGED (the
 * DEMAND idiom) - conservation exact - which both proves standing (only the
 * demand's holder can spend them) and keeps the op self-contained.
 *
 * Effects on CHouse: nProtestOpen++ (a COUNTER - see house.h), nProtestHeight
 * takes the earliest live value, nProtestDemandHeight the oldest protested
 * demand. From there NOTHING NEW IS NEEDED: the third stress origin makes the
 * house effectively Stressed, which prices exits through brassage, drops
 * par-eligibility, blocks discounting and minting, and expires into Insolvent
 * and the waterfall if the house still will not pay.
 *
 * Priors ride in the payload for the undo (the nPrevLastActivation idiom). */
struct NoteProtest {
    uint32_t nHouseID;
    std::vector<uint64_t> vUnits;                         // parallel to the re-issued note outputs
    std::vector<unsigned char> vchHolderPubKey;           // must hash to every spent note input
    std::vector<unsigned char> vchHolderSig;
    // The tag the spent notes carry (height WITH the pre-auth bit), re-stamped
    // unchanged onto the re-issued outputs. In the payload for AddCoins'
    // self-containment; tx_verify forces it to match the spent coins.
    uint32_t nDemandTag;
    // undo priors (must match the DB at connect)
    uint32_t nPrevProtestOpen;
    uint32_t nPrevProtestHeight;
    uint32_t nPrevProtestDemandHeight;

    NoteProtest() : nHouseID(0), nDemandTag(0), nPrevProtestOpen(0),
                    nPrevProtestHeight(0), nPrevProtestDemandHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vUnits);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
        READWRITE(nDemandTag);
        READWRITE(nPrevProtestOpen);
        READWRITE(nPrevProtestHeight);
        READWRITE(nPrevProtestDemandHeight);
    }
};

/** REDEEM: the holder burns note coin(s) of one house (U units total) and is
 * paid base-coin. Holder protection is by SIGNATURE, not a consensus payout
 * floor: the holder signs (house_id + U + hashOutputs) AND supplies the P2PKH
 * scriptSig for every burned note input (SIGHASH_ALL) - both bind the exact
 * output set, so the holder never surrenders notes without endorsing the payout
 * they receive. The house funds the payout from its own key-signed base-coin
 * inputs. Consensus does NOT enforce a >= U floor (D5). nMintedUnits -= U. */
struct NoteRedeem {
    uint32_t nHouseID;
    // 1 -> vout[1] is the DYNAMIC BRASSAGE output: the redemption spread, paid
    // into the house's escrow pot (3.5 D1/D10). Required whenever the house's
    // attested ratio is below rho; forbidden when the spread is zero (an
    // untracked escrow-script output would enter the UTXO set anyone-can-spend).
    uint8_t fBrassage;
    std::vector<unsigned char> vchHolderPubKey;           // must hash to every spent note input; receives the payout
    std::vector<unsigned char> vchHolderSig;
    // ---- B3 T-b3: the PRE-AUTHORISED DISCHARGE ----------------------------
    // 1 => the house executes a standing authorisation ALONE: the holder's
    // fresh vchHolderSig is not required; instead vchPreAuthSig is verified
    // over NotePreAuthSigHash(nHouseID, vPreAuthUnits, vchPayoutScript) against
    // the holder key on the burned coins. vPreAuthUnits is re-supplied VERBATIM
    // from the demand because the digest binds the VECTOR, which cannot be
    // reconstructed from an unordered burned-coin set - consensus checks
    // sum(vPreAuthUnits) == burned units, so a lie cannot change what is owed.
    uint8_t fPreAuthDischarge;
    std::vector<uint64_t> vPreAuthUnits;
    std::vector<unsigned char> vchPayoutScript;
    std::vector<unsigned char> vchPreAuthSig;

    NoteRedeem() : nHouseID(0), fBrassage(0), fPreAuthDischarge(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(fBrassage);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
        READWRITE(fPreAuthDischarge);
        READWRITE(vPreAuthUnits);
        READWRITE(vchPayoutScript);
        READWRITE(vchPreAuthSig);
    }
};

/** CLAIM (Phase 3.4, ARCH s7 Option a-2): at effective-Insolvent, the holder
 * burns note coin(s) of the house (U units) and takes AT MOST the pro-rata
 * entitlement min(U, U*pot/units) from the house's escrow coins - pot and
 * units are the FIXED snapshot written by the first claim (order-independent,
 * no front-running; D5/D15: claims never expire, holders senior forever).
 * vin = holder's note coins + house escrow coins + plain fee coins;
 * vout[0] = payout (the holder signs the exact output set); if fEscrowChange,
 * vout[1] returns escrow change to the canonical escrow script (re-tagged
 * from this self-contained payload - AddCoins/mempool/rollforward identical). */
struct NoteClaim {
    uint32_t nHouseID;                                    // leading - guard convention
    uint8_t fEscrowChange;                                // 1 -> vout[1] is escrow change
    std::vector<unsigned char> vchHolderPubKey;           // must hash to every spent note input
    std::vector<unsigned char> vchHolderSig;

    NoteClaim() : nHouseID(0), fEscrowChange(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(fEscrowChange);
        READWRITE(vchHolderPubKey);
        READWRITE(vchHolderSig);
    }
};

//
// Pure helpers (note.cpp)
//

/** Note UTXO lock: standard P2PKH to the holder. Note-ness is carried by the
 * coin tag (fNote + nHouseID + nNoteUnits), never the script - so a transfer is
 * an ordinary key-spend and the tag propagates via the v13 op (Bills pattern). */
CScript NoteScriptForPubKey(const std::vector<unsigned char>& vchPubKey);

/** B3 consensus-custody lock for PRE-AUTH demanded coins:
 *   <20-byte holder keyid> OP_DROP OP_TRUE
 * The escrow family (house.cpp:183), 20-byte push where the escrows push 32 -
 * distinguished from them by coin tags, never by script inspection. Script-
 * level open so the HOUSE can build the discharge alone; the embedded keyid
 * keeps the tx_verify holder pin byte-compare exact (protest / voluntary
 * redeem / insolvency claim all still require the HOLDER's payload signature
 * against the key this keyid pins). See the custody note at
 * NOTE_DEMAND_PROTESTED_BIT for why P2PKH cannot carry a pre-auth coin. */
CScript NotePreAuthScript(const std::vector<unsigned char>& vchPubKey);
bool IsNotePreAuthScript(const CScript& script);

/** SHA256d over every input outpoint of tx - the tx-unique element bound into
 * the mint sighash so reused M-of-N approver signatures cannot authorize a
 * second, differently-funded mint (MINT spends only fungible plain inputs, so
 * without this its authorization is replayable). */
uint256 NoteHashPrevouts(const CTransaction& tx);

uint256 NoteMintSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 NoteTransferSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs);
uint256 NoteRedeemSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs);
uint256 NoteClaimSigHash(uint32_t nHouseID, uint64_t nUnitsBurned, const uint256& hashOutputs);
uint256 NoteDemandSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs);
/** B3: the STANDING authorisation. Domain-separated from every other note
 * digest because it authorises a payout the holder will not be present to sign,
 * and binds the payout SCRIPT rather than a transaction's outputs - the
 * discharge that satisfies it does not exist yet when this is signed. */
uint256 NotePreAuthSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits,
                           const std::vector<unsigned char>& vchPayoutScript);
uint256 NoteProtestSigHash(uint32_t nHouseID, const std::vector<uint64_t>& vUnits, const uint256& hashOutputs);

/** Deferral interest (Phase 3.5 D6): nUnits held demanded for nBlocks, at
 * HOUSE_DEFER_INTEREST_BPS per year, pro-rated by block. Simple (not
 * compounding) - the Scottish clause was 5% flat. 128-bit intermediate:
 * nUnits <= 3*MAX_MONEY and nBlocks is unbounded in principle, so the product
 * overflows uint64. Returns the INTEREST only, not principal + interest. */
CAmount NoteDeferralInterest(uint64_t nUnits, uint32_t nBlocks);

/** The pro-rata waterfall entitlement: burning nUnits against the insolvency
 * snapshot (amountPot escrow backing nSnapshotUnits claims) entitles the
 * holder to min(nUnits, floor(nUnits * amountPot / nSnapshotUnits)) sats.
 * 128-bit intermediate (the product overflows uint64). Returns 0 if
 * nSnapshotUnits == 0. */
CAmount NoteClaimEntitlement(uint64_t nUnits, const CAmount& amountPot, uint64_t nSnapshotUnits);

/** A partner's residual share at whole-house settlement: distributes
 * amountResidual pro-rata by pledge over amountPledgeSum. 128-bit; 0 if the
 * pledge sum is 0. Sum over partners never exceeds amountResidual. */
CAmount HouseResidualShare(const CAmount& amountPledge, const CAmount& amountResidual, const CAmount& amountPledgeSum);

/** Sum a vUnits vector with overflow protection (returns false on overflow or
 * a zero total / any zero element). */
bool SumNoteUnits(const std::vector<uint64_t>& vUnits, uint64_t& total);

template <typename T>
bool DecodeNotePayload(const std::vector<unsigned char>& vch, T& payload);

/** Context-free shape rules for v13 note txs (no DB, no ECDSA - signatures and
 * the cap/status checks run contextually in CheckNoteOperation, DoS pricing). */
bool CheckNoteTransactionShape(const CTransaction& tx, CValidationState& state);

#endif // BITCOIN_NOTE_H

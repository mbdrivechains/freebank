// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FREEBANK_TOKEN_H
#define FREEBANK_TOKEN_H

// The token holders' claim at a failed house, without the partners (gateway docs/freebank/TOKEN_CLAIM_DESIGN.md,
// draft 3, signed off by Michael 2026-10-08; overriding rule: "keep noteholders whole" - claims are paid only out of
// the token backing, at a note's per-unit share).
//
//   NOTE_OP_TOKEN_KEYSET  the partners record a mint keyset (its posting key and one public key per amount 2^i).
//                         No house slot; the same keyset recorded twice in a block keeps its first record.
//   NOTE_OP_TOKEN_POST    the posting key records blinded messages the mint signed (B_, amount) and spent token Ys.
//                         No house slot; a record already present is ignored. Refused once the house is insolvent.
//   NOTE_OP_TOKEN_CLAIM   during the window E .. E+W: tokens, each signed with its blinding factor (key B_ - Y).
//                         No house slot (any number of holders per block); its totals are added at the block's end.
//   NOTE_OP_TOKEN_COLLECT after the window: pays claims from the escrow. Takes the house slot.
//
// Words: Y = hash_to_curve(secret), stored as the 32-byte x of its 0x02 point; B_ = Y + r*G the blinded message the
// mint signed; E the height from which the chain counts the house insolvent (HouseInsolventSince).

#include <amount.h>
#include <pubkey.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

#include <functional>
#include <map>
#include <set>
#include <vector>

static const uint8_t NOTE_OP_TOKEN_KEYSET  = 9;
static const uint8_t NOTE_OP_TOKEN_POST    = 10;
static const uint8_t NOTE_OP_TOKEN_CLAIM   = 11;
static const uint8_t NOTE_OP_TOKEN_COLLECT = 12;

inline bool IsTokenClaimOp(uint8_t nNoteOp) { return nNoteOp >= NOTE_OP_TOKEN_KEYSET && nNoteOp <= NOTE_OP_TOKEN_COLLECT; }

/** Highest amount exponent: 2^50 <= MAX_MONEY (2.1e15) < 2^51. */
static const uint8_t MAX_TOKEN_AMOUNT_EXP = 50;
/** Entries per POST (issued + spent), tokens per CLAIM, claims per COLLECT. */
static const size_t MAX_TOKEN_POST_ENTRIES = 2000;
static const size_t MAX_TOKEN_CLAIM_ENTRIES = 64;
static const size_t MAX_TOKEN_COLLECT_ENTRIES = 100;
/** A token secret's length: Cashu's default is 64 hex characters. */
static const size_t MAX_TOKEN_SECRET_SIZE = 256;
/** The relayer's script (a standard output script). */
static const size_t MAX_TOKEN_RELAYER_SCRIPT = 34;
/** The holder's payout script: a standard output script (P2PKH, P2SH, P2WPKH, P2WSH). */
static const size_t MAX_TOKEN_PAYOUT_SCRIPT = 34;
static const uint16_t TOKEN_FEE_BPS_MAX = 10000;

/** One key of a keyset: amount 2^nExp. */
struct TokenKey {
    uint8_t nExp;
    std::vector<unsigned char> vchPubKey;   // 33-byte compressed

    TokenKey() : nExp(0) {}
    TokenKey(uint8_t n, const std::vector<unsigned char>& v) : nExp(n), vchPubKey(v) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nExp);
        READWRITE(vchPubKey);
    }
};

/** NOTE_OP_TOKEN_KEYSET payload. The keyset id is derived from the keys (TokenKeysetID), not carried. */
struct NoteTokenKeyset {
    uint32_t nHouseID;                                  // leading - guard convention
    std::vector<unsigned char> vchPostingPubKey;        // signs this keyset's POSTs
    std::vector<TokenKey> vKey;                         // 1..51, exponents strictly ascending
    std::vector<uint32_t> vApproverIndex;               // M-of-N, as every house op
    std::vector<std::vector<unsigned char>> vApproverSig;

    NoteTokenKeyset() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vchPostingPubKey);
        READWRITE(vKey);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** A blinded message the mint signed. */
struct TokenIssued {
    std::vector<unsigned char> vchB;   // B_, 33-byte compressed
    uint64_t nAmount;

    TokenIssued() : nAmount(0) {}
    TokenIssued(const std::vector<unsigned char>& v, uint64_t n) : vchB(v), nAmount(n) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchB);
        READWRITE(nAmount);
    }
};

/** NOTE_OP_TOKEN_POST payload, signed by the keyset's posting key. */
struct NoteTokenPost {
    uint32_t nHouseID;
    uint64_t nKeysetID;
    std::vector<TokenIssued> vIssued;   // B_s this keyset signed, with their amounts
    std::vector<uint256> vSpent;        // Ys the mint marked spent (any of the house's keysets)
    std::vector<unsigned char> vchSig;

    NoteTokenPost() : nHouseID(0), nKeysetID(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(nKeysetID);
        READWRITE(vIssued);
        READWRITE(vSpent);
        READWRITE(vchSig);
    }
};

/** One token in a claim, with the payout terms its holder signed with the key P = B_ - Y. */
struct TokenClaimEntry {
    uint64_t nKeysetID;
    uint64_t nAmount;
    std::vector<unsigned char> vchSecret;        // the token's secret, as the mint hashed it
    std::vector<unsigned char> vchB;             // B_
    std::vector<unsigned char> vchC;             // C_ = k * B_, the mint's blind signature
    std::vector<unsigned char> vchE;             // DLEQ e (32 bytes)
    std::vector<unsigned char> vchS;             // DLEQ s (32 bytes)
    std::vector<unsigned char> vchPayoutScript;  // the holder's payout script (a standard output script)
    uint16_t nFeeBps;                            // the relayer's share of the payout
    std::vector<unsigned char> vchRelayerScript; // empty iff nFeeBps == 0
    std::vector<unsigned char> vchSig;           // under P over TokenClaimSigHash

    TokenClaimEntry() : nKeysetID(0), nAmount(0), nFeeBps(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nKeysetID);
        READWRITE(nAmount);
        READWRITE(vchSecret);
        READWRITE(vchB);
        READWRITE(vchC);
        READWRITE(vchE);
        READWRITE(vchS);
        READWRITE(vchPayoutScript);
        READWRITE(nFeeBps);
        READWRITE(vchRelayerScript);
        READWRITE(vchSig);
    }
};

struct NoteTokenClaim {
    uint32_t nHouseID;
    std::vector<TokenClaimEntry> vEntry;

    NoteTokenClaim() : nHouseID(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(vEntry);
    }
};

/** NOTE_OP_TOKEN_COLLECT payload. Outputs, in order: vout[0] escrow change if fEscrowChange; then, for each claim,
 *  its payout (if above 0) and its relayer fee (if above 0); anything after is the sender's (no escrow script). */
struct NoteTokenCollect {
    uint32_t nHouseID;
    uint8_t fEscrowChange;
    std::vector<uint256> vY;

    NoteTokenCollect() : nHouseID(0), fEscrowChange(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseID);
        READWRITE(fEscrowChange);
        READWRITE(vY);
    }
};

//
// Records (HouseDB)
//

struct CTokenKeyset {
    uint32_t nHeight;
    uint256 txid;
    std::vector<unsigned char> vchPostingPubKey;
    std::vector<TokenKey> vKey;

    CTokenKeyset() : nHeight(0) {}

    /** The key for amount nAmount, or false if the amount is not 2^i with a key here. */
    bool KeyFor(uint64_t nAmount, CPubKey& key) const;

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHeight);
        READWRITE(txid);
        READWRITE(vchPostingPubKey);
        READWRITE(vKey);
    }
};

/** An issued B_ or a spent Y: who posted it first, when. A reorg undoes only the records its own txs wrote. */
struct CTokenMark {
    uint32_t nHeight;
    uint256 txid;
    uint64_t nKeysetID;   // issued only
    uint64_t nAmount;     // issued only

    CTokenMark() : nHeight(0), nKeysetID(0), nAmount(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHeight);
        READWRITE(txid);
        READWRITE(nKeysetID);
        READWRITE(nAmount);
    }
};

struct CTokenClaim {
    uint64_t nAmount;
    std::vector<unsigned char> vchPayoutScript;
    uint16_t nFeeBps;
    std::vector<unsigned char> vchRelayerScript;
    uint32_t nHeight;
    uint32_t nCollectHeight;   // 0 = not collected

    CTokenClaim() : nAmount(0), nFeeBps(0), nHeight(0), nCollectHeight(0) {}

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nAmount);
        READWRITE(vchPayoutScript);
        READWRITE(nFeeBps);
        READWRITE(vchRelayerScript);
        READWRITE(nHeight);
        READWRITE(nCollectHeight);
    }
};

/** What token ops read: the confirmed records (plus, in ConnectBlock, the block's staged POST records). */
struct TokenView {
    std::function<bool(uint32_t, uint64_t, CTokenKeyset&)> fnGetKeyset;
    std::function<bool(uint32_t, const std::vector<unsigned char>&, CTokenMark&)> fnGetIssued;
    std::function<bool(uint32_t, const uint256&, CTokenMark&)> fnGetSpent;
    std::function<bool(uint32_t, const uint256&, CTokenClaim&)> fnGetClaim;
};

/** One block's token record writes (records are only added, or a claim's collect height set), and the claim totals
 *  each house gains (claims take no house slot: their totals are added to the house at the block's end). */
struct TokenEffects {
    std::map<std::pair<uint32_t, uint64_t>, CTokenKeyset> mapKeyset;
    std::map<uint32_t, std::pair<uint64_t, uint32_t>> mapClaimTotals;   // house -> (amount claimed, claims)
    std::map<std::pair<uint32_t, std::vector<unsigned char>>, CTokenMark> mapIssued;
    std::map<std::pair<uint32_t, uint256>, CTokenMark> mapSpent;
    std::map<std::pair<uint32_t, uint256>, CTokenClaim> mapClaim;

    bool empty() const { return mapKeyset.empty() && mapIssued.empty() && mapSpent.empty() && mapClaim.empty(); }
};

//
// Helpers (token.cpp)
//

/** Cashu NUT-02 keyset id: 0x00 || the first 7 bytes of SHA256 over the compressed keys in amount order, read as a
 *  big-endian integer. */
uint64_t TokenKeysetID(const std::vector<TokenKey>& vKey);

/** Y's stored form from a hash_to_curve point (always 0x02-prefixed): its 32-byte x. */
uint256 TokenYID(const CPubKey& Y);
/** The point back from its stored form. */
CPubKey TokenYPoint(const uint256& y);

uint256 TokenKeysetSigHash(const NoteTokenKeyset& ks, const uint256& hashPrevouts);
uint256 TokenPostSigHash(const NoteTokenPost& post, const uint256& hashPrevouts);
/** What a holder signs with P = B_ - Y: the house, the token, and its payout terms. Not bound to the tx, so any
 *  relayer can carry it; a token can be claimed once, so it can't be replayed. */
uint256 TokenClaimSigHash(uint32_t nHouseID, const uint256& y, const std::vector<unsigned char>& vchPayoutScript,
                          uint16_t nFeeBps, const std::vector<unsigned char>& vchRelayerScript);

/** A Cashu NUT-10 secret (a spending condition: P2PK, HTLC) - a JSON array. Such tokens can't claim. */
bool IsTokenConditionSecret(const std::vector<unsigned char>& vchSecret);

/** A claim's units after the pro-rata cut: amount x min(1, B / T), floored. */
uint64_t TokenClaimUnits(uint64_t nAmount, uint64_t nBase, uint64_t nClaimed);

/** The payout split of one claim's escrow entitlement: the relayer's share, floored; the holder gets the rest. */
CAmount TokenRelayerFee(const CAmount& amountEntitlement, uint16_t nFeeBps);

#endif // FREEBANK_TOKEN_H

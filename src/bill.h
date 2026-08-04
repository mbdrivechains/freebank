// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BILL_H
#define BITCOIN_BILL_H

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
class Coin;

//
// Bills of exchange (Phase 3.3).
//
// A bill is a unique, stateful credit instrument: identity is
// bill_id = sha256(encrypted_body) (consensus never decrypts the body), the
// drawee/acceptor posts a sidechain-native escrow bond at issue, ownership is
// a title UTXO advanced by endorsement, and the bill terminates Retired
// (drawee pays face to the current holder) or Defaulted (maturity + grace
// elapsed; the escrow pays out to the current holder).
//
// All constants are PROVISIONAL (B-1) - revisit at M1-package time.
//

// Bill operations carried by TRANSACTION_BILL_VERSION transactions
static const uint8_t BILL_OP_ISSUE   = 1;
static const uint8_t BILL_OP_ENDORSE = 2;
static const uint8_t BILL_OP_RETIRE  = 3;
static const uint8_t BILL_OP_CLAIM   = 4;
// Phase 3.9 (B1) - discounting. Spec: docs-local/PHASE3_9_DISCOUNT.md
// (operator-signed 2026-08-02). DISCOUNT is an endorsement FOR VALUE: it appends
// a real endorsement link and binds the consideration - the buying house's own
// notes, minted in the op - to the title transfer atomically, which is the one
// thing BILL_OP_ENDORSE lacks. HRETIRE/HCLAIM are the house-held twins of
// RETIRE/CLAIM: they carry the owning house id in the payload so the mempool
// slot guard can stay a pure memcpy, and they exit the loan book. RECOURSE is
// the dishonour cure - a liable party pays the holder and takes the position by
// subrogation, with no title spend and no holder signature.
static const uint8_t BILL_OP_DISCOUNT = 5;
static const uint8_t BILL_OP_RECOURSE = 6;
static const uint8_t BILL_OP_HRETIRE  = 7;
static const uint8_t BILL_OP_HCLAIM   = 8;

// On-chain bill status (Issued / Endorsed collapse to active)
static const char BILL_STATUS_ACTIVE    = 'a';
static const char BILL_STATUS_RETIRED   = 'r';
static const char BILL_STATUS_DEFAULTED = 'd';
// Reserved for the dispute module - not reachable in v1. PROVISIONAL (B-1 / D3)
static const char BILL_STATUS_DISPUTED  = 'x';

// Encrypted body size cap. PROVISIONAL (B-1)
static const size_t MAX_BILL_BODY_BYTES = 4096;

// Grace period: default and cap. PROVISIONAL (B-1, Tx-5)
static const uint32_t DEFAULT_BILL_GRACE_BLOCKS = 1008;
static const uint32_t MAX_BILL_GRACE_BLOCKS = 52560;

// Maturity may be at most this many blocks ahead of issuance (~10 years at
// 10-min blocks). Bounds the tenor to a sane range and — with the grace cap —
// keeps maturity_height + grace_blocks far below uint32 overflow. Consensus
// only enforces this outer bound; the ≤12-month real-bills discipline is
// app-layer. PROVISIONAL (B-1)
static const uint32_t MAX_BILL_TENOR_BLOCKS = 525600;

// Endorsement-chain DoS rule: fee doubles per endorsement past the soft cap,
// no hard cap. PROVISIONAL (B-1, Tx-4)
static const size_t BILL_ENDORSE_SOFT_CAP = 16;
static const CAmount BILL_ENDORSE_BASE_FEE = 10000;

// Value carried by the title (ownership) output - above dust. PROVISIONAL (B-1)
static const CAmount BILL_TITLE_VALUE = 10000;

// Endorsement record atHeight must be within this many blocks below the
// height it connects at (records stay accurate, txs survive small reorgs
// and mempool delay). PROVISIONAL (B-1)
static const uint32_t BILL_ENDORSE_HEIGHT_SLACK = 64;

// DISCOUNT payload ceiling: the M-of-N approver set plus up to MAX_ATTEST_PROOFS
// rho-at-mint reserve proofs. The house-payload cap precedent. PROVISIONAL (B-1)
static const size_t MAX_BILL_DISCOUNT_PAYLOAD = 16384;

// Ceiling for the ops 6-8 payloads (no proof sets, no approver-scale vectors
// beyond one quorum). PROVISIONAL (B-1)
static const size_t MAX_BILL_OP_PAYLOAD = 4096;

// A co-signed discount offer must expire, and may not be dated arbitrarily far
// ahead: a dangling co-signed authorization is a live grenade. PROVISIONAL (B-1)
static const uint32_t BILL_DISCOUNT_MAX_EXPIRY_AHEAD = 1008;

// Loan-book magnitude ceiling: a book cannot exceed the money supply at face.
// With every remaining term bounded by MAX_BILL_TENOR_BLOCKS this is what keeps
// the match-funding cross-multiplication inside u128 (house.h).
static const uint64_t LOAN_BOOK_MAX_FACE = (uint64_t)MAX_MONEY;

// CBill serialization discriminator (B1 OD-6). CBill has no version prefix and
// its first field is nBillID, a dense id assigned from 1 - so a sentinel value
// no live record can hold buys in-band versioning with NO disk-format bump and
// NO reindex.
//
// The encoding is CANONICAL-MINIMAL and that is load-bearing: a record whose
// nOwnerHouseID is 0 - every pre-B1 bill, and every bill not currently held by a
// house - is written in the EXACT legacy byte layout, so upgraded, reorged and
// fresh-synced nodes hold byte-identical records and the deep-reorg gate stays a
// STRICT byte compare (which is what catches u128 accumulator drift). Only a
// house-held bill takes the versioned layout.
static const uint32_t BILL_SER_SENTINEL = 0xFFFFFFFFU;
static const uint8_t BILL_SER_VERSION = 2;

/** One link of the endorsement chain (ARCH §4): signed over
 * (bill_id, to_pk, at_height) with a domain tag. */
struct BillEndorsement {
    std::vector<unsigned char> vchFrom;   // 33-byte compressed pubkey
    std::vector<unsigned char> vchTo;
    uint32_t nAtHeight;
    std::vector<unsigned char> vchSig;

    BillEndorsement() : nAtHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchFrom);
        READWRITE(vchTo);
        READWRITE(nAtHeight);
        READWRITE(vchSig);
    }
};

/** The consensus bill record persisted in BillDB. */
struct CBill {
    uint32_t nBillID;                             // dense id (BitAsset nID pattern); coin tags carry this
    uint256 billID;                               // sha256(encrypted_body) - canonical identity
    std::vector<unsigned char> vchEncryptedBody;  // opaque to consensus
    CAmount amount;                               // face, base-coin sats (D2)
    CAmount amountEscrow;                         // bond actually posted (issue vout[1] value)
    uint32_t nIssuedHeight;
    uint32_t nMaturityHeight;
    uint32_t nGraceBlocks;
    std::vector<unsigned char> vchDrawerPubKey;
    std::vector<unsigned char> vchAcceptorPubKey; // drawee; added to the Tx-9 set per D1
    std::vector<unsigned char> vchHolderPubKey;   // current holder
    std::vector<BillEndorsement> vEndorsement;
    char status;
    uint256 txidIssue;
    COutPoint outEscrow;                          // escrow_lock_ref, sidechain-native (D1)
    COutPoint outTitle;                           // current title (ownership) UTXO
    // Phase 3.9 (B1): 0 = not house-held; else the house holding this bill for
    // its own account. Written by BILL_OP_DISCOUNT, cleared by HRETIRE/HCLAIM.
    // While nonzero the bill is in exactly one house's loan book and the plain
    // ops 2/3/4 refuse to touch it, so a single custody key can move nothing.
    uint32_t nOwnerHouseID;

    CBill() : nBillID(0), amount(0), amountEscrow(0), nIssuedHeight(0),
              nMaturityHeight(0), nGraceBlocks(0), status(BILL_STATUS_ACTIVE),
              nOwnerHouseID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // Canonical-minimal versioning (B1 OD-6) - see BILL_SER_SENTINEL. This
        // is the ONE choke-point; no caller cooperation is required, and no
        // stream rewind is needed (on read we peek the first u32 and, when it is
        // not the sentinel, that value IS nBillID).
        uint8_t nSerVersion = 1;
        if (ser_action.ForRead()) {
            uint32_t nFirst = 0;
            READWRITE(nFirst);
            if (nFirst == BILL_SER_SENTINEL) {
                READWRITE(nSerVersion);
                if (nSerVersion < 2 || nSerVersion > BILL_SER_VERSION)
                    throw std::ios_base::failure("CBill: unknown serialization version");
                READWRITE(nBillID);
            } else {
                nBillID = nFirst;
            }
        } else {
            // Emit the legacy layout iff the record carries no post-legacy
            // state, so the on-disk bytes of an untouched bill never change.
            if (nOwnerHouseID != 0) {
                uint32_t nSentinel = BILL_SER_SENTINEL;
                nSerVersion = BILL_SER_VERSION;
                READWRITE(nSentinel);
                READWRITE(nSerVersion);
            }
            READWRITE(nBillID);
        }
        READWRITE(billID);
        READWRITE(vchEncryptedBody);
        READWRITE(amount);
        READWRITE(amountEscrow);
        READWRITE(nIssuedHeight);
        READWRITE(nMaturityHeight);
        READWRITE(nGraceBlocks);
        READWRITE(vchDrawerPubKey);
        READWRITE(vchAcceptorPubKey);
        READWRITE(vchHolderPubKey);
        READWRITE(vEndorsement);
        READWRITE(status);
        READWRITE(txidIssue);
        READWRITE(outEscrow);
        READWRITE(outTitle);
        if (nSerVersion >= 2) {
            READWRITE(nOwnerHouseID);
        } else if (ser_action.ForRead()) {
            nOwnerHouseID = 0;
        }
    }
};

//
// v11 trailer payloads, one per BILL_OP_*
//

struct BillIssue {
    std::vector<unsigned char> vchEncryptedBody;
    CAmount amount;                               // face
    uint32_t nMaturityHeight;
    uint32_t nGraceBlocks;
    std::vector<unsigned char> vchDrawerPubKey;
    std::vector<unsigned char> vchAcceptorPubKey;
    std::vector<unsigned char> vchHolderPubKey;
    std::vector<unsigned char> vchDrawerSig;      // over BillIssueSigHash
    std::vector<unsigned char> vchAcceptorSig;    // over BillIssueSigHash - this IS acceptance

    BillIssue() : amount(0), nMaturityHeight(0), nGraceBlocks(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vchEncryptedBody);
        READWRITE(amount);
        READWRITE(nMaturityHeight);
        READWRITE(nGraceBlocks);
        READWRITE(vchDrawerPubKey);
        READWRITE(vchAcceptorPubKey);
        READWRITE(vchHolderPubKey);
        READWRITE(vchDrawerSig);
        READWRITE(vchAcceptorSig);
    }
};

struct BillEndorse {
    uint32_t nBillID;
    BillEndorsement endorsement;

    BillEndorse() : nBillID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(endorsement);
    }
};

struct BillRetire {
    uint32_t nBillID;
    std::vector<unsigned char> vchAcceptorSig;    // over BillRetireSigHash

    BillRetire() : nBillID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(vchAcceptorSig);
    }
};

struct BillClaim {
    uint32_t nBillID;
    std::vector<unsigned char> vchHolderSig;      // over BillClaimSigHash

    BillClaim() : nBillID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(vchHolderSig);
    }
};

//
// Phase 3.9 (B1) payloads. Every one of them LEADS with nBillID, and the three
// that mutate house state carry the owning house id in bytes 4..8, so
// GetHouseSlotIDs stays a pure memcpy (the settle/oracle leading-8 contract).
//

/** DISCOUNT: a house purchases the bill from its current holder, paying in its
 * own notes minted by this transaction.
 *
 * amountFace / nBillMaturityHeight are the two bill facts every house delta is
 * computed from. They are payload-carried AND byte-exact-pinned to the record at
 * connect, which is what makes the crash-replay arm and the disconnect inverse
 * derivable from the payload ALONE - no DB read, no dependence on any mutable
 * field. (The first cut computed the delta "from the priors and the payload",
 * which was false once the book was valued at face: neither quantity was in the
 * payload at all.) Binding amountFace into the digest also means both parties
 * sign the face they believe they are trading. */
struct BillDiscount {
    uint32_t nBillID;                                     // LEADING
    uint32_t nHouseID;                                    // buying house (slot key)
    CAmount amountPrice;                                  // note-units; 0 < price <= amountFace
    CAmount amountFace;                                   // == bill.amount
    uint32_t nBillMaturityHeight;                         // == bill.nMaturityHeight
    uint16_t nNoteOutputs;                                // note coins at vout[1..nNoteOutputs]
    std::vector<uint64_t> vUnits;                         // parallel; sum == amountPrice
    std::vector<unsigned char> vchCustodyPubKey;          // 33B; == house.vchRedemptionDestPK
    uint32_t nExpiryHeight;                               // mandatory nonzero, bounded ahead
    uint32_t nAsOfHeight;                                 // rho-at-mint liveness (R-i7 / DR-1)
    std::vector<AttestProof> vReserveProofs;              // 1..MAX_ATTEST_PROOFS, never empty
    uint64_t nPrevMintedUnits;                            // undo priors, one per mutated field
    uint64_t nPrevLoanBookFace;
    uint64_t nPrevLoanWtMatHi;
    uint64_t nPrevLoanWtMatLo;
    BillEndorsement endorsement;                          // from = seller, to = custody key;
                                                          // its stored sig is the CLASSIC
                                                          // BillEndorseSigHash, so the chain
                                                          // stays verifiable from CBill alone
    std::vector<unsigned char> vchSellerSig;              // over BillDiscountSigHash (excluded)
    std::vector<uint32_t> vApproverIndex;                 // strictly ascending (excluded)
    std::vector<std::vector<unsigned char>> vApproverSig; // house M-of-N over the SAME digest

    BillDiscount() : nBillID(0), nHouseID(0), amountPrice(0), amountFace(0),
                     nBillMaturityHeight(0), nNoteOutputs(0), nExpiryHeight(0),
                     nAsOfHeight(0), nPrevMintedUnits(0), nPrevLoanBookFace(0),
                     nPrevLoanWtMatHi(0), nPrevLoanWtMatLo(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(nHouseID);
        READWRITE(amountPrice);
        READWRITE(amountFace);
        READWRITE(nBillMaturityHeight);
        READWRITE(nNoteOutputs);
        READWRITE(vUnits);
        READWRITE(vchCustodyPubKey);
        READWRITE(nExpiryHeight);
        READWRITE(nAsOfHeight);
        READWRITE(vReserveProofs);
        READWRITE(nPrevMintedUnits);
        READWRITE(nPrevLoanBookFace);
        READWRITE(nPrevLoanWtMatHi);
        READWRITE(nPrevLoanWtMatLo);
        READWRITE(endorsement);
        READWRITE(vchSellerSig);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** RECOURSE: a liable party pays the current holder and takes the position by
 * subrogation. Payment is base coin to P2PKH(holder) - no title spend and no
 * holder signature, which is the uncooperative-holder answer.
 *
 * Legal ONLY on a bill that is not house-held, so it mutates NO house record,
 * takes NO house slot and carries NO house priors. That restriction is what
 * stops a single custody key from paying itself and walking an asset out of the
 * house's loan book, bypassing HCLAIM's quorum - and it puts the cure in the
 * historical cascade order: drawee, then escrow, then the endorser chain. */
struct BillRecourse {
    uint32_t nBillID;                                     // LEADING
    std::vector<unsigned char> vchPayerPubKey;            // in the liable set, != holder
    std::vector<unsigned char> vchPrevHolderPubKey;       // prior; == bill.vchHolderPubKey
    std::vector<unsigned char> vchPayerSig;               // over BillRecourseSigHash

    BillRecourse() : nBillID(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(vchPayerPubKey);
        READWRITE(vchPrevHolderPubKey);
        READWRITE(vchPayerSig);
    }
};

/** HRETIRE: the drawee retires a HOUSE-HELD bill. The digest is the shipped
 * BillRetireSigHash - cross-op replay is dead because op 3 rejects house-held
 * bills and op 7 requires them, and the bound hashOutputs must pay the pinned
 * custody key. Valid at EVERY owner-house status, including effective-Insolvent:
 * the drawee must always be able to discharge its debt. */
struct BillHRetire {
    uint32_t nBillID;                                     // LEADING
    uint32_t nOwnerHouseID;                               // == bill.nOwnerHouseID (slot key)
    CAmount amountFace;                                   // == bill.amount (book delta)
    uint32_t nBillMaturityHeight;                         // == bill.nMaturityHeight
    uint64_t nPrevLoanBookFace;                           // undo priors
    uint64_t nPrevLoanWtMatHi;
    uint64_t nPrevLoanWtMatLo;
    std::vector<unsigned char> vchAcceptorSig;            // over BillRetireSigHash

    BillHRetire() : nBillID(0), nOwnerHouseID(0), amountFace(0), nBillMaturityHeight(0),
                    nPrevLoanBookFace(0), nPrevLoanWtMatHi(0), nPrevLoanWtMatLo(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(nOwnerHouseID);
        READWRITE(amountFace);
        READWRITE(nBillMaturityHeight);
        READWRITE(nPrevLoanBookFace);
        READWRITE(nPrevLoanWtMatHi);
        READWRITE(nPrevLoanWtMatLo);
        READWRITE(vchAcceptorSig);
    }
};

/** HCLAIM: the owning house takes the escrow on default. The house quorum
 * REPLACES the single holder signature - the custody key alone must never direct
 * the escrow payout, nor take a bill out of the book. */
struct BillHClaim {
    uint32_t nBillID;                                     // LEADING
    uint32_t nOwnerHouseID;                               // == bill.nOwnerHouseID (slot key)
    CAmount amountFace;
    uint32_t nBillMaturityHeight;
    uint64_t nPrevLoanBookFace;
    uint64_t nPrevLoanWtMatHi;
    uint64_t nPrevLoanWtMatLo;
    std::vector<uint32_t> vApproverIndex;                 // strictly ascending
    std::vector<std::vector<unsigned char>> vApproverSig; // M-of-N over BillClaimSigHash

    BillHClaim() : nBillID(0), nOwnerHouseID(0), amountFace(0), nBillMaturityHeight(0),
                   nPrevLoanBookFace(0), nPrevLoanWtMatHi(0), nPrevLoanWtMatLo(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nBillID);
        READWRITE(nOwnerHouseID);
        READWRITE(amountFace);
        READWRITE(nBillMaturityHeight);
        READWRITE(nPrevLoanBookFace);
        READWRITE(nPrevLoanWtMatHi);
        READWRITE(nPrevLoanWtMatLo);
        READWRITE(vApproverIndex);
        READWRITE(vApproverSig);
    }
};

/** Round-1 blob of the discount ceremony (T-d7): the SELLER's offer, carried
 * out-of-band to the buying house. UNSIGNED and advisory, exactly like
 * SettleProposalV1 - and for the same reason. The shared digest binds
 * hashPrevouts and hashOutputs, so no party can sign until the transaction is
 * complete, and the house is the only side able to complete it. The seller's
 * protection is therefore not in this blob at all: it is that round 3
 * re-verifies every term against the chain before it signs anything.
 *
 * It is a wallet-layer message and never touches consensus - nothing here is
 * serialized into a transaction. outTitle is carried so the house need not trust
 * its own view of who holds the bill, and is re-checked against the record. */
struct DiscountProposalV1 {
    uint8_t nVersion;                             // = 1
    uint32_t nBillID;
    uint32_t nHouseID;                            // the house asked to buy
    CAmount amountPrice;                          // note-units offered; 0 < price <= face
    std::vector<unsigned char> vchSellerPubKey;   // == bill.vchHolderPubKey
    COutPoint outTitle;                           // == bill.outTitle
    uint32_t nExpiryHeight;

    DiscountProposalV1() : nVersion(1), nBillID(0), nHouseID(0), amountPrice(0),
                           nExpiryHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(nBillID);
        READWRITE(nHouseID);
        READWRITE(amountPrice);
        READWRITE(vchSellerPubKey);
        READWRITE(outTitle);
        READWRITE(nExpiryHeight);
    }
};

/** bill_id = single sha256 of the encrypted body (ARCH §4). */
uint256 BillIDFromBody(const std::vector<unsigned char>& vchBody);

//
// Domain-separated signature messages. The legacy input sighash does not
// cover v11 trailer fields, so every payload field a party relies on MUST be
// bound by one of these payload-level signatures.
//
uint256 BillIssueSigHash(const uint256& billID, const CAmount& amount, const CAmount& amountEscrow, uint32_t nMaturityHeight, uint32_t nGraceBlocks, const std::vector<unsigned char>& vchDrawerPubKey, const std::vector<unsigned char>& vchAcceptorPubKey, const std::vector<unsigned char>& vchHolderPubKey);
uint256 BillEndorseSigHash(const uint256& billID, const std::vector<unsigned char>& vchTo, uint32_t nAtHeight);

// Retire / claim spend the escrow coin with an EMPTY scriptSig, so nothing
// else pins the transaction's outputs - these signatures bind hashOutputs
// (BIP143-style) or a miner could replay them into a transaction paying
// itself.
uint256 BillHashOutputs(const CTransaction& tx);
uint256 BillRetireSigHash(const uint256& billID, const uint256& hashOutputs);
uint256 BillClaimSigHash(const uint256& billID, const uint256& hashOutputs);

/** SHA256d over every input outpoint of tx - bound into the B1 digests (the R-i6
 * rule: bind prevouts wherever a payload signature authorizes a spend). */
uint256 BillHashPrevouts(const CTransaction& tx);

//
// B1 digests. Both serialize every VALUE field of their payload in declaration
// order (sig and approver-index fields excluded, so signatures can land after
// transaction assembly), then hashPrevouts, then hashOutputs. One shared digest
// per op carries every authority: for DISCOUNT the seller AND the house quorum
// sign the same bytes, so neither side can alter any term after the other signs.
//
uint256 BillDiscountSigHash(const BillDiscount& x, const uint256& billID,
                            const uint256& hashPrevouts, const uint256& hashOutputs);
uint256 BillRecourseSigHash(const BillRecourse& x, const uint256& billID,
                            const uint256& hashPrevouts, const uint256& hashOutputs);

/** The escrow output script: <bill_id> OP_DROP OP_TRUE - open at script
 * layer, locked by the consensus spend rules on fBillEscrow coins. */
CScript BillEscrowScript(const uint256& billID);
bool IsBillEscrowScript(const CScript& script);

/** P2PKH script for a compressed pubkey (payments to holder / title outputs). */
CScript BillScriptForPubKey(const std::vector<unsigned char>& vchPubKey);

/** Deserialize a v11 trailer payload; false on failure or trailing bytes. */
template <typename T>
bool DecodeBillPayload(const std::vector<unsigned char>& vch, T& payload);

/** PAYLOAD-PURE tagger for a v11 output: sets fBill / fBillEscrow / fNote on
 * vout[n] and nothing else. The dense bill id is deliberately NOT set - it only
 * exists once the issuing transaction connects - so callers that have it
 * (AddCoins) overwrite it afterwards and callers that do not (the mempool view,
 * the wallet) get id 0, which fails closed.
 *
 * ONE decision point, shared by consensus tagging, the mempool view, the
 * wallet's funding skip and the wallet's note collector - the ApplyPoolCoinTags
 * discipline. Four separate enumerations of "which v11 outputs are tagged" is
 * how a discount's minted notes end up offered as fee coins, which is the fifth
 * recurrence of a class this codebase has already been bitten by four times
 * (wallet.cpp:2305-2313). `bill_coin_tagger_matches_addcoins` pins the tagger
 * against AddCoins for every op and index. */
void ApplyBillCoinTags(const CTransaction& tx, uint32_t n, Coin& coin);

/** Context-free checks for a v11 transaction (shape, sizes, payload
 * signatures). Called from CheckTransaction. */
bool CheckBillTransactionShape(const CTransaction& tx, CValidationState& state);

/** Sum of tx outputs paying P2PKH(vchPubKey). */
CAmount BillValuePaidTo(const CTransaction& tx, const std::vector<unsigned char>& vchPubKey);

/** The consensus fee floor for an endorsement making the chain nLen long.
 * PROVISIONAL (B-1, Tx-4): base fee doubles per endorsement past the soft cap. */
CAmount BillEndorseFeeFloor(size_t nLen);

#endif // BITCOIN_BILL_H

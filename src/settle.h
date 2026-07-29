// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SETTLE_H
#define BITCOIN_SETTLE_H

// Phase 3.7 part 2 - SETTLEMENT / PAR-ATTRACTOR (Phase A): SETTLE_EXCHANGE.
// Design: docs-local/PHASE3_7_SETTLEMENT.md (operator-signed 2026-07-26).
//
// Settlement is a TRANSACTION, not an epoch. Two par-eligible houses co-sign
// one v16 tx: each presents an exact-sum bundle of the OTHER's notes; both
// bundles burn (REDEEM semantics - the counters only ever move against real
// spent coins), both nMintedUnits fall, and the net difference is paid in
// base coin at par +/- SETTLE_PAR_BAND_BPS to the creditor house's declared
// vchRedemptionDestPK. Par needs no oracle: 1 note-unit face = 1 sat is
// consensus canon. Nothing here is block-periodic (cadence is an eligibility
// comparison against CHouse.nLastSettleHeight, never a sweep) and NO v16
// consensus path reads, writes or spends pool state - LP neutrality is
// structural, not policed.
//
// Op namespace: EXCHANGE is the only Phase-A op. PRESENT (unilateral
// presentment) and DRAW (the consensus-drawable response once Phase B escrows
// reserves) are RESERVED here so the Phase-B rails have their numbers.

#include <amount.h>
#include <serialize.h>
#include <uint256.h>

#include <stdint.h>
#include <vector>

class CTransaction;

static const uint8_t SETTLE_OP_EXCHANGE = 1;   // bilateral co-signed par-exchange (Phase A)
// static const uint8_t SETTLE_OP_PRESENT = 2; // RESERVED - Phase B unilateral presentment
// static const uint8_t SETTLE_OP_DRAW    = 3; // RESERVED - Phase B escrowed-reserve response

// The residual band around par, basis points. Par is 1 unit = 1 sat; a mode-1
// residual must satisfy |dU|*(10^4 - band) <= residual*10^4 <= |dU|*(10^4 + band).
// PROVISIONAL (P-2, ARCH s8's +/-0.5%): NOT sim-validated - OQ-SIM-SETTLE owns
// this number before any mainnet parameter lock.
static const uint32_t SETTLE_PAR_BAND_BPS = 50;

// Minimum mode-1 residual, sats. Below this the pair should equalize to mode 0
// via note-splitting; +/-0.5% of dust is sub-sat noise. PROVISIONAL (P-2).
static const CAmount SETTLE_MIN_RESIDUAL = 10000;

// Per-house settlement cadence, blocks: a house may enter at most one exchange
// per window (nLastSettleHeight + cadence <= height). An eligibility comparison,
// never a sweep - nothing happens ON a schedule; the schedule gates when
// parties may act. Per-network: Consensus::Params::nSettleCadence (main 144,
// regtest 12). Consensus-critical, deliberately NOT runtime-settable — the
// HOUSE_ATTEST_CADENCE -attestcadence pattern is a fork hazard; do not copy
// it. PROVISIONAL sizing (P-2; Scottish twice-weekly ~ 504).

// Max note inputs per presented bundle (bounds per-tx loops; the wallet
// consolidates to typically one coin per side first). MAX_POOL_LP_INPUTS scale.
static const size_t SETTLE_MAX_BUNDLE_INPUTS = 100;

// Payload ceiling (largest realistic op: 2 presenter keys + 2 sigs + 2 full
// M-of-N approver sets ~ 2.5KB at 15 partners each).
static const size_t MAX_SETTLE_PAYLOAD = 4096;

// Magnitude ceiling for presented units - the shared overflow envelope
// (== POOL_MAX_AMOUNT; equality is static_asserted in settle_tests.cpp).
// units <= 3*MAX_MONEY < 2^53, so units*(10^4 + band) < 2^67 -> the band
// arithmetic MUST run u128 (principle 5: every consensus multiplication
// carries its named ceiling and a max-magnitude test vector).
static const uint64_t SETTLE_MAX_UNITS = (uint64_t)3 * (uint64_t)MAX_MONEY;

/** SETTLE_OP_EXCHANGE payload. Canonical ordering nHouseA < nHouseB
 * (structurally bans self-exchange); the two house ids are the LEADING 8
 * bytes so ATMP guards can identify both houses by memcpy of the decoded
 * prefix (the pool nPoolID-leading precedent).
 *
 * Naming: nUnitsANotes = units of A-ISSUED notes presented (held/presented by
 * B's side from vchPresentKeyOfANotes); mirrored for B. Direction rule:
 * dU = nUnitsANotes - nUnitsBNotes; dU > 0 means more of A's paper came home,
 * A is net debtor, the residual flows to B's vchRedemptionDestPK (and mirror).
 * nMode == (dU != 0): 0 = pure swap, 1 = residual.
 *
 * Prior-state binding (ATTEST pattern): one nPrev* per mutated house field,
 * BOTH houses - connect requires them equal to the DB byte-exact, so
 * DisconnectBlock restores from the payload alone and any replay is
 * structurally invalid.
 *
 * Authorization = four signatures over ONE shared digest (SettleExchangeSigHash:
 * every value field in declaration order, sig/index fields excluded, plus
 * hashPrevouts + hashOutputs): both houses' M-of-N approver quorums
 * (VerifyHouseApprovers - parallel index/sig vectors, the chassis M-of-N form)
 * and both presentment-key holder sigs. Approver indices ride OUTSIDE the
 * digest (chassis form): a sig moved to another index fails ECDSA against that
 * partner's key, so binding them would be redundant. */
struct SettleExchange {
    uint32_t nHouseA;                                     // LEADING; lower dense id
    uint32_t nHouseB;                                     // higher dense id
    uint8_t nMode;                                        // 0 = pure swap (dU==0), 1 = residual
    uint64_t nUnitsANotes;                                // A-issued units presented, >= 1
    uint64_t nUnitsBNotes;                                // B-issued units presented, >= 1
    uint16_t nCountANotes;                                // vin bundle sizes
    uint16_t nCountBNotes;
    std::vector<unsigned char> vchPresentKeyOfANotes;     // 33B; holds the A-note bundle
    std::vector<unsigned char> vchPresentKeyOfBNotes;     // 33B; holds the B-note bundle
    CAmount amountResidual;                               // mode 1 only (else 0); == vout[0].nValue
    uint64_t nPrevMintedUnitsA;                           // priors, ATTEST pattern
    uint64_t nPrevMintedUnitsB;
    uint32_t nPrevLastSettleHeightA;
    uint32_t nPrevLastSettleHeightB;
    uint32_t nExpiryHeight;                               // 0 = none; wallet default tip+72
    std::vector<unsigned char> vchPresentSigOfANotes;     // holder sigs (excluded from digest)
    std::vector<unsigned char> vchPresentSigOfBNotes;
    std::vector<uint32_t> vApproverIndexA;                // strictly ascending (excluded from digest)
    std::vector<std::vector<unsigned char>> vApproverSigA;
    std::vector<uint32_t> vApproverIndexB;
    std::vector<std::vector<unsigned char>> vApproverSigB;

    SettleExchange() : nHouseA(0), nHouseB(0), nMode(0), nUnitsANotes(0), nUnitsBNotes(0),
                       nCountANotes(0), nCountBNotes(0), amountResidual(0),
                       nPrevMintedUnitsA(0), nPrevMintedUnitsB(0),
                       nPrevLastSettleHeightA(0), nPrevLastSettleHeightB(0), nExpiryHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nHouseA);
        READWRITE(nHouseB);
        READWRITE(nMode);
        READWRITE(nUnitsANotes);
        READWRITE(nUnitsBNotes);
        READWRITE(nCountANotes);
        READWRITE(nCountBNotes);
        READWRITE(vchPresentKeyOfANotes);
        READWRITE(vchPresentKeyOfBNotes);
        READWRITE(amountResidual);
        READWRITE(nPrevMintedUnitsA);
        READWRITE(nPrevMintedUnitsB);
        READWRITE(nPrevLastSettleHeightA);
        READWRITE(nPrevLastSettleHeightB);
        READWRITE(nExpiryHeight);
        READWRITE(vchPresentSigOfANotes);
        READWRITE(vchPresentSigOfBNotes);
        READWRITE(vApproverIndexA);
        READWRITE(vApproverSigA);
        READWRITE(vApproverIndexB);
        READWRITE(vApproverSigB);
    }
};

/** SHA256d over every input outpoint of tx - bound into the settle digest
 * (the R-i6 rule: bind prevouts wherever a payload signature authorizes). */
uint256 SettleHashPrevouts(const CTransaction& tx);

/** The ONE shared digest all four signatures cover: domain tag, every value
 * field of the payload in declaration order (sig/index fields excluded),
 * hashPrevouts, hashOutputs. Atomic mutual consent - neither side can alter
 * any term after the other signs. */
uint256 SettleExchangeSigHash(const SettleExchange& x, const uint256& hashPrevouts,
                              const uint256& hashOutputs);

/** Payload-pure residual band check (consensus s4 check 6; NO DB read - par
 * is 1:1 by canon). For dU = nUnitsANotes - nUnitsBNotes:
 *   mode 0: dU == 0 and amountResidual == 0;
 *   mode 1: |dU| >= SETTLE_MIN_RESIDUAL and
 *           |dU|*(10^4 - band) <= amountResidual*10^4 <= |dU|*(10^4 + band).
 * All arithmetic u128 under the SETTLE_MAX_UNITS envelope (callers must have
 * shape-checked units <= SETTLE_MAX_UNITS and amountResidual in [0, MAX_MONEY]
 * first; the helper additionally hard-bounds both). */
bool SettleResidualInBand(uint64_t nUnitsANotes, uint64_t nUnitsBNotes,
                          uint8_t nMode, CAmount amountResidual);

template <typename T>
bool DecodeSettlePayload(const std::vector<unsigned char>& vch, T& payload);

class CValidationState;

#include <primitives/transaction.h>   // COutPoint (wallet-protocol blob below)

/** Round-1 blob of the two-round wallet ceremony (proposesettle -> signsettle
 * -> completesettle). WALLET PROTOCOL, NOT CONSENSUS - versioned so it can
 * evolve freely. The initiator (the CREDITOR-to-be, or either side of a pure
 * swap) exports its half: which paper it presents (counterparty-issued notes
 * it holds, consolidated on ONE key) and under what expiry. The responder -
 * who must turn out to be the DEBTOR, because only the debtor's wallet can
 * fund the residual and finalize the tx skeleton the SIGHASH_ALL scriptSigs
 * bind - assembles the full transaction. Mechanical soundness note: the P2PKH
 * signature hash covers version/vin/vout/locktime but NOT the op trailer, so
 * the initiator's payload signatures can land AFTER the responder's scriptSigs
 * without breaking them (and the shared payload digest excludes sig fields for
 * the same reason). */
struct SettleProposalV1 {
    uint8_t nVersion;                          // = 1
    uint32_t nHouseInitiator;
    uint32_t nHouseCounterparty;
    uint64_t nUnitsPresented;                  // counterparty-ISSUED units the initiator presents
    std::vector<unsigned char> vchPresentKey;  // the ONE key holding that bundle
    std::vector<COutPoint> vBundle;            // the exact coins (sum == nUnitsPresented)
    uint32_t nExpiryHeight;

    SettleProposalV1() : nVersion(1), nHouseInitiator(0), nHouseCounterparty(0),
                         nUnitsPresented(0), nExpiryHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nVersion);
        READWRITE(nHouseInitiator);
        READWRITE(nHouseCounterparty);
        READWRITE(nUnitsPresented);
        READWRITE(vchPresentKey);
        READWRITE(vBundle);
        READWRITE(nExpiryHeight);
    }
};

/** Context-free shape rules for v16 settle txs (no DB, no ECDSA - priors,
 * eligibility, cadence, approver ranges and all signature verification run
 * contextually in CheckSettleOperation, DoS pricing). Decode-exact payload,
 * canonical house order, unit/bundle bounds, key/sig well-formedness,
 * mode/band arithmetic (payload-pure - par is 1:1), and the mode-1 residual
 * output pinned at vout[0]. */
bool CheckSettleTransactionShape(const CTransaction& tx, CValidationState& state);

#endif // BITCOIN_SETTLE_H

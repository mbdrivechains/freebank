// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ORACLE_H
#define BITCOIN_ORACLE_H

// Phase G-1 - THE GOLD ORACLE, CONSENSUS-INERT (spec v2, reviewed 2026-07-27:
// docs-local/PHASE_GOLD_ORACLE.md; params: docs-local/GOLD_PARAMS_PROPOSAL.md,
// operator-signed 2026-07-27).
//
// One bonded price stream, two derived views. RAW = lower median of the
// block's valid submissions from >= nOracleQuorumMin DISTINCT submitters (a
// ConnectBlock rule - ATMP guards are convenience, never the defense).
// BRAKED = asymmetric brake: rises track raw immediately, falls are bounded
// per elapsed block (capped) - the G4-F1 trigger-view crash filter.
//
// INERT BY DESIGN: no consensus path outside this module and its RPCs may
// read the fix. Promotion to a live denomination input is a separate,
// operator-gated hard fork. There is deliberately NO max-age validity rule
// anywhere (params row 6: redemption never halts on staleness - implemented
// as the ABSENCE of a rule, so nothing exists to inherit wrongly).
//
// State shape (the D3 lazy-chassis rule): store heights, derive everything.
// No sweeps, no per-block counters - fix age and submitter liveness are
// DERIVED from {nFixHeight, nLastSubmitHeight} at read. Blocks without v17
// ops write nothing.

#include <amount.h>
#include <primitives/transaction.h>   // COutPoint (bond outpoints, in payloads AND records)
#include <serialize.h>
#include <uint256.h>

#include <stdint.h>
#include <vector>

class CTransaction;

static const uint8_t ORACLE_OP_BOND = 1;     // escrow bond + register/top a submitter key
static const uint8_t ORACLE_OP_SUBMIT = 2;   // one bonded price observation, one per block

// VALIDITY WINDOW (operator-signed 2026-07-28, ORACLE_WINDOW_PROPOSAL.md).
// nTargetHeight is the FIRST height at which an op may connect; it stays valid
// for Consensus::Params::nOracleOpWindow heights (main 6, regtest 3, floor 2).
// Why not a single height: under BMM, RefreshBMM connects the committed
// candidate and templates the NEXT one inside one call, so an op that can only
// be signed after observing tip H always arrives after the H+1 candidate is
// frozen - a one-height rule starved the oracle outright rather than merely
// losing races. Replay is NOT held by the height rule: nPrevOwnLastSubmitHeight
// makes each signed payload single-use per branch regardless (see below), which
// is why widening was cheap. Cross-branch reuse stays closed because
// hashPrevBlockBind is checked as an ANCESTOR at nTargetHeight-1 on the
// connecting branch. QUORUM IS STILL PER BLOCK: the window keeps an op alive,
// it does NOT keep a batch together - submitters that scatter across blocks are
// each credited for liveness while no fix ever forms.

// Price unit: MILLIGRAMS OF GOLD PER 1000 ECX (the sims' P convention: up =
// ECX-up/gold-down; the G3-F4/G4-F1 brake direction is stated against this).
// The promotion-time payout side consumes the INVERSE (ECX per gram); the
// conversion identity and both rounding directions carry unit vectors in
// oracle_tests. Envelope: zero is invalid (absorbing under a multiplicative
// brake; division hazard at promotion); the ceiling is the POOL/SETTLE u128
// envelope class - every consensus multiplication against it carries a
// max-magnitude vector (principle 5).
static const uint64_t ORACLE_PRICE_MIN = 1;
static const uint64_t ORACLE_PRICE_MAX = ((uint64_t)1 << 53) - 1;

// Payload ceiling (largest realistic op: BOND with pubkey + sig + priors).
static const size_t MAX_ORACLE_PAYLOAD = 512;

// Brake units: parts-per-million of the braked value, per elapsed block,
// with elapsed capped at Consensus::Params::nOracleBrakeElapsedCap (one
// nominal day) - bounds BOTH review-named failure modes [B-1]: a censoring
// sequencer can bank at most one day's fall headroom, and outage recovery
// converges at the simmed daily rate. The fall step is max(1 unit, floor(.))
// so integer floor can never freeze the view above raw permanently [B-2].
// (The constants themselves live in chainparams - the nSettleCadence
// precedent; consensus-critical, deliberately NOT runtime-settable.)

/** ORACLE_OP_SUBMIT payload. Leading 8 bytes = {nSubmitterID, nTargetHeight}
 * (the version-wide memcpy guard contract [F-2pat]: dense u32 id assigned by
 * BOND at connect - 33-byte pubkeys are un-memcpy-able as guard keys).
 *
 * Prior-state binding (ATTEST pattern, one nPrev* per mutated field): all
 * submissions in one block legitimately bind the SAME pre-block fix state
 * (the median applies post-loop); connect requires byte-exact equality, so
 * DisconnectBlock restores from any one payload alone. The braked view is
 * path-dependent (asym clamp) and is only restorable BECAUSE it is bound
 * here. Genesis binding is context-free-checkable: nPrevFixHeight == 0 iff
 * both prev views are 0.
 *
 * hashPrevBlockBind: the digest AND payload carry the parent block hash -
 * branch binding kills the sequencer's stale-vs-fresh selection option
 * across reorgs [C-5/F-4fid]; submitters re-sign every block anyway.
 * Authorization = one submitter sig over OracleSubmitSigHash (every value
 * field in declaration order, sig excluded, plus hashPrevouts + hashOutputs
 * - the R-i6 rule - and the branch bind). */
struct OracleSubmit {
    uint32_t nSubmitterID;                     // LEADING; dense id, >= 1
    uint32_t nTargetHeight;                    // FIRST height at which this may
                                               //   connect; valid through
                                               //   +nOracleOpWindow-1 (see the
                                               //   window note at the top)
    uint64_t nPriceMilligrams;                 // mg gold per 1000 ECX, in envelope
    uint64_t nPrevRaw;                         // priors, ATTEST pattern
    uint64_t nPrevBraked;
    uint32_t nPrevFixHeight;
    uint32_t nPrevOwnLastSubmitHeight;         // ALSO the single-use mechanism:
                                               //   bumped on every inclusion, so
                                               //   at most ONE of a submitter's
                                               //   outstanding payloads can ever
                                               //   connect per branch
    uint256 hashPrevBlockBind;                 // hash of the block at
                                               //   nTargetHeight-1 on the
                                               //   CONNECTING branch (the signing
                                               //   tip) - an ancestry check, not
                                               //   an immediate-parent equality
    std::vector<unsigned char> vchSig;         // submitter sig (excluded from digest)

    OracleSubmit() : nSubmitterID(0), nTargetHeight(0), nPriceMilligrams(0),
                     nPrevRaw(0), nPrevBraked(0), nPrevFixHeight(0),
                     nPrevOwnLastSubmitHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSubmitterID);
        READWRITE(nTargetHeight);
        READWRITE(nPriceMilligrams);
        READWRITE(nPrevRaw);
        READWRITE(nPrevBraked);
        READWRITE(nPrevFixHeight);
        READWRITE(nPrevOwnLastSubmitHeight);
        READWRITE(hashPrevBlockBind);
        READWRITE(vchSig);
    }
};

/** ORACLE_OP_BOND payload. Leading 8 bytes = {nSubmitterID, nTargetHeight}:
 * a FRESH registration carries nSubmitterID == 0 (the dense id is assigned
 * at connect, house-charter precedent; at most one fresh bond per block via
 * the id-0 guard slot); a RETURNING id re-bond carries its id and the priors
 * of the record it overwrites [C-3]. The registered key must prove
 * possession: vchSig over OracleBondSigHash (R-i6: binds prevouts/outputs -
 * the bond coins themselves authorize via their own scriptSigs, the sig here
 * binds the KEY to this registration). */
struct OracleBond {
    uint32_t nSubmitterID;                     // LEADING; 0 = fresh registration
    uint32_t nTargetHeight;                    // registration intent height
    std::vector<unsigned char> vchSubmitterPubKey;  // 33B compressed
    uint32_t nPrevBondHeight;                  // priors (returning id; 0 for fresh)
    uint32_t nPrevLastSubmitHeight;
    uint32_t nPrevUnbondRequestHeight;
    COutPoint outPrevBond;                     // the record's bond outpoint being
                                               //   overwritten; null for fresh.
                                               //   EVERY mutated field must be
                                               //   payload-bound or disconnect
                                               //   cannot restore it - this one
                                               //   was the sole exception, and a
                                               //   reorg left the record pointing
                                               //   at a coin that no longer exists.
    std::vector<unsigned char> vchSig;         // possession proof (excluded from digest)

    OracleBond() : nSubmitterID(0), nTargetHeight(0), nPrevBondHeight(0),
                   nPrevLastSubmitHeight(0), nPrevUnbondRequestHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSubmitterID);
        READWRITE(nTargetHeight);
        READWRITE(vchSubmitterPubKey);
        READWRITE(nPrevBondHeight);
        READWRITE(nPrevLastSubmitHeight);
        READWRITE(nPrevUnbondRequestHeight);
        READWRITE(outPrevBond);
        READWRITE(vchSig);
    }
};

/** The two-view fix record. Ser-version discipline from day one: version
 * byte leads; reads hard-fail on newer-than-known (the house v7 pattern).
 * Fix AGE is never stored - it is tipHeight - nFixHeight at read. */
static const uint8_t ORACLE_FIX_SER_VERSION = 1;
struct CGoldFix {
    uint64_t nRaw;                             // lower median, last quorum block
    uint64_t nBraked;                          // asym-braked view
    uint32_t nFixHeight;                       // block that set it

    CGoldFix() : nRaw(0), nBraked(0), nFixHeight(0) {}
    bool IsNull() const { return nFixHeight == 0; }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint8_t nSerVersion = ORACLE_FIX_SER_VERSION;
        READWRITE(nSerVersion);
        if (nSerVersion > ORACLE_FIX_SER_VERSION)
            throw std::ios_base::failure("CGoldFix: record version newer than this node");
        READWRITE(nRaw);
        READWRITE(nBraked);
        READWRITE(nFixHeight);
    }
};

/** Registered submitter. Liveness is DERIVED from nLastSubmitHeight at read
 * (misses are sequencer-poisonable and are telemetry, never scaffold-era
 * slashing evidence - spec s4). */
static const uint8_t ORACLE_SUBMITTER_SER_VERSION = 1;

struct COracleSubmitter {
    uint32_t nSubmitterID;
    std::vector<unsigned char> vchPubKey;      // 33B compressed
    COutPoint bondOutpoint;
    uint32_t nBondHeight;
    uint32_t nLastSubmitHeight;                // 0 = never; updates on EVERY
                                               //   included submission, quorum
                                               //   or not [A-3 pinned]
    uint32_t nUnbondRequestHeight;             // 0 = none pending

    COracleSubmitter() : nSubmitterID(0), nBondHeight(0), nLastSubmitHeight(0),
                         nUnbondRequestHeight(0) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint8_t nSerVersion = ORACLE_SUBMITTER_SER_VERSION;
        READWRITE(nSerVersion);
        if (nSerVersion > ORACLE_SUBMITTER_SER_VERSION)
            throw std::ios_base::failure("COracleSubmitter: record version newer than this node");
        READWRITE(nSubmitterID);
        READWRITE(vchPubKey);
        READWRITE(bondOutpoint);
        READWRITE(nBondHeight);
        READWRITE(nLastSubmitHeight);
        READWRITE(nUnbondRequestHeight);
    }
};

/** SHA256d over every input outpoint of tx (the settle pattern; R-i6). */
uint256 OracleHashPrevouts(const CTransaction& tx);

/** The submit digest: domain tag, every value field in declaration order
 * (sig excluded), hashPrevouts, hashOutputs. hashPrevBlockBind rides as a
 * value field - branch binding is part of what the signature authorizes. */
uint256 OracleSubmitSigHash(const OracleSubmit& x, const uint256& hashPrevouts,
                            const uint256& hashOutputs);

/** The bond digest: domain tag, value fields, prevouts/outputs. */
uint256 OracleBondSigHash(const OracleBond& x, const uint256& hashPrevouts,
                          const uint256& hashOutputs);

/** Lower median: element (n-1)/2 of the sorted value multiset [A-2].
 * Deterministic, duplicate-proof, no averaging, no overflow. Caller
 * guarantees non-empty. */
uint64_t OracleLowerMedian(std::vector<uint64_t> vPrices);

/** The asymmetric brake [G4-F1 wiring, B-1/B-2 arithmetic]: given the prior
 * braked view, the new raw, elapsed blocks since the last accepted fix, the
 * per-block ppm rate and the elapsed cap - returns the next braked view.
 * Rises: braked := raw immediately. Falls: bounded to
 *   step = max(1, braked * ppm * min(elapsed, cap) / 1e6)   [u128]
 * First fix ever (prevBraked == 0): braked := raw explicitly [C-4]. */
uint64_t OracleBrakedNext(uint64_t nPrevBraked, uint64_t nRaw,
                          uint32_t nElapsedBlocks, uint32_t nBrakePpmPerBlock,
                          uint32_t nElapsedCap);

template <typename T>
bool DecodeOraclePayload(const std::vector<unsigned char>& vch, T& payload);

class CScript;

/** Bond escrow lock: <33-byte submitter pubkey> OP_DROP OP_TRUE - the house
 * escrow family with a LENGTH-distinct form (36 bytes vs the house form's
 * 35), so no shared tag surface [OQ-D resolved: own class]. Coin-level spend
 * protection (T-o3): the coin is tagged fOracleBond at AddCoins and gated in
 * CheckTxInputs - only a v17 BOND whose payload key matches this script may
 * spend it (re-bond/top-up consolidation; the in-script key makes the gate a
 * script compare, no lookup). No unbond-withdraw op exists in the scaffold. */
CScript OracleBondScript(const std::vector<unsigned char>& vchPubKey);
bool IsOracleBondScript(const CScript& script);

class CValidationState;

/** Context-free shape rules for v17 oracle txs (no DB, no ECDSA - quorum,
 * slots, priors-vs-DB, branch bind vs the actual parent, and signature
 * verification run contextually at connect/ATMP, T-o2/T-o3). Decode-exact
 * payload, known op, envelope checks (price bounds; genesis-binding
 * consistency: nPrevFixHeight == 0 iff both prev views are 0), key/sig
 * well-formedness, target-height nonzero. */
bool CheckOracleTransactionShape(const CTransaction& tx, CValidationState& state);

#endif // BITCOIN_ORACLE_H

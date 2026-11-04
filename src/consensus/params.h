// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>
#include <map>
#include <string>
#include <vector>

namespace Consensus {

/** One step of the suspension-interest rate schedule (v0.2.18, operator sign-off
 *  2026-10-02, Q1-Q3): from block nHeight onward, demanded notes accrue at nBps
 *  basis points per year (simple, per block). */
struct DeferInterestStep {
    uint32_t nHeight;
    uint32_t nBps;
};

/** Gram-notes release (docs-local/GOLD_USD_SCOPE.md; design draft 9): the figures of the gram-notes rules. Fixed in
 *  consensus at switch-on; a later release changes a figure only from an announced height (legal condition 6), as a
 *  new entry of Params::vGramSchedule, never as a CLI knob. Fields are added step by step as the rules that read them
 *  land. */
struct GramParams {
    // The price feed (step 3; R3-10, D-2026-11-01-6 item 3).
    uint32_t nOracleWindow = 6;           // blocks: a reporter's latest submission this recent counts toward a fix
    uint32_t nOracleActiveWindows = 4;    // a bonded reporter counts toward a stream's quorum base if it observed that
                                          //   stream within this many windows (review round 1, G7a: was 24, any stream)
                                          //   this many windows (silent bonds can't raise the quorum, design 11-01)
    uint32_t nOracleQuorumMin = 3;        // quorum = max(min, ceil(active / 2)), capped at max
    uint32_t nOracleQuorumMax = 7;
    uint32_t nPriceViewBlocks = 144;      // the payout view: the median of the last this-many blocks' raw fixes
    uint32_t nPriceBackBlocks = 72;       // a payload's price height may be at most this far back (R2-ops-11, R2-int-7)
    uint32_t nBackingWindow = 144;        // backing reports count within this window
    uint32_t nBackingStaleBlocks = 288;   // a token whose last backing fix is older counts zero for issuing
    uint32_t nBurnPayBlocks = 1008;       // D-2026-11-04-1 (3d, R2-ops-7; design agreed N = 7 days): burns this old
                                          //   that the backing reports don't show paid, beyond the threshold below,
                                          //   make the token untrusted (zero for issuing at once; equity and claims
                                          //   after the 30-day grace, as any loss of trust)
    uint64_t nBurnUnpaidMinMg = 10000;    //   the threshold: max(10 g, 0.5% of the token's supply) - so a burn to an
    uint32_t nBurnUnpaidBps = 50;         //   address the issuer can't pay costs its sender real gold to matter
    int64_t nOracleBondMin = 100000000;   // sats; provisional (to be sized against notes outstanding)
    // Token pools and the payout price (step 4; R3-3, D-2026-11-01-6 item 4).
    uint32_t nPoolViewBlocks = 144;       // a pool's price and depth are averaged over this many blocks
    uint32_t nPoolDepthMinBps = 500;      // a pool counts while its average token reserve is >= 5% of the token's supply
    uint32_t nPayoutCapBps = 500;         // while a pool counts, no payout price is more than 5% above the pool view
    uint64_t nCreateFeeMg = 1000;         // D-2026-11-04-1 (3b): creating a token or a pool burns 1 g of gold's worth of
                                          //   sECX at the payout price (no price, no creation)
    // The house machine on gold (step 5; D-2026-11-01-1; the Monte Carlo's figures, proposals until agreed).
    uint32_t nCapitalMinBps = 1000;       // issuing needs owners' capital (counted gold) >= 10% of notes and deposits
    uint32_t nTillMinBps = 200;           // ... and a till (counted gold) >= 2% of notes
    uint32_t nBillOverdueBlocks = 432;    // a bill unpaid this long past maturity counts zero in equity (R3-1)
    uint64_t nIssuerBondMinMg = 1000000;  // review round 1b: a token is trusted only with an issuer bond worth >= 1 kg
    uint32_t nFreezeGraceBlocks = 4320;   // frozen vault gold still counts for 30 days (decisions log 4)...
    uint32_t nFreezeClearBlocks = 25920;  // ...and the grace restarts only after 180 days with nothing frozen
    // The exit to ECX reserves (design draft 9; D-2026-11-01-1, -5): sigma = the annualised standard deviation of the
    // daily log changes of the gold price over the trailing nExitDays; at or below nExitCalmBps the share of capital and
    // till that may count in sECX rises one step (25%) per nExitStepBlocks, above nExitStormBps it falls one step.
    uint32_t nExitDays = 730;
    uint32_t nExitStepBlocks = 25920;
    uint32_t nExitCalmBps = 4500;
    uint32_t nExitStormBps = 6000;
};

struct GramStep {
    uint32_t nHeight;
    GramParams p;
};

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height at which BIP16 becomes active */
    int BIP16Height;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for bitassetss.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    /** SETTLE_EXCHANGE per-house cadence in blocks (eligibility comparison in
     *  CheckSettleOperation, never a sweep). Consensus-critical: a per-node
     *  override would fork the chain, so this lives here and ONLY here —
     *  no CLI/conf knob may ever set it. */
    uint32_t nSettleCadence;
    /** B3 bearer par-redemption: blocks a PRE-AUTHORISED demand may sit
     *  undischarged before its holder may PROTEST (Phase 3.5b, D-ii signed
     *  2026-08-04). Consensus-critical, and it lives HERE and only here for the
     *  same reason nSettleCadence does — settle.h:54 warns that the
     *  HOUSE_ATTEST_CADENCE/-attestcadence extern-plus-CLI pattern is a fork
     *  hazard; do not copy it. No CLI/conf knob may ever set this.
     *
     *  It prices ONE thing: how long an honest house may be offline before a
     *  holder can put it on the stress cascade. Too small punishes honest
     *  downtime; too large lets a stonewaller idle. */
    uint32_t nDemandWindow;
    /** Suspension interest (v0.2.18, operator sign-off 2026-10-02, Q1-Q3): the
     *  rate demanded notes earn, as a HEIGHT SCHEDULE so a later release can
     *  change it from a future height without rewriting history. Entries are
     *  sorted by nHeight, the first is at height 0; block b accrues at the rate
     *  of the last entry with nHeight <= b. ONE schedule serves both clocks:
     *  the suspension queue (from the demand) and lapsed B3 pre-auth demands
     *  (from window lapse). Same never-a-CLI-knob rule as nSettleCadence. */
    std::vector<DeferInterestStep> vDeferInterestSchedule;
    /** Silence clock of a SUSPENDED house (v0.2.18, Q5): once it has missed
     *  HOUSE_ATTEST_MISS_N attestation cadences, it has this many more blocks
     *  to attest again before it is (lazily) Insolvent. ~4 weeks on mainnet.
     *  Open/stressed houses keep HOUSE_STRESSED_WINDOW. Never a CLI knob. */
    uint32_t nDeferSilenceWindow;
    /** v0.2.21: the token holders' claim window at a failed house, in blocks from E (TOKEN_CLAIM_DESIGN.md). */
    uint32_t nTokenClaimWindow;
    /** v0.2.28 (gateway/docs/freebank/FAILED_HOUSE_DESIGN.md, signed off 2026-10-16), all in blocks:
     *  nSuspensionCap - a suspension ends in insolvency this long after DEFER (12 months);
     *  nCollectWindow - payouts at an insolvent house wait until its loan book is empty or this long after E (6
     *                   months), and DISCOUNT refuses a bill maturing further ahead than this;
     *  nInsolventClaimWindow - claims close this long after E (2 years); then anyone may CLOSE the house. */
    uint32_t nSuspensionCap;
    uint32_t nCollectWindow;
    uint32_t nInsolventClaimWindow;
    /** Gold oracle (Phase G-1, consensus-inert). Same never-a-CLI-knob rule.
     *  Quorum = DISTINCT registered submitters required in one block for a
     *  new fix; brake = max fall of the braked view, ppm per elapsed block,
     *  elapsed capped; unbond delay is provisional (decorative while inert). */
    uint32_t nOracleQuorumMin;
    uint32_t nOracleBrakePpmPerBlock;
    uint32_t nOracleBrakeElapsedCap;
    uint32_t nOracleUnbondDelay;
    /** How many heights a v17 op stays valid, counting its nTargetHeight as the
     * first. MUST be >= 2: under BMM the candidate for the next block is
     * templated in the same call that connects the current one, so an op signed
     * against tip H can never reach the H+1 candidate - k=1 starves the oracle
     * completely. See docs-local/ORACLE_WINDOW_PROPOSAL.md (operator-signed
     * 2026-07-28). Every STORED height stays a connect height; only this
     * validity predicate widened. */
    uint32_t nOracleOpWindow;
    /** Withdrawal poison-row guard (v0.2.13, operator sign-off 2026-09-24:
     *  0 on main and regtest).
     *  From this sidechain height: (a) a withdrawal object is valid only if its
     *  destination yields a standard, non-dust L1 payout under a decode that does
     *  not depend on the L1 family (CheckWithdrawalPayable) - mempool and block
     *  rule, a soft fork; (b) the bundle builder, and so replication, SKIPS an
     *  unspent row whose payout cannot be paid instead of failing - this changes
     *  what a valid bundle is for chains that already hold such a row, so every
     *  node must upgrade before this height (flag day). A withdrawal pooled
     *  before this height is evicted at it (EvictUnpayableWithdrawals) and never
     *  enters a template (BlockAssembler::TestPackageTransactions). Same
     *  never-a-CLI-knob rule as nSettleCadence; unit tests move it through a
     *  const_cast on Params().GetConsensus(). */
    int nWithdrawalGuardHeight;
    /** v1.0.2 (NEXT 40, docs-local/CREDIT_SIGHASH_SPEC.md): from this height both input digests of a credit
     *  transaction (v11-17) bind its op and payload minus the payload's signature fields
     *  (SCRIPT_VERIFY_CREDIT_BINDING). Genesis on every network (easynet bound from 600 until its v1.1.0 restart as a
     *  fresh chain). Below it, a node takes no credit transaction into its mempool or its templates (signers always
     *  sign the bound form). Never a CLI knob. */
    int nCreditBindingHeight;
    bool CreditBindingActive(int nHeight) const { return nHeight >= nCreditBindingHeight; }
    /** Gram-notes release: the figures as a height schedule (sorted, the first at 0); a block uses the last entry at
     *  or below its height. */
    std::vector<GramStep> vGramSchedule;
    const GramParams& GramAt(int nHeight) const
    {
        const GramStep* p = &vGramSchedule.front();
        for (const GramStep& s : vGramSchedule)
            if ((int64_t)s.nHeight <= (int64_t)nHeight)
                p = &s;
        return p->p;
    }
    /** Gram-notes release, D-2026-11-01-6 item 3: while one block producer is the only one, reporters forfeit only
     *  for equivocation and reporter pay is 0. From this height (set by a later release, once a second unconnected
     *  bidder produces) the liveness and against-the-pool forfeits and the pay switch on. INT_MAX until then. */
    int nFullForfeitHeight;
    /** Gram-notes release, D-2026-11-01-6 item 1: no dollar-token pools at launch; a later release sets this height.
     *  INT_MAX until then. */
    int nDollarPoolHeight;
    /** Gram-notes release, D-2026-10-31-8 item 9: house note pools (tx version TRANSACTION_POOL_VERSION, every op)
     *  open once a second, unconnected BMM bidder produces; a later release sets this height. INT_MAX until then
     *  (regtest: -housepoolheight). */
    int nNotePoolHeight;
    /** Gram-notes release (scope 7h): a chain started fresh on an L1 whose slot-130 treasury already has a history
     *  credits only treasury changes in L1 blocks at or above this L1 height; the older ones belong to the chain that
     *  ran before (a fresh chain would credit every deposit again after its withdrawals were paid). 0 = all; set on
     *  easynet's restart on v1.1.0 (regtest: -depositstartheight). */
    int nDepositStartL1Height;
    /** v0.2.19 (genesis M1, Michael 2026-10-04, option A): while set, no block
     *  after genesis is valid and none is produced. Mainnet ships dormant so its
     *  M1 can name a real release; a later release clears it ("switches it on"),
     *  and its first blocks credit every deposit made in the meantime, in order. */
    bool fChainDormant = false;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 defaultAssumeValid;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H

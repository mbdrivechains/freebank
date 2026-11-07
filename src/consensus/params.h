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

/** No forks (D-2026-11-05-3): 31 Oct 2027 00:00 UTC, the end of Michael's bidding (doc/PRODUCER_POLICY.md). */
static constexpr int64_t LATER_RULES_TIME_MAIN = 1824940800;
/** A later rule that never switches on (regtest's default). */
static constexpr int64_t LATER_RULE_NEVER = std::numeric_limits<int64_t>::max();

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
    int64_t nCreateFeeSats = 10000000;    // Gold B (GOLD_B.md §7; closes hole 4): creating a token or a pool burns this much
                                          //   sECX (0.1 ECX; placeholder until the switch-on figures are set). D-2026-11-04-1 (3b)
                                          //   made it 1 g at the payout price, which needed a price.
    // The floors (D-2026-11-06-2, counted as D-2026-11-07-1 says: sECX in mg at the house's 30-day highest ask).
    uint32_t nCapitalMinBps = 1000;       // issuing needs owners' capital (the sECX escrow) >= 10% of notes and deposits
    uint32_t nTillMinBps = 200;           // ... and a till (attested sECX) >= 2% of notes
    uint32_t nBillOverdueBlocks = 432;    // a bill unpaid this long past maturity is defaulted (R3-1; D-2026-11-07-2)
    // Gold B (D-2026-11-07-1; GOLD_B.md §1, §4, §9): each house's own rate and the chain clock.
    uint32_t nRateSpreadBps = 200;          // ask <= bid x (1 + 2%)
    uint32_t nRateRiseBps = 2500;           // the bid may rise at most 25% ...
    uint32_t nRateRiseWindowSecs = 86400;   // ... per 24 h (from the bid in effect when the window restarted); no fall cap
    uint32_t nRateRefreshSecs = 86400;      // to issue, a house must have posted its rate within 24 h
    uint32_t nActiveGapCapSecs = 3600;      // active time leaves out gaps over 1 h between blocks (the swap deadline)
    uint32_t nCharterRemovalSecs = 2592000; // removing a charter token takes effect 30 days after it is posted
    uint32_t nSwapDeadlineSecs = 259200;    // a swap's gold tokens are delivered (s revealed) within 72 h of active time
    uint32_t nSwapPayWindowSecs = 86400;    // an undelivered swap unpaid this much active time after its deadline is protestable
    uint32_t nShortfallLapseSecs = 7776000; // a failed swap's shortfall claim lapses 90 days after it is paid
    uint32_t nSwapBidWindowSecs = 86400;    // a failed swap pays at most the highest bid in effect this long before T_f
    uint32_t nRampPeriodBlocks = 25920;     // the ramp (GOLD_B §5): each escrow tranche's multiple doubles per 180 clean
                                            //   days (clock blocks), from 1x up to the floor's limit
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
    /** No forks (D-2026-11-05-3): the rules that waited on the sole-producer period switch on by themselves at one
     *  time, the end of Michael's bidding (31 Oct 2027 00:00 UTC = LATER_RULES_TIME_MAIN on main), judged by the median
     *  time past of a block's parent (LaterRuleOn, validation.h). No later release sets or moves them. Equal on every
     *  public network, so regtest can switch each alone (-housepooltime, -dollarpooltime). LATER_RULE_NEVER = never;
     *  0 = from genesis. (Gold B dropped nFullForfeitTime with the forfeits and reporter pay it switched on.)
     *  - nDollarPoolTime: dollar-token pools (D-2026-11-01-6 item 1).
     *  - nNotePoolTime: house note pools, tx version TRANSACTION_POOL_VERSION, every op (D-2026-10-31-8 item 9). */
    int64_t nDollarPoolTime;
    int64_t nNotePoolTime;
    /** Gold B clocks in time (GOLD_B.md §6): the credit layer's windows count "clock blocks", 600 s each of chain active
     *  time (CChainClock), so sparse blocks don't stretch them. Regtest counts plain heights instead (true), so gates
     *  that mine N blocks keep working; the time path is covered by unit tests. */
    bool fClockIsHeight = false;
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

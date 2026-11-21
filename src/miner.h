// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include <primitives/block.h>
#include <txmempool.h>

#include <stdint.h>
#include <memory>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>

class CBlockIndex;
class CCoinsViewCache;
class CUnitsView;
struct SidechainDeposit;
class CChainParams;
class CScript;
class CValidationState;

namespace Consensus { struct Params; };

static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOpsCost;
    std::vector<unsigned char> vchCoinbaseCommitment;
};

// Container for tracking updates to ancestor feerate as we include (parent)
// transactions in a block
struct CTxMemPoolModifiedEntry {
    explicit CTxMemPoolModifiedEntry(CTxMemPool::txiter entry)
    {
        iter = entry;
        nSizeWithAncestors = entry->GetSizeWithAncestors();
        nModFeesWithAncestors = entry->GetModFeesWithAncestors();
        nSigOpCostWithAncestors = entry->GetSigOpCostWithAncestors();
    }

    int64_t GetModifiedFee() const { return iter->GetModifiedFee(); }
    uint64_t GetSizeWithAncestors() const { return nSizeWithAncestors; }
    CAmount GetModFeesWithAncestors() const { return nModFeesWithAncestors; }
    size_t GetTxSize() const { return iter->GetTxSize(); }
    const CTransaction& GetTx() const { return iter->GetTx(); }

    CTxMemPool::txiter iter;
    uint64_t nSizeWithAncestors;
    CAmount nModFeesWithAncestors;
    int64_t nSigOpCostWithAncestors;
};

/** Comparator for CTxMemPool::txiter objects.
 *  It simply compares the internal memory address of the CTxMemPoolEntry object
 *  pointed to. This means it has no meaning, and is only useful for using them
 *  as key in other indexes.
 */
struct CompareCTxMemPoolIter {
    bool operator()(const CTxMemPool::txiter& a, const CTxMemPool::txiter& b) const
    {
        return &(*a) < &(*b);
    }
};

struct modifiedentry_iter {
    typedef CTxMemPool::txiter result_type;
    result_type operator() (const CTxMemPoolModifiedEntry &entry) const
    {
        return entry.iter;
    }
};

// A comparator that sorts transactions based on number of ancestors.
// This is sufficient to sort an ancestor package in an order that is valid
// to appear in a block.
struct CompareTxIterByAncestorCount {
    bool operator()(const CTxMemPool::txiter &a, const CTxMemPool::txiter &b) const
    {
        if (a->GetCountWithAncestors() != b->GetCountWithAncestors())
            return a->GetCountWithAncestors() < b->GetCountWithAncestors();
        return CTxMemPool::CompareIteratorByHash()(a, b);
    }
};

typedef boost::multi_index_container<
    CTxMemPoolModifiedEntry,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<
            modifiedentry_iter,
            CompareCTxMemPoolIter
        >,
        // sorted by modified ancestor fee rate
        boost::multi_index::ordered_non_unique<
            // Reuse same tag from CTxMemPool's similar index
            boost::multi_index::tag<ancestor_score>,
            boost::multi_index::identity<CTxMemPoolModifiedEntry>,
            CompareTxMemPoolEntryByAncestorFee
        >
    >
> indexed_modified_transaction_set;

typedef indexed_modified_transaction_set::nth_index<0>::type::iterator modtxiter;
typedef indexed_modified_transaction_set::index<ancestor_score>::type::iterator modtxscoreiter;

struct update_for_parent_inclusion
{
    explicit update_for_parent_inclusion(CTxMemPool::txiter it) : iter(it) {}

    void operator() (CTxMemPoolModifiedEntry &e)
    {
        e.nModFeesWithAncestors -= iter->GetFee();
        e.nSizeWithAncestors -= iter->GetTxSize();
        e.nSigOpCostWithAncestors -= iter->GetSigOpCost();
    }

    CTxMemPool::txiter iter;
};

/** Generate a new block, without valid proof-of-work */
//! -bmmblockmaxweight default (v0.2.16): the weight cap for get_block_template's
//! mempool transactions. The BMM engine stores every template in its bid records.
static const unsigned int DEFAULT_BMM_BLOCK_MAX_WEIGHT = 300000;
/** The weight and sigop cost every template reserves for its coinbase before anything else (BlockAssembler::resetBlock) */
static const uint64_t COINBASE_RESERVED_WEIGHT = 4000;
static const int64_t COINBASE_RESERVED_SIGOPS_COST = 400;
/** The outputs a deposit record adds to the coinbase: the payout GetDepositPayoutOutput owes, if any, then the record. */
std::vector<CTxOut> DepositCoinbaseOutputs(const SidechainDeposit& deposit);
/** The weight and (legacy, scaled) sigop cost of a set of coinbase outputs, as the builder budgets them. */
void DepositOutputsCost(const std::vector<CTxOut>& vOut, uint64_t& nWeight, int64_t& nSigOpsCost);
/** The weight budget deposit records get in every template this node builds, refreshbmm's and get_block_template's
 *  alike: -blockmaxweight (default MAX_BLOCK_WEIGHT - 4000). -bmmblockmaxweight caps get_block_template's mempool
 *  transactions only, never deposits. */
uint64_t DepositMaxWeight();
/** Deposits' share of a template, on every path (security 11-19): half the room -blockmaxweight leaves after the coinbase
 *  reserve, for weight; half of MAX_BLOCK_SIGOPS_COST after its reserve, for sigops. Packages always keep the rest. */
uint64_t DepositCapWeight();
int64_t DepositCapSigOpsCost();
/** S5X-5: true if no template this node builds can ever hold the deposit's outputs, even with no other deposit (the
 *  builder's own test, against DepositCapWeight / DepositCapSigOpsCost). Such a deposit doesn't hold UpdateDeposits' window back; any
 *  other one does until it is recorded (security 11-19: a test that disagrees with the builder either pins the window
 *  or drops a deposit the builder would take). */
bool DepositNeverFitsTemplate(const SidechainDeposit& deposit);
/** Pooled transactions a template drops before it builds the block from no mempool transactions (v0.2.19) */
static const int MAX_TEMPLATE_EVICTIONS = 10;

/** S1X-4: the most weight the template holds back for the rate pass (about a dozen rate ops) */
static const uint64_t RATE_PASS_MAX_RESERVED_WEIGHT = 16000;

class BlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    // A convenience pointer that always refers to the CBlock in pblocktemplate
    CBlock* pblock;

    // Configuration parameters for the block size
    bool fIncludeWitness;
    unsigned int nBlockMaxWeight;
    CFeeRate blockMinFeeRate;

    // Information on the current status of the block
    uint64_t nBlockWeight;
    // S5X-5 / security 11-19: neither deposits nor mempool packages may starve the other. Deposits are reserved first,
    // up to DepositCapWeight (half the room after the coinbase reserve); then nBlockWeight may grow to
    // nPackageWeightLimit = min(nBlockMaxWeight + the deposits' weight, DepositMaxWeight()): packages are held to this
    // path's cap counted on themselves (plus the reserve), and the block to -blockmaxweight.
    uint64_t nDepositReservedWeight;
    uint64_t nPackageWeightLimit;
    uint64_t nBlockTx;
    uint64_t nBlockSigOpsCost;
    CAmount nFees;
    CTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;
    const CChainParams& chainparams;

public:
    struct Options {
        Options();
        size_t nBlockMaxWeight;
        CFeeRate blockMinFeeRate;
    };

    explicit BlockAssembler(const CChainParams& params);
    BlockAssembler(const CChainParams& params, const Options& options);


    /**
     * Generates a BMM block (selects transactions, minimal PoW) which can
     * then be commited to on the parent chain. Once the parent chain commits
     * the BMM hash of this block, a BMM proof can be used to actually connect
     * this block to the chain.
     *
     * If an optional vector of transactions is passed in, all but the coinbase
     * will be replaced with those transactions.
     */
    bool GenerateBMMBlock(CBlock& block, std::string& strError, CAmount* nFeesOut = nullptr, const std::vector<CMutableTransaction>& vtx = std::vector<CMutableTransaction>(), const uint256& hashPrevBlock = uint256(), const CScript& scriptPubKey = CScript(), const uint256& hashMainTip = uint256());

private:
    // Note: Moved to private, should always use GenerateBMMBlock().
    /** Construct a new block template with coinbase to scriptPubKeyIn */
    std::unique_ptr<CBlockTemplate> CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx=true, bool fCheckBMM = true, const uint256& hashPrevBlock = uint256(), CAmount* nFeesOut = nullptr, const uint256& hashMainTip = uint256());
    /** One attempt (v0.2.19): fNoMempoolTxs builds the block from no mempool
      * transactions. A template that fails TestBlockValidity comes back with
      * fInvalid set and the failure in state, for CreateNewBlock to find and
      * drop the transaction at fault. Caller holds cs_main and mempool.cs. */
    std::unique_ptr<CBlockTemplate> CreateNewBlockOnce(const CScript& scriptPubKeyIn, const uint256& hashPrevBlock, CAmount* nFeesOut, const uint256& hashMainTip, bool fCheckBMM, bool fNoMempoolTxs, bool& fInvalid, CValidationState& state);

    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** v0.2.18: withdrawal ids the template already creates (bad-withdrawal-not-new) */
    std::set<uint256> setBlockWithdrawalIDs;
    /** D-2026-11-11-3: houses whose rate op (POST or SETKEY) the template already holds (one per house per block) */
    std::set<uint32_t> setBlockRateHouses;
    /** S2X-1: the units state as the template's issued ops leave it, and the coins they read (null: no check, as when
      * the template builds on a block other than the tip, whose state these views don't hold) */
    CUnitsView* pTemplateUnits = nullptr;
    const CCoinsViewCache* pTemplateCoins = nullptr;
    /** S1X-4: while set (the clock and fee-rate passes), packages holding a rate op wait for addRateTxs */
    bool fDeferRateOps = false;
    /** S1X-4: weight held back from the earlier passes for addRateTxs */
    uint64_t nRateReservedWeight = 0;
    /** S2X-1b: token packages this template skipped because an issued op didn't follow (TestPackageIssued; logged) */
    int nIssuedFailed = 0;
    /** Add a tx to the block */
    void AddToBlock(CTxMemPool::txiter iter);

    // Note: Also returns a vector of refund request txns. These txns must
    // be manually added to the block by the miner.
    //
    // Methods for how to add transactions to a block.
    /** Add transactions based on feerate including unconfirmed ancestors
      * Increments nPackagesSelected / nDescendantsUpdated with corresponding
      * statistics from the package selection (for logging statistics). */
    void addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated, std::vector<CTxMemPool::txiter>& vRefundTx, bool fIncludeRefunds);
    /** v0.2.19: before the fee-rate pass, add the pooled transactions that run a
      * house's solvency clock (IsClockTx) with their ancestors, oldest first, in at
      * most half the block. A demand, protest or redemption must not wait behind
      * cheaper traffic: the sole producer's no-censorship rule (D-2026-10-03-2). */
    void addClockTxs(int &nPackagesSelected);
    /** S1X-4: last, the pooled rate ops (POST, SETKEY) with their ancestors, so no reader in the block follows a post */
    void addRateTxs(int &nPackagesSelected);
    /** S1X-4: hold back the pooled rate ops' weight (capped) from the earlier passes */
    void ReserveRateWeight();

    // helper functions for addPackageTxs()
    /** Remove confirmed (inBlock) entries from given set */
    void onlyUnconfirmed(CTxMemPool::setEntries& testSet);
    /** Test if a new package would "fit" in the block */
    bool TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const;
    /** Perform checks on each transaction in a package:
      * locktime, premature-witness, serialized size (if necessary)
      * These checks should always succeed, and they're here
      * only as an extra check in case of suboptimal node configuration */
    bool TestPackageTransactions(const CTxMemPool::setEntries& package);
    /** S2X-1: run the package's issued-version txs, in block order, against the template's units state; on success the
      * template state moves on, on failure it is untouched and the package is skipped */
    bool TestPackageIssued(const std::vector<CTxMemPool::txiter>& sortedEntries);
    /** Return true if given transaction from mapTx has already been evaluated,
      * or if the transaction's cached data in mapTx is incorrect. */
    bool SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx);
    /** Sort the package in an order that is valid to appear in a block */
    void SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries);
    /** Add descendants of given transactions to mapModifiedTx with ancestor
      * state updated assuming given transactions are inBlock. Returns number
      * of updated descendants. */
    int UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded, indexed_modified_transaction_set &mapModifiedTx);
};

/** Block assembler options for get_block_template (v0.2.16): the usual ones,
 *  with the transaction weight capped at -bmmblockmaxweight. Deposits come
 *  after the transactions and are still bounded by MAX_BLOCK_WEIGHT only,
 *  so the cap never truncates them. */
BlockAssembler::Options BMMTemplateAssemblerOptions();

/** v0.2.19 policy: a transaction that runs a house's solvency clock or a holder's
 *  exit from it. Notes: REDEEM (a holder's redemption or the house's discharge of
 *  queued demands), DEMAND, PROTEST, CLAIM. Term deposits: WITHDRAW, CLAIM. Houses:
 *  ATTEST (a missed cadence makes a house Stressed). */
bool IsClockTx(const CTransaction& tx);

/** Modify the extranonce in a block. The coinbase scriptSig becomes
 *  <height> <extranonce> + COINBASE_FLAGS (the -coinbasetag push, or nothing). */
void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);

/** Longest -coinbasetag, in bytes. A produced coinbase scriptSig is then at most
 *  (1+5) + (1+5) + (1+64) = 77 bytes, inside the 100 that consensus allows a
 *  coinbase scriptSig (CheckTransaction, "bad-cb-length") and that
 *  IncrementExtraNonce asserts. */
static const unsigned int MAX_COINBASE_TAG_BYTES = 64;

/** -coinbasetag: the block producer's self-declared name. It is written after the
 *  height and the extra nonce in the coinbase scriptSig of every block this node
 *  produces (through COINBASE_FLAGS), so an explorer can show who produced a block.
 *  Policy, not consensus: validation reads nothing in a coinbase scriptSig past the
 *  BIP34 height prefix, and checks only its 2..100-byte length.
 *
 *  Trims surrounding whitespace, then requires 1..MAX_COINBASE_TAG_BYTES bytes of
 *  printable ASCII (0x20-0x7e). On success strTag is the trimmed tag and scriptTag
 *  one push of its bytes (the value for COINBASE_FLAGS). On failure strError says
 *  why, and strTag and scriptTag are left untouched. */
bool ParseCoinbaseTag(const std::string& strIn, std::string& strTag, CScript& scriptTag, std::string& strError);
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

bool CreateDepositTx(CMutableTransaction& depositTx);

// Gram-notes release (GOLD_USD_SCOPE.md 7j; legal condition 6, "no discretion"): the producer's inclusion log -
// node-side, not consensus. Each block template this node builds (its height, the pool transactions it carries and the
// ones it leaves out, logged when that set changes) and each transaction a template had to drop. JSON lines appended to
// <datadir>/inclusion.log; the last 1,000 entries also kept for getinclusionlog.
class UniValue;
void InclusionLogTemplate(int nHeight, const std::vector<uint256>& vIncluded,
                          const std::vector<std::pair<uint256, std::string>>& vLeftOut);
void InclusionLogDrop(const uint256& txid, const std::string& strReason);
UniValue InclusionLogRecent(size_t nMax);

#endif // BITCOIN_MINER_H

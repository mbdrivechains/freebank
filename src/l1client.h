// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_L1CLIENT_H
#define BITCOIN_L1CLIENT_H

#include <amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <string>
#include <utility>
#include <vector>

class SidechainDeposit;
class UniValue;

/** Transport used to reach the mainchain (L1). */
enum class L1Transport {
    JSONRPC,  // drivechain-patched mainchain node JSON-RPC (BTX / eCash-v1)
    ENFORCER, // CUSF bip300301_enforcer gRPC via grpcurl (eCash-v2 / Cygnet)
};

/** Mainchain-connection defaults. Orchestrated installs (BitWindow) launch the
 *  sidechain binary with no arguments, so the argless defaults must describe
 *  the standard CUSF stack: enforcer gRPC on 50051, bitcoind REST on the
 *  signet RPC port. Regtest keeps the legacy jsonrpc default — the integration
 *  gates run a local drivechain-patched pair on 18443, not an enforcer stack.
 *  Every value remains overridable on the command line. */
const std::string& DefaultMainchainTransport();
static const std::string DEFAULT_MAINCHAIN_REST = "127.0.0.1:38332";

/** Startup reachability probe for the -mainchainrest endpoint (one HTTP GET of
 *  /rest/chaininfo.json). Returns false with strError set if it does not
 *  answer; init fails loud on that rather than letting a node without REST
 *  reject the first deposit-bearing block and fork off the network. */
/** Probe the mainchain REST endpoint and check the L1 identity pin.
 *
 * Sets *pfIdentityMismatch when the endpoint answered but is the WRONG L1.
 * That distinction decides retry policy: an unreachable node is worth waiting
 * for (an orchestrator may start it moments after this one), but a mismatch is
 * deterministic - retrying it only delays a certain failure by a minute.
 */
bool ProbeMainchainRest(std::string& strError, bool* pfIdentityMismatch = nullptr);

/** A9: the L1 family observed by the REST pin at init. True iff the mainchain reports
 *  chain=main (a forknet such as eCash alphanet, or mainnet). Read by base58's mainchain
 *  address decoding (withdrawal destinations, consumed at bundle build/validate), so it
 *  is set once from the L1 itself and never configurable - identical for every node that
 *  follows the same L1. False (signet/testnet family, prefix 111) until the probe runs.
 *  Defined in base58.cpp (common layer) so freebank-tx links; SET here. */
extern bool g_fMainchainMainFamily;

/** Parse a -mainchainblockpin value "<height>:<blockhash>" (forknet / mainnet-family
 *  L1 identity pin). Pure, no I/O, unit-tested. Returns false on any malformation. */
bool ParseMainchainBlockPin(const std::string& strPin, int& nHeight, uint256& hashBlock);

/** Result of the enforcer-side (gRPC) L1 identity probe. */
enum EnforcerIdentity {
    ENFORCER_IDENTITY_MATCH,     // enforcer tip is a block on the REST node's active chain
    ENFORCER_IDENTITY_MISMATCH,  // enforcer tip is NOT (wrong L1, or an abandoned fork)
    ENFORCER_IDENTITY_NOTREADY,  // could not determine (enforcer down/syncing, REST transient)
};

/**
 * A7 gRPC L1 IDENTITY PIN. The REST pin (ProbeMainchainRest) validates the REST
 * node's identity via chain + signet_challenge. BMM and peg data ALSO flow over
 * a SEPARATE channel - the enforcer gRPC at -enforceraddr - which the REST pin
 * does not cover; a wrong-mainchain enforcer reproduces the 2026-07-28 incident
 * through it. This asserts the enforcer indexes the SAME L1 as the (already
 * challenge-pinned) REST node, TRANSITIVELY: check the enforcer's chain tip is a
 * block on the REST node's ACTIVE chain (/rest/headers/1/<tip> returns the header
 * iff on the active chain, else an empty 200 - so "not my chain" is cleanly
 * distinguishable from a transport failure).
 *
 * Tip membership (not a fixed-depth anchor) is deliberate: the enforcer sources
 * its blocks from the mainchain node, so enforcer_tip <= rest_tip always, making
 * a correct-but-lagging enforcer's tip a real block on the REST chain (MATCH, no
 * false mismatch from boot sync-skew) while a wrong chain OR an abandoned fork
 * (the D-4 shape) leaves the tip off the active chain (MISMATCH). One attempt;
 * the caller debounces across a retry window. *pfStale set (a WARN, not a refuse)
 * when the enforcer trails REST far enough to look frozen.
 */
EnforcerIdentity ProbeEnforcerIdentity(std::string& strError, bool* pfStale = nullptr);

/** Pure decision for ProbeEnforcerIdentity, split out for unit tests (no I/O).
 *  nStaleWarnDepth>0: set *pfStale if the enforcer tip trails REST by more than it. */
EnforcerIdentity ClassifyEnforcerIdentity(bool fEnfTipOK, int nEnfTipHeight,
                                          bool fRestOK, int nRestTipHeight,
                                          bool fMemberQueryOK, bool fEnfTipOnRestChain,
                                          int nStaleWarnDepth, bool* pfStale,
                                          std::string& strDetail);

/**
 * L1Client - the mainchain I/O behind SidechainClient.
 *
 * One virtual per mainchain query. Two implementations, selected once at
 * startup by -mainchaintransport: JsonRpcL1Client speaks the legacy
 * drivechain JSON-RPC surface; EnforcerL1Client reads from the CUSF
 * enforcer's gRPC ValidatorService by shelling out to grpcurl (the enforcer
 * is invoked at runtime by service name - nothing of it is vendored or
 * linked).
 */
class L1Client
{
public:
    virtual ~L1Client() {}

    virtual bool BroadcastWithdrawalBundle(const std::string& hex) = 0;
    virtual std::vector<SidechainDeposit> UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex) = 0;
    virtual bool VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx) = 0;
    virtual bool VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime) = 0;
    virtual uint256 SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount) = 0;
    virtual bool GetCTIP(std::pair<uint256, uint32_t>& ctip) = 0;
    virtual bool GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFees) = 0;
    virtual bool GetBlockCount(int& nBlocks) = 0;
    virtual bool GetWorkScore(const uint256& hash, int& nWorkScore) = 0;
    virtual bool ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle) = 0;
    virtual bool GetBlockHash(int nHeight, uint256& hashBlock) = 0;

    /**
     * Batched backward walk for cold header-cache sync: up to nMax hashes
     * newest-first, starting AT (hashBlock, nHeight) and descending toward
     * genesis. The caller supplies both the cursor hash and its height so each
     * transport can use its cheap primitive: the enforcer indexes by hash and
     * answers a whole batch in one ancestor call, while the JSON-RPC mainchain
     * indexes by height and looks each one up directly.
     *
     * Walking per-block through GetBlockHash() instead is quadratic on the
     * enforcer transport (every call re-walks from the tip), which made a cold
     * sync of a few thousand blocks take the better part of an hour.
     */
    virtual bool GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash) = 0;
    virtual bool HaveSpentWithdrawalBundle(const uint256& hash) = 0;
    virtual bool HaveFailedWithdrawalBundle(const uint256& hash) = 0;
};

/** Transport selected by -mainchaintransport (jsonrpc | enforcer). */
L1Transport GetL1Transport();

/** Process-wide L1 client for the selected transport. */
L1Client& GetL1Client();

/** The process-wide enforcer-transport client, whatever -mainchaintransport says.
 *  GetL1Client() returns this same object on the enforcer transport; exposed so
 *  unit tests can drive the real enforcer methods through a fake -grpcurlbin. */
L1Client& GetEnforcerL1Client();

/** True if strTransport names a valid -mainchaintransport value. */
bool IsValidL1Transport(const std::string& strTransport);

/** The shell command the enforcer transport runs for one grpcurl call. The binary path is
 *  double-quoted (BitWindow's macOS path contains a space); a path containing a double quote
 *  cannot be quoted safely and yields "". Pure, unit-tested. */
std::string BuildGrpcurlCommand(const std::string& strBin, const std::string& strRequest, const std::string& strAddr, const std::string& strService, const std::string& strMethod);

//
// Enforcer wire helpers - exposed for unit tests (l1client_tests.cpp).
//
// Wire conventions (verified live against enforcer v0.3.4 via reflection):
// - ReverseHex fields ({"hex": "..."}) carry standard bitcoin display-order
//   hex: uint256::ToString() / uint256S() round-trip them directly.
// - ConsensusHex fields (e.g. BlockInfo.bmm_commitment) carry consensus
//   (internal) byte order: the reverse of display order.
// - uint64 fields arrive as JSON strings, uint32 fields as JSON numbers.
// - grpcurl emits camelCase keys (block_header_info -> blockHeaderInfo).
//

/** Mainchain block header as served by the enforcer. */
struct L1BlockHeader {
    uint256 hashBlock;
    uint256 hashPrevBlock;
    int nHeight = -1;
    uint32_t nTime = 0;
};

/** Decode a ConsensusHex (internal byte order) uint256. Null on bad input. */
uint256 Uint256FromConsensusHex(const std::string& strHex);

/** Encode a uint256 as ConsensusHex (internal byte order). */
std::string ConsensusHexFromUint256(const uint256& hash);

/** Parse a GetChainTip response. */
bool ParseEnforcerChainTip(const UniValue& response, L1BlockHeader& header);

/** Parse a GetBlockHeaderInfo response (self + ancestors, newest first). */
bool ParseEnforcerHeaderInfos(const UniValue& response, std::vector<L1BlockHeader>& vHeader);

/**
 * Parse a GetBmmHStarCommitment response.
 * fBlockFound: the mainchain block is known to the enforcer.
 * fHaveCommitment: an h* commitment for this sidechain exists in the block.
 */
bool ParseEnforcerBmmCommitment(const UniValue& response, bool& fBlockFound, bool& fHaveCommitment, uint256& hashCommitment);

/** Parse a GetBlockInfo response: collect deposit txids for the first (requested) block. */
bool ParseEnforcerBlockDepositTxids(const UniValue& response, std::vector<uint256>& vTxid);

/** Parse a GetCtip response. False if no ctip (no deposits yet) or bad shape. */
bool ParseEnforcerCtip(const UniValue& response, uint256& txid, uint32_t& n);

/** One enforcer WithdrawalBundleEvent. status: 'S' succeeded (== spent / M6
 * paid on the mainchain), 'F' failed, 'U' submitted. m6id is decoded from the
 * event's ConsensusHex. hashMainBlock is the mainchain block the event was
 * recorded in (the block containing the M6 for 'S' events); null if absent. */
struct L1WithdrawalEvent {
    uint256 m6id;
    uint256 hashMainBlock;
    char status;
    L1WithdrawalEvent() : status(0) {}
};

/** Parse a GetTwoWayPegData response into withdrawal-bundle events (deposits
 * ignored). Used by HaveSpent/HaveFailedWithdrawalBundle + ListWithdrawalBundleStatus. */
bool ParseEnforcerWithdrawalEvents(const UniValue& response, std::vector<L1WithdrawalEvent>& vEvents);

/** Fold withdrawal-bundle events (oldest first, as GetTwoWayPegData returns
 * them) into the m6ids L1 is STILL tracking for this slot: Submitted adds,
 * Succeeded/Failed removes. Mirrors the enforcer's pending_m6ids (M3 adds,
 * M6 removes only the paid m6id, max-age expiry removes) and the legacy
 * mainchain listwithdrawalstatus (scdb.GetState: live bundles only). Keeps
 * first-submission order; a repeated Submitted for a pending m6id is counted
 * once; a Succeeded/Failed with no earlier Submitted is ignored. Pure. */
std::vector<uint256> PendingM6idsFromEvents(const std::vector<L1WithdrawalEvent>& vEvents);

/** v0.2.13 item 1 - locating a Succeeded M6 on the L1.
 *
 * OP_DRIVECHAIN is a per-L1 parameter (enforcer NetworkParams::op_drivechain):
 * OP_NOP5 0xb4 on BIP300 / alphanet / the regtest bench, OP_NOP8 0xb7 on
 * betanet, eCash mainnet unpublished. v0.2.12 matched only OP_NOP5, so the
 * first beta M6 would have halted deposit crediting for good. */

/** OP_DRIVECHAIN byte of a treasury (CTIP) script, exactly
 *  `<op> 0x01 <nSidechain> OP_TRUE` (4 bytes) with <op> an upgradable NOP
 *  (OP_NOP1, OP_NOP4..OP_NOP10; never CLTV/CSV), else 0. A cheap SHAPE
 *  prefilter only: the M6 itself is identified by its m6id. Pure. */
unsigned char TreasuryScriptOpcode(const CScript& script, unsigned int nSidechain);
inline bool IsTreasuryScript(const CScript& script, unsigned int nSidechain)
{ return TreasuryScriptOpcode(script, nSidechain) != 0; }

/** The enforcer's m6id of an L1 M6 that spends a treasury UTXO worth
 *  nPrevTreasury (port of bip300301_enforcer OpDrivechain::compute_m6id):
 *  exactly one input; vout[0] a treasury script for nSidechain; fee =
 *  nPrevTreasury - vout[0] - sum(payouts) >= 0; blind = clear vin and replace
 *  vout[0] with OP_RETURN PUSH8(fee big-endian); m6id = its txid. False if the
 *  tx is not M6-shaped or an amount is out of range. Pure. */
bool ComputeM6id(const CMutableTransaction& mtx, CAmount nPrevTreasury, unsigned int nSidechain, uint256& m6id);

/** One non-coinbase, non-deposit tx of a Succeeded event's L1 block that passed
 *  the treasury-shape prefilter, with the output its single input spends. */
struct M6Candidate {
    int nTx;                    //!< index in the L1 block
    CMutableTransaction mtx;
    CAmount nPrevValue;         //!< value of the spent output (T_{n-1} if it is the CTIP)
    CScript scriptPrev;         //!< script of the spent output
};

/** The index into vCandidate of the M6 whose m6id is `m6id` and whose input
 *  spends a treasury output of the same script (the CTIP): -1 if none matches,
 *  -2 if more than one does (the caller fails closed either way). nMatches gets
 *  the match count. Opcode-agnostic: a lookalike under another OP_NOPx cannot
 *  match the enforcer's m6id, and a second (e.g. foreign) M6 in the same block
 *  has a different m6id. Pure. */
int LocateM6(const std::vector<M6Candidate>& vCandidate, const uint256& m6id, unsigned int nSidechain, int& nMatches);

/** The double-propose guard's decision from a fetched event history: appends
 * the still-pending m6ids to vHashWithdrawalBundle and returns true iff there
 * is at least one (then no new bundle may be proposed). The body of
 * EnforcerL1Client::ListWithdrawalBundleStatus after the fetch. Pure. */
bool L1StillTracksWithdrawalBundle(const std::vector<L1WithdrawalEvent>& vEvents, std::vector<uint256>& vHashWithdrawalBundle);

#endif // BITCOIN_L1CLIENT_H

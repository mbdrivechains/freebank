// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_L1CLIENT_H
#define BITCOIN_L1CLIENT_H

#include <amount.h>
#include <primitives/transaction.h>
#include <uint256.h>

#include <functional>
#include <set>
#include <string>
#include <utility>
#include <vector>

class SidechainDeposit;
class UniValue;

/** Transport used to reach the mainchain (L1). */
enum class L1Transport {
    JSONRPC,  // drivechain-patched mainchain node JSON-RPC (BTX / eCash-v1)
    ENFORCER, // CUSF bip300301_enforcer, Connect over HTTP/1.1 or gRPC via grpcurl (eCash-v2 / Cygnet)
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

/** v0.2.17 D2: the enforcer's BIP300 settings (ValidatorService/GetChainInfo).
 *  They come from its command line (--network-preset), so a wrongly started
 *  enforcer reports other "paid"/"failed" events than everyone else's. */
struct EnforcerSettings {
    uint32_t nBundleMaxAge = 0;
    uint32_t nBundleThreshold = 0;
    uint32_t nUsedSlotMaxAge = 0;
    uint32_t nUsedSlotThreshold = 0;
    uint32_t nUnusedSlotMaxAge = 0;
    uint32_t nUnusedSlotThreshold = 0;
    uint32_t nActivationHeight = 0;
};

/** Parse a GetChainInfo reply (proto3 JSON: a zero field is omitted). Pure. */
bool ParseEnforcerChainInfo(const UniValue& response, EnforcerSettings& settings);

/** "" if an enforcer with these settings suits the L1 forked at nForkHeight
 *  (the -mainchainblockpin height), else what differs. The activation height
 *  must be the fork height; the thresholds are checked where the preset is
 *  known (betanet 967680, alphanet 963648). Pure. */
std::string CompareEnforcerSettings(int nForkHeight, const EnforcerSettings& got);

/** v0.2.17 D2 + D5: ask the enforcer for its settings and compare them with
 *  the -mainchainblockpin fork. OK also when there is nothing to compare (no
 *  pin: regtest, a signet). */
enum class EnforcerSettingsCheck { OK, MISMATCH, NOTREADY };
EnforcerSettingsCheck CheckEnforcerSettings(std::string& strError);

/** v0.2.17 D6: is a -enforceraddr / -mainchainrest "host:port" on this machine
 *  or a private network (loopback, RFC1918, 100.64/10 as tailnets use, fc00::/7)?
 *  The link has no password and no encryption. A host name counts as not
 *  local. Pure. */
bool IsLocalOrPrivateL1Address(const std::string& strHostPort);

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
 * enforcer's ValidatorService over the Connect protocol (a persistent HTTP/1.1
 * JSON client, enforcerconnect.h; the default since v0.2.17) or by shelling out
 * to grpcurl (-enforcertransport=grpcurl). The enforcer is invoked at runtime
 * by service name - nothing of it is vendored or linked.
 */
enum class L1Answer;
struct L1PegEvents;

class L1Client
{
public:
    virtual ~L1Client() {}

    virtual bool BroadcastWithdrawalBundle(const std::string& hex) = 0;
    virtual std::vector<SidechainDeposit> UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex) = 0;
    virtual bool VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx) = 0;
    virtual bool VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime) = 0;
    /* The bid's txid, or null if none came back. On a null txid fNotSent says
     * the L1 definitely sent no bid (a refusal before any broadcast), so the
     * tip may be bid on again; false means a bid may have gone out. */
    virtual uint256 SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount, bool& fNotSent) = 0;
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

    /**
     * v0.2.17 D3: the slot-130 peg events of the L1 blocks after hashStart up
     * to and including hashEnd (hashStart == hashEnd: exactly that block),
     * asked of one bounded range instead of the whole L1 history. YES: events
     * holds them, oldest first. NO: hashStart is not an ancestor of hashEnd.
     * UNKNOWN: anything else (L1 unreachable, hashEnd not processed yet, a reply
     * we cannot fully read). The JSON-RPC mainchain cannot answer it: UNKNOWN.
     */
    virtual L1Answer GetPegEvents(const uint256& hashStart, const uint256& hashEnd, L1PegEvents& events);

    /** v0.2.17 D4: is the L1 view behind its own node (the enforcer's tip
     *  below the -mainchainrest node's)? A bid on a stale L1 tip is wasted and
     *  can block the next one. False when it cannot tell. */
    virtual bool IsBehindItsNode(std::string& strWhy) { return false; }
    virtual bool HaveSpentWithdrawalBundle(const uint256& hash) = 0;
    virtual bool HaveFailedWithdrawalBundle(const uint256& hash) = 0;

    /**
     * v0.2.16: read a mainchain block's slot-130 h* commitment without knowing
     * h* in advance. Unlike VerifyBMM, a failed call (UNKNOWN) is kept apart
     * from "no commitment" (NONE) and "block unknown to the L1" (NOT_FOUND).
     * The BMM JSON-RPCs rely on that split. Only the enforcer transport answers;
     * the legacy transport always says UNKNOWN.
     */
    enum class Commitment { COMMITTED, NONE, NOT_FOUND, UNKNOWN };
    virtual Commitment ReadBmmCommitment(const uint256& hashMainBlock, uint256& hashCommitment)
    {
        hashCommitment.SetNull();
        return Commitment::UNKNOWN;
    }
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

/** v0.2.17: how the enforcer transport reaches the enforcer (-enforcertransport). */
enum class EnforcerTransport {
    CONNECT, // Connect protocol: JSON over a persistent HTTP/1.1 connection (enforcerconnect.h)
    GRPCURL, // one grpcurl process per call (-grpcurlbin); the fallback
};
static const char* const DEFAULT_ENFORCER_TRANSPORT = "connect";

/** True if strTransport names a valid -enforcertransport value (connect | grpcurl). */
bool IsValidEnforcerTransport(const std::string& strTransport);

/** The transport -enforcertransport selects; read on every call. */
EnforcerTransport GetEnforcerTransport();

/** How a failed call's status is named in the log: "grpcurl exit" or "connect status". */
std::string EnforcerStatusLabel();

/** The shell command the enforcer transport runs for one grpcurl call. The binary path is
 *  double-quoted (BitWindow's macOS path contains a space); a path containing a double quote
 *  cannot be quoted safely and yields "". stderr goes to /dev/null, or into stdout if fStderr.
 *  nMaxTime is grpcurl's -max-time. Pure, unit-tested. */
std::string BuildGrpcurlCommand(const std::string& strBin, const std::string& strRequest, const std::string& strAddr, const std::string& strService, const std::string& strMethod, bool fStderr = false, int nMaxTime = 15);

/** Where the enforcer transport's grpcurl is (v0.2.17). */
struct GrpcurlLocation {
    std::string strPath;   //!< what is run; "grpcurl" (a bare PATH lookup by the shell) if none was found
    std::string strSource; //!< "-grpcurlbin", "PATH", "next to freebankd", or the directory searched
    bool fFound = false;
};

/** The default search when -grpcurlbin is not set: each PATH entry, then strExeDir (freebankd's
 *  directory), then /opt/homebrew/bin and /usr/local/bin (a macOS GUI launch has a bare PATH).
 *  fnIsExecutable is injected so the order can be unit-tested. Pure. */
GrpcurlLocation FindGrpcurl(const std::string& strPathEnv, const std::string& strExeDir,
                            const std::function<bool(const std::string&)>& fnIsExecutable);

/** -grpcurlbin as given if set (fFound says whether it exists), else FindGrpcurl over the real
 *  PATH and executable directory. A hit is cached; a miss is looked up again after 30 s, so a
 *  grpcurl installed later is picked up. Logs the choice whenever it changes. */
GrpcurlLocation GetGrpcurlLocation();

/** How one enforcer call failed, as far as the withdrawal-bundle fallback (D7) cares. The
 *  Connect transport reports its outcome in grpcurl's exit convention (enforcerconnect.h), so
 *  this classifier and GrpcurlBMMRequestNotSent serve both transports. */
enum class GrpcurlFailure {
    NONE,          // exit 0
    UNIMPLEMENTED, // the enforcer does not have this method
    OTHER,         // anything else: down, timeout, any other gRPC code - may be transient
};

/** Classify a grpcurl run from its exit status and stderr. Checked 2026-09-26 with grpcurl v1.9.1
 *  against enforcer 73d239a: a gRPC error from the server exits 64 + its code (Unimplemented = 12
 *  -> 76, FailedPrecondition -> 73); grpcurl's own errors exit 1. A method missing from the
 *  server's reflection (an enforcer older than the method) never reaches the server: exit 1 with
 *  'does not include a method named' (or 'does not expose service' for a whole service). Both
 *  count as UNIMPLEMENTED; a failed dial is also exit 1 but OTHER. Pure. */
GrpcurlFailure ClassifyGrpcurlFailure(int nExit, const std::string& strError);

/** True if a failed WalletService/CreateBmmCriticalDataTransaction call (grpcurl exit nExit, output
 *  strError) definitely sent no bid. The enforcer (73d239a, lib/server/wallet/grpc.rs and
 *  lib/wallet/mod.rs create_bmm_request) refuses with InvalidArgument (stale prev_bytes, 67) or
 *  FailedPrecondition (inactive sidechain, 73) before building the tx, and a build or sign failure
 *  (e.g. an unfunded wallet) says so in its Unknown (66) message. A failed dial, a missing binary
 *  and an UNIMPLEMENTED method never reach it. Everything else - a timeout, an Unknown from the
 *  broadcast, any other code, a killed grpcurl - may come after the bid went out. Pure. */
bool GrpcurlBMMRequestNotSent(int nExit, const std::string& strError);

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
    // v0.2.17 D7: what a Succeeded event carries (ParsePegEvents fills them
    // when present): the treasury's running number and the M6 itself
    bool fHaveSequence = false;
    uint64_t nSequence = 0;
    std::vector<unsigned char> vchTx;
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

/** How one L1 raw-tx fetch ended. UNDECODABLE: the L1 returned the bytes but
 *  FreeBank's decoder cannot read them. An eCash v3 (TRUC) tx is one: FreeBank's
 *  own v3 layout reads a replay byte after nVersion, which TRUC does not have. */
enum class L1TxFetch { OK, FAILED, UNDECODABLE };

/** Classify a REST /rest/tx/<txid>.hex body (trailing whitespace trimmed): FAILED
 *  if it is empty or not hex (a misbehaving server, not an unreadable tx), else OK
 *  or UNDECODABLE by FreeBank's DecodeHexTx. Pure. */
L1TxFetch ClassifyRawTxBody(std::string body, CMutableTransaction& tx);

/** v0.2.17: find tx txid in a raw L1 block (its bytes), reading every tx in the
 *  L1's layout: OK with the tx and its index; FAILED if it is not there;
 *  UNDECODABLE if the block cannot be read. Pure. */
L1TxFetch FindL1TxInBlock(const std::vector<unsigned char>& vchBlock, const uint256& txid, CMutableTransaction& tx, int& nTx);

/** The double-propose guard's decision from a fetched event history: appends
 * the still-pending m6ids to vHashWithdrawalBundle and returns true iff there
 * is at least one (then no new bundle may be proposed). The body of
 * EnforcerL1Client::ListWithdrawalBundleStatus after the fetch. Pure. */
bool L1StillTracksWithdrawalBundle(const std::vector<L1WithdrawalEvent>& vEvents, std::vector<uint256>& vHashWithdrawalBundle);

//
// v0.2.17 P3: the L1 questions consensus asks, behind one injectable.
//
// Design (docs-local/SOFTFORK_V0216_DESIGN_DRAFT.md 3.1): every consensus
// question to the L1 has three answers. YES; NO, a definite answer from a
// successful call with a fully recognised response (the block is invalid);
// UNKNOWN, anything else (the block is not marked, it is retried).
//

enum class L1Answer { YES, NO, UNKNOWN };

/** One slot-130 deposit event of an L1 block (enforcer GetTwoWayPegData,
 *  validator.proto Deposit). ParsePegEvents fills every field or fails. */
struct L1DepositEvent {
    uint256 hashMainBlock;
    COutPoint outpoint;              //!< (MainchainTxid, vout) of the new treasury output
    uint64_t nSequence = 0;          //!< the treasury's running number (deposits and M6s share it)
    CAmount nValue = 0;              //!< output.value_sats: what this deposit added to the treasury
    std::vector<unsigned char> vchAddress; //!< output.address.hex; empty if absent or ""
};

/** The slot-130 events of one L1 block or window, oldest first. */
struct L1PegEvents {
    std::vector<L1DepositEvent> vDeposit;
    std::vector<L1WithdrawalEvent> vWithdrawal;
};

/**
 * L1Oracle: the L1 answers ConnectBlock and CheckBlock depend on, asked as of a
 * named L1 block, never the enforcer's current tip. GetL1Oracle() is the
 * transport-backed oracle unless a unit test injected one (SetL1OracleForTest),
 * so the peg-binding tests (src/test/pegbind_tests.cpp) can give any
 * YES/NO/UNKNOWN answer without a mainchain.
 *
 * v0.2.17: one question, the peg events of a range of L1 blocks
 * (L1Client::GetPegEvents). ConnectBlock's bundle-mark check (B3) asks it.
 */
class L1Oracle
{
public:
    virtual ~L1Oracle() {}

    /** The slot-130 events of the L1 blocks in (hashStart, hashEnd], or of
     *  exactly hashEnd if hashStart == hashEnd (L1Client::GetPegEvents). The one
     *  question the v0.2.17 peg checks ask. */
    virtual L1Answer EventsInWindow(const uint256& hashStart, const uint256& hashEnd, L1PegEvents& events) = 0;

    /** v0.2.17 C1: does L1 block hashMainBlock carry the BMM bid hashBMM
     *  (h*) for this sidechain? YES; NO (the L1 has processed the block and it
     *  carries no bid or another one); UNKNOWN (not processed yet, or no
     *  answer). */
    virtual L1Answer BmmCommitment(const uint256& hashMainBlock, const uint256& hashBMM) = 0;
};

/** v0.2.17 B3 + D1, decisions 2026-09-29: a bundle's outcome on the L1 from
 *  its events (oldest first). 'S' if any event says paid: a payment is final
 *  (a paid bundle proposed again and failed must not count as failed). Else
 *  the last event: 'F' failed, 'U' proposed again after a failure; 0 if none.
 *  Pure. */
char BundleOutcome(const std::vector<L1WithdrawalEvent>& vEvents, const uint256& m6id);

/** The enforcer's m6id of a FreeBank bundle: the txid of the bundle tx with
 *  its inputs stripped (enforcer compute_m6id of the zero-input BlindedM6).
 *  Pure. */
uint256 BundleM6id(const CTransaction& txBundle);

/** v0.2.17 D3: parse a GetTwoWayPegData reply strictly. Every event must be a
 *  deposit or a withdrawal-bundle event with all its fields; anything else
 *  (a missing field, an event kind we do not know) fails the whole reply, so
 *  a reply we cannot fully read is never taken for "no such event". proto3
 *  JSON omits an empty list: no "blocks" or no "events" is none. Pure. */
bool ParsePegEvents(const UniValue& response, L1PegEvents& events);

/** v0.2.17 D3: what a failed GetTwoWayPegData call means. NO only for the
 *  enforcer's "start block is not an ancestor of end block"; UNKNOWN for
 *  everything else ("end block not found": not processed yet; transport
 *  errors; timeouts). Pure. */
L1Answer ClassifyPegEventsError(const std::string& strError);

/** The injected test oracle if one is set, else the transport-backed one. */
L1Oracle& GetL1Oracle();

/** Unit tests only: answer every L1Oracle question from pOracle (nullptr
 *  restores the transport-backed oracle). Never called outside src/test. */
void SetL1OracleForTest(L1Oracle* pOracle);

/** Unit tests only: GetL1Client() returns pClient (nullptr restores the
 *  transport's client). Never called outside src/test. */
void SetL1ClientForTest(L1Client* pClient);

#endif // BITCOIN_L1CLIENT_H

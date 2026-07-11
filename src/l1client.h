// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_L1CLIENT_H
#define BITCOIN_L1CLIENT_H

#include <amount.h>
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
    virtual bool HaveSpentWithdrawalBundle(const uint256& hash) = 0;
    virtual bool HaveFailedWithdrawalBundle(const uint256& hash) = 0;
};

/** Transport selected by -mainchaintransport (jsonrpc | enforcer). */
L1Transport GetL1Transport();

/** Process-wide L1 client for the selected transport. */
L1Client& GetL1Client();

/** True if strTransport names a valid -mainchaintransport value. */
bool IsValidL1Transport(const std::string& strTransport);

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
 * event's ConsensusHex. */
struct L1WithdrawalEvent {
    uint256 m6id;
    char status;
    L1WithdrawalEvent() : status(0) {}
};

/** Parse a GetTwoWayPegData response into withdrawal-bundle events (deposits
 * ignored). Used by HaveSpent/HaveFailedWithdrawalBundle + ListWithdrawalBundleStatus. */
bool ParseEnforcerWithdrawalEvents(const UniValue& response, std::vector<L1WithdrawalEvent>& vEvents);

#endif // BITCOIN_L1CLIENT_H

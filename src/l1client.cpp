// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <l1client.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <core_io.h>
#include <enforcerconnect.h>
#include <sidechain.h>
#include <uint256.h>
#include <univalue.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <hash.h>
#include <netbase.h>
#include <primitives/block.h>
#include <streams.h>
#include <txdb.h>
#include <util.h>
#include <validation.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <climits>
#include <limits>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

#include <boost/array.hpp>
#include <boost/asio.hpp>
#include <boost/foreach.hpp>
#include <boost/property_tree/json_parser.hpp>

using boost::asio::ip::tcp;

//
// JsonRpcL1Client - the legacy drivechain JSON-RPC transport. Method bodies
// moved verbatim from SidechainClient (which is now a facade over L1Client).
//

class JsonRpcL1Client final : public L1Client
{
public:
    bool BroadcastWithdrawalBundle(const std::string& hex) override;
    std::vector<SidechainDeposit> UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex) override;
    bool VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx) override;
    bool VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime) override;
    uint256 SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount, bool& fNotSent) override;
    bool GetCTIP(std::pair<uint256, uint32_t>& ctip) override;
    bool GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFees) override;
    bool GetBlockCount(int& nBlocks) override;
    bool GetWorkScore(const uint256& hash, int& nWorkScore) override;
    bool ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle) override;
    bool GetBlockHash(int nHeight, uint256& hashBlock) override;
    bool GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash) override;
    bool HaveSpentWithdrawalBundle(const uint256& hash) override;
    bool HaveFailedWithdrawalBundle(const uint256& hash) override;

private:
    /*
     * Send json request to local node
     */
    bool SendRequestToMainchain(const std::string& json, boost::property_tree::ptree& ptree);
};

//
// EnforcerL1Client - the CUSF bip300301_enforcer transport, over the Connect
// protocol (HTTP/1.1 + JSON, enforcerconnect.h; the v0.2.17 default) or by
// shelling out to grpcurl (-enforcertransport=grpcurl): mainchain state and
// withdrawal-bundle events from ValidatorService,
// BMM requests from WalletService (SendBMMRequest needs the enforcer wallet),
// withdrawal bundles to BlockProducerService/ProposeWithdrawalBundle (with a
// fallback to WalletService/BroadcastWithdrawalBundle for enforcers older than
// 7958cef), and deposit txs from the mainchain node's REST interface
// (-mainchainrest).
//

class EnforcerL1Client final : public L1Client
{
public:
    bool BroadcastWithdrawalBundle(const std::string& hex) override;
    std::vector<SidechainDeposit> UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex) override;
    bool VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx) override;
    bool VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime) override;
    uint256 SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount, bool& fNotSent) override;
    bool GetCTIP(std::pair<uint256, uint32_t>& ctip) override;
    bool GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFees) override;
    bool GetBlockCount(int& nBlocks) override;
    bool GetWorkScore(const uint256& hash, int& nWorkScore) override;
    bool ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle) override;
    bool GetBlockHash(int nHeight, uint256& hashBlock) override;
    bool GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash) override;
    bool HaveSpentWithdrawalBundle(const uint256& hash) override;
    bool HaveFailedWithdrawalBundle(const uint256& hash) override;
    Commitment ReadBmmCommitment(const uint256& hashMainBlock, uint256& hashCommitment) override;
    L1Answer GetPegEvents(const uint256& hashStart, const uint256& hashEnd, L1PegEvents& events) override;
    bool IsBehindItsNode(std::string& strWhy) override;

    /* The init-time REST reachability probe borrows the private RestGet. */
    friend bool ::ProbeMainchainRest(std::string& strError, bool* pfIdentityMismatch);
    friend EnforcerIdentity (::ProbeEnforcerIdentity)(std::string& strError, bool* pfStale);
    friend EnforcerSettingsCheck (::CheckEnforcerSettings)(std::string& strError);

private:
    /*
     * Invoke a ValidatorService method and parse the JSON reply. The enforcer
     * is only ever invoked at runtime by service name - nothing of it is
     * vendored or linked.
     */
    bool CallValidator(const std::string& strMethod, const std::string& strRequest, UniValue& result);

    /* Invoke a WalletService method (write-path). */
    bool CallWallet(const std::string& strMethod, const std::string& strRequest, UniValue& result);

    /* Shared call for any enforcer service. */
    bool CallEnforcer(const std::string& strService, const std::string& strMethod, const std::string& strRequest, UniValue& result);

    /* The same call when the reply is not needed. Returns the call's status in
     * grpcurl's exit convention (-1 if it could not be run) and its error text
     * in strError, so the caller can tell a method the enforcer lacks from a
     * transient failure (ClassifyGrpcurlFailure). */
    int CallEnforcerStatus(const std::string& strService, const std::string& strMethod, const std::string& strRequest, std::string& strError);

    /* v0.2.17: run one enforcer call on the transport -enforcertransport
     * selects. The reply (or, if fStderr, the error text too) goes to
     * strOutput. Returns the status in grpcurl's exit convention (0 ok, 64 +
     * gRPC code for an enforcer error, 1 client side, -1 could not run), which
     * the Connect client reports as well (enforcerconnect.h). fRetrySafe=false
     * for a call with a side effect a repeat could double (the BMM bid).
     * nTimeoutSecs bounds the call (default 15 s, at most 60 s). */
    int RunEnforcerCall(const std::string& strService, const std::string& strMethod, const std::string& strRequest, bool fStderr, std::string& strOutput,
                        bool fRetrySafe = true, int nTimeoutSecs = enforcerconnect::DEFAULT_CALL_TIMEOUT);

    /* Run one grpcurl call; stdout (with stderr merged in if fStderr) goes to
     * strOutput. Returns the exit status, or -1 if it could not be run. */
    int RunGrpcurl(const std::string& strService, const std::string& strMethod, const std::string& strRequest, bool fStderr, std::string& strOutput,
                   int nTimeoutSecs = enforcerconnect::DEFAULT_CALL_TIMEOUT);

    /* The persistent Connect-protocol client (-enforcertransport=connect) */
    enforcerconnect::Client connectClient;

    /* One enforcer method that takes a withdrawal bundle (D7) */
    struct BundleMethod {
        const char* pszService;
        const char* pszMethod;
    };

    /* Log a failed withdrawal-bundle call once per method and exit status */
    void LogBundleFailure(const BundleMethod& method, int nExit, const std::string& strError, const std::string& strHint);

    /* GetChainTip convenience wrapper */
    bool GetChainTip(L1BlockHeader& header);

    /* GetBlockHeaderInfo for hashBlock plus up to nMaxAncestors ancestors */
    bool GetHeaderInfos(const uint256& hashBlock, uint32_t nMaxAncestors, std::vector<L1BlockHeader>& vHeader);

    /* Mainchain REST helpers (-mainchainrest=<host:port>) for the deposit path:
     * the enforcer's Deposit event lacks the raw tx (needed for CTIP-chain
     * ordering + cumulative CTIP amount) and the tx-index-in-block (nTx), so we
     * fetch them from the mainchain node's REST interface. */
    bool RestGet(const std::string& strPath, std::string& strBody);
    bool RestGetBlockTxids(const uint256& hashBlock, std::vector<uint256>& vTxid);
    /* v0.2.17: tx txid of L1 block hashBlock, and its index there, read from
     * the block itself (/rest/block/<hash>.hex). No -txindex needed: on a node
     * started from an assumeutxo snapshot the tx index covers only the
     * background chainstate, and /rest/tx answers 404 for weeks. */
    L1TxFetch RestGetTxFromBlock(const uint256& hashBlock, const uint256& txid, CMutableTransaction& tx, int& nTx);

    /* Fetch all withdrawal-bundle events for THIS_SIDECHAIN via GetTwoWayPegData. */
    bool FetchWithdrawalEvents(std::vector<L1WithdrawalEvent>& vEvents);

    /* Log a message once per key */
    void LogOnce(const std::string& strKey, const std::string& strMessage);

    /* Log an unimplemented-method warning once per method */
    void LogUnimplemented(const std::string& strMethod, const std::string& strReason);

    std::mutex mutexLogged;
    std::set<std::string> setLogged;

    /* D7: true once WalletService/BroadcastWithdrawalBundle has taken a bundle
     * after ProposeWithdrawalBundle answered Unimplemented (an enforcer older
     * than 7958cef). Changed only by a successful call on the other method,
     * never by a transient failure. */
    std::atomic<bool> fBundleViaWallet{false};

};

//
// Enforcer wire helpers
//

uint256 Uint256FromConsensusHex(const std::string& strHex)
{
    if (strHex.size() != 64 || !IsHex(strHex))
        return uint256();

    // ConsensusHex is internal byte order; uint256's string form is the
    // reverse (display order)
    std::vector<unsigned char> vch = ParseHex(strHex);
    uint256 ret;
    std::copy(vch.begin(), vch.end(), ret.begin());
    return ret;
}

std::string ConsensusHexFromUint256(const uint256& hash)
{
    return HexStr(hash.begin(), hash.end());
}

/** Read a {"hex": "..."} wrapper (ReverseHex / ConsensusHex / Hex). */
static bool GetHexField(const UniValue& obj, std::string& strHex)
{
    if (!obj.isObject())
        return false;

    const UniValue& hex = find_value(obj, "hex");
    if (!hex.isStr())
        return false;

    strHex = hex.get_str();
    return IsHex(strHex);
}

/** Parse one BlockHeaderInfo object. proto3 JSON omits zero-value fields. */
static bool ParseHeaderObject(const UniValue& obj, L1BlockHeader& header)
{
    if (!obj.isObject())
        return false;

    std::string strHash;
    if (!GetHexField(find_value(obj, "blockHash"), strHash))
        return false;
    header.hashBlock = uint256S(strHash);

    std::string strPrevHash;
    if (GetHexField(find_value(obj, "prevBlockHash"), strPrevHash))
        header.hashPrevBlock = uint256S(strPrevHash);
    else
        header.hashPrevBlock.SetNull();

    // Absent height / timestamp = proto3 zero default (genesis / unset)
    const UniValue& height = find_value(obj, "height");
    header.nHeight = height.isNum() ? height.get_int() : 0;

    const UniValue& timestamp = find_value(obj, "timestamp");
    if (timestamp.isNull())
        header.nTime = 0;
    else
        header.nTime = (uint32_t)atoi64(timestamp.getValStr());

    return true;
}

bool ParseEnforcerChainTip(const UniValue& response, L1BlockHeader& header)
{
    if (!response.isObject())
        return false;

    return ParseHeaderObject(find_value(response, "blockHeaderInfo"), header);
}

bool ParseEnforcerHeaderInfos(const UniValue& response, std::vector<L1BlockHeader>& vHeader)
{
    vHeader.clear();

    if (!response.isObject())
        return false;

    const UniValue& infos = find_value(response, "headerInfos");
    if (!infos.isArray())
        return false;

    for (size_t i = 0; i < infos.size(); i++) {
        L1BlockHeader header;
        if (!ParseHeaderObject(infos[i], header))
            return false;

        vHeader.push_back(header);
    }

    return !vHeader.empty();
}

bool ParseEnforcerBmmCommitment(const UniValue& response, bool& fBlockFound, bool& fHaveCommitment, uint256& hashCommitment)
{
    fBlockFound = false;
    fHaveCommitment = false;
    hashCommitment.SetNull();

    if (!response.isObject())
        return false;

    if (find_value(response, "blockNotFound").isObject())
        return true;

    const UniValue& commitment = find_value(response, "commitment");
    if (!commitment.isObject())
        return false;

    fBlockFound = true;

    // Block known, but no h* committed for this sidechain
    std::string strHex;
    if (!GetHexField(find_value(commitment, "commitment"), strHex))
        return true;

    // BlockInfo.bmm_commitment is ConsensusHex (internal byte order)
    hashCommitment = Uint256FromConsensusHex(strHex);
    fHaveCommitment = !hashCommitment.IsNull();

    return true;
}

bool ParseEnforcerBlockDepositTxids(const UniValue& response, std::vector<uint256>& vTxid)
{
    vTxid.clear();

    if (!response.isObject())
        return false;

    const UniValue& infos = find_value(response, "infos");
    if (!infos.isArray() || infos.empty())
        return false;

    // Ancestors are newest-first; [0] is the requested block
    const UniValue& blockInfo = find_value(infos[0], "blockInfo");
    if (!blockInfo.isObject())
        return true;

    const UniValue& events = find_value(blockInfo, "events");
    if (!events.isArray())
        return true;

    for (size_t i = 0; i < events.size(); i++) {
        const UniValue& deposit = find_value(events[i], "deposit");
        if (!deposit.isObject())
            continue;

        std::string strTxid;
        if (!GetHexField(find_value(find_value(deposit, "outpoint"), "txid"), strTxid))
            continue;

        vTxid.push_back(uint256S(strTxid));
    }

    return true;
}

bool ParseEnforcerCtip(const UniValue& response, uint256& txid, uint32_t& n)
{
    if (!response.isObject())
        return false;

    const UniValue& ctip = find_value(response, "ctip");
    if (!ctip.isObject())
        return false;

    std::string strTxid;
    if (!GetHexField(find_value(ctip, "txid"), strTxid))
        return false;

    txid = uint256S(strTxid);

    // Absent vout = proto3 zero default
    const UniValue& vout = find_value(ctip, "vout");
    n = vout.isNum() ? (uint32_t)vout.get_int() : 0;

    return true;
}

bool ParseEnforcerWithdrawalEvents(const UniValue& response, std::vector<L1WithdrawalEvent>& vEvents)
{
    vEvents.clear();

    if (!response.isObject())
        return false;

    const UniValue& blocks = find_value(response, "blocks");
    if (!blocks.isArray())
        return true; // no peg data is a valid empty result

    for (size_t b = 0; b < blocks.size(); b++) {
        // Block hash (ReverseHex == display order) - null if absent
        uint256 hashBlock;
        std::string strBlockHash;
        if (GetHexField(find_value(find_value(blocks[b], "blockHeaderInfo"), "blockHash"), strBlockHash))
            hashBlock = uint256S(strBlockHash);

        const UniValue& events = find_value(find_value(blocks[b], "blockInfo"), "events");
        if (!events.isArray())
            continue;

        for (size_t e = 0; e < events.size(); e++) {
            const UniValue& wb = find_value(events[e], "withdrawalBundle");
            if (!wb.isObject())
                continue;

            L1WithdrawalEvent ev;
            ev.hashMainBlock = hashBlock;
            std::string strM6;
            // m6id is ConsensusHex (internal byte order), like bmm_commitment
            if (!GetHexField(find_value(wb, "m6id"), strM6))
                continue;
            ev.m6id = Uint256FromConsensusHex(strM6);
            if (ev.m6id.IsNull())
                continue;

            const UniValue& event = find_value(wb, "event");
            if (find_value(event, "succeeded").isObject())
                ev.status = 'S';
            else if (find_value(event, "failed").isObject())
                ev.status = 'F';
            else if (find_value(event, "submitted").isObject())
                ev.status = 'U';
            else
                continue;

            vEvents.push_back(ev);
        }
    }
    return true;
}

/** A proto3 JSON uint64 (a decimal string) or uint32 (a number). */
static bool GetUInt64Field(const UniValue& v, uint64_t& n)
{
    if (v.isNum()) {
        const std::string str = v.getValStr();
        return !str.empty() && str.find_first_not_of("0123456789") == std::string::npos && ParseUInt64(str, &n);
    }
    if (v.isStr()) {
        const std::string& str = v.get_str();
        return !str.empty() && str.find_first_not_of("0123456789") == std::string::npos && ParseUInt64(str, &n);
    }
    return false;
}

/** A 32-byte hash field ({"hex": <64 hex chars>}). */
static bool GetHash32Field(const UniValue& obj, std::string& strHex)
{
    return GetHexField(obj, strHex) && strHex.size() == 64;
}

static bool ParsePegEventsInner(const UniValue& response, L1PegEvents& events)
{
    if (!response.isObject())
        return false;

    const UniValue& blocks = find_value(response, "blocks");
    if (blocks.isNull())
        return true;
    if (!blocks.isArray())
        return false;

    for (size_t b = 0; b < blocks.size(); b++) {
        std::string strBlockHash;
        if (!GetHash32Field(find_value(find_value(blocks[b], "blockHeaderInfo"), "blockHash"), strBlockHash))
            return false;
        const uint256 hashBlock = uint256S(strBlockHash);

        const UniValue& info = find_value(blocks[b], "blockInfo");
        if (!info.isObject())
            return false;
        const UniValue& vEvent = find_value(info, "events");
        if (vEvent.isNull())
            continue; // a block listed for its BMM commitment only
        if (!vEvent.isArray())
            return false;

        for (size_t e = 0; e < vEvent.size(); e++) {
            if (!vEvent[e].isObject())
                return false;
            const UniValue& dep = find_value(vEvent[e], "deposit");
            const UniValue& wb = find_value(vEvent[e], "withdrawalBundle");
            if (dep.isObject() == wb.isObject())
                return false; // neither (an event kind we do not know) or both

            if (dep.isObject()) {
                L1DepositEvent d;
                d.hashMainBlock = hashBlock;
                if (!GetUInt64Field(find_value(dep, "sequenceNumber"), d.nSequence))
                    return false;
                const UniValue& outpoint = find_value(dep, "outpoint");
                std::string strTxid;
                uint64_t nVout;
                if (!GetHash32Field(find_value(outpoint, "txid"), strTxid) ||
                        !GetUInt64Field(find_value(outpoint, "vout"), nVout) || nVout > std::numeric_limits<uint32_t>::max())
                    return false;
                d.outpoint = COutPoint(uint256S(strTxid), (uint32_t)nVout);
                const UniValue& output = find_value(dep, "output");
                if (!output.isObject())
                    return false;
                uint64_t nValue;
                if (!GetUInt64Field(find_value(output, "valueSats"), nValue) || !MoneyRange((CAmount)nValue))
                    return false;
                d.nValue = (CAmount)nValue;
                // The address may be empty: absent, {} or {"hex": ""}
                const UniValue& address = find_value(output, "address");
                if (!address.isNull()) {
                    if (!address.isObject())
                        return false;
                    const UniValue& hex = find_value(address, "hex");
                    if (!hex.isNull()) {
                        if (!hex.isStr() || (!hex.get_str().empty() && !IsHex(hex.get_str())))
                            return false;
                        d.vchAddress = ParseHex(hex.get_str());
                    }
                }
                events.vDeposit.push_back(d);
            } else {
                L1WithdrawalEvent ev;
                ev.hashMainBlock = hashBlock;
                std::string strM6;
                if (!GetHash32Field(find_value(wb, "m6id"), strM6))
                    return false;
                ev.m6id = Uint256FromConsensusHex(strM6);
                const UniValue& event = find_value(wb, "event");
                const bool fSucceeded = find_value(event, "succeeded").isObject();
                const bool fFailed = find_value(event, "failed").isObject();
                const bool fSubmitted = find_value(event, "submitted").isObject();
                if (fSucceeded + fFailed + fSubmitted != 1)
                    return false;
                ev.status = fSucceeded ? 'S' : fFailed ? 'F' : 'U';
                if (fSucceeded) {
                    // D7: the running number and the M6, when sent
                    const UniValue& succeeded = find_value(event, "succeeded");
                    const UniValue& seq = find_value(succeeded, "sequenceNumber");
                    if (!seq.isNull()) {
                        if (!GetUInt64Field(seq, ev.nSequence))
                            return false;
                        ev.fHaveSequence = true;
                    }
                    const UniValue& tx = find_value(succeeded, "transaction");
                    if (!tx.isNull()) {
                        std::string strTx;
                        if (!GetHexField(tx, strTx))
                            return false;
                        ev.vchTx = ParseHex(strTx);
                    }
                }
                events.vWithdrawal.push_back(ev);
            }
        }
    }
    return true;
}

bool ParsePegEvents(const UniValue& response, L1PegEvents& events)
{
    events = L1PegEvents();
    if (ParsePegEventsInner(response, events))
        return true;
    events = L1PegEvents(); // never half a reply
    return false;
}

L1Answer ClassifyPegEventsError(const std::string& strError)
{
    if (strError.find("is not an ancestor of end block") != std::string::npos)
        return L1Answer::NO;
    return L1Answer::UNKNOWN;
}

L1Answer L1Client::GetPegEvents(const uint256&, const uint256&, L1PegEvents& events)
{
    events = L1PegEvents();
    return L1Answer::UNKNOWN;
}

std::vector<uint256> PendingM6idsFromEvents(const std::vector<L1WithdrawalEvent>& vEvents)
{
    std::vector<uint256> vPending;
    for (const L1WithdrawalEvent& e : vEvents) {
        std::vector<uint256>::iterator it = std::find(vPending.begin(), vPending.end(), e.m6id);
        if (e.status == 'U') {
            if (it == vPending.end())
                vPending.push_back(e.m6id);
        } else if (e.status == 'S' || e.status == 'F') {
            if (it != vPending.end())
                vPending.erase(it);
        }
    }
    return vPending;
}

bool L1StillTracksWithdrawalBundle(const std::vector<L1WithdrawalEvent>& vEvents, std::vector<uint256>& vHashWithdrawalBundle)
{
    const std::vector<uint256> vPending = PendingM6idsFromEvents(vEvents);
    vHashWithdrawalBundle.insert(vHashWithdrawalBundle.end(), vPending.begin(), vPending.end());
    return !vPending.empty();
}

unsigned char TreasuryScriptOpcode(const CScript& script, unsigned int nSidechain)
{
    if (nSidechain > 0xff || script.size() != 4)
        return 0;
    const unsigned char op = script[0];
    const bool fUpgradableNop = op == OP_NOP1 || (op >= OP_NOP4 && op <= OP_NOP10);
    if (!fUpgradableNop)
        return 0;
    if (script[1] != 0x01 || script[2] != (unsigned char)nSidechain || script[3] != OP_TRUE)
        return 0;
    return op;
}

bool ComputeM6id(const CMutableTransaction& mtx, CAmount nPrevTreasury, unsigned int nSidechain, uint256& m6id)
{
    if (mtx.vin.size() != 1 || mtx.vout.empty() || !IsTreasuryScript(mtx.vout[0].scriptPubKey, nSidechain))
        return false;
    if (!MoneyRange(nPrevTreasury))
        return false;
    const CAmount nTreasuryNew = mtx.vout[0].nValue;
    if (!MoneyRange(nTreasuryNew))
        return false;
    CAmount nPayout = 0;
    for (size_t i = 1; i < mtx.vout.size(); i++) {
        if (!MoneyRange(mtx.vout[i].nValue))
            return false;
        nPayout += mtx.vout[i].nValue;
        if (!MoneyRange(nPayout))
            return false;
    }
    const CAmount nFee = nPrevTreasury - nTreasuryNew - nPayout;
    if (nFee < 0 || !MoneyRange(nFee))
        return false;

    CMutableTransaction mtxBlind(mtx);
    mtxBlind.vin.clear();
    mtxBlind.vout[0] = CTxOut(0, EncodeWithdrawalFeesCUSF(nFee));
    m6id = L1MutableTransaction(mtxBlind).GetHash(); // the L1 layout (A5), as the enforcer hashes it
    return true;
}


L1TxFetch FindL1TxInBlock(const std::vector<unsigned char>& vchBlock, const uint256& txid, CMutableTransaction& tx, int& nTx)
{
    nTx = -1;
    try {
        CDataStream ss(vchBlock, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_L1);
        ss.ignore(80); // the L1 block header
        const uint64_t nTxs = ReadCompactSize(ss);
        for (uint64_t i = 0; i < nTxs; i++) {
            L1MutableTransaction txL1;
            ss >> txL1;
            if (txL1.GetHash() == txid) {
                tx = txL1;
                nTx = (int)i;
                return L1TxFetch::OK;
            }
        }
    } catch (const std::exception&) {
        return L1TxFetch::UNDECODABLE;
    }
    return L1TxFetch::FAILED; // not in that block
}

L1TxFetch ClassifyRawTxBody(std::string body, CMutableTransaction& tx)
{
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r' || body.back() == ' '))
        body.pop_back();

    // A non-hex body is a misbehaving REST server, not an unreadable tx.
    if (body.empty() || !IsHex(body))
        return L1TxFetch::FAILED;

    // v0.2.17 A5: an L1 tx, read in the plain Bitcoin layout (with witness
    // if it has one, as DecodeHexTx tries), never FreeBank's own layouts
    const std::vector<unsigned char> vch = ParseHex(body);
    for (const int nVersionFlags : {PROTOCOL_VERSION, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS}) {
        CDataStream ss(vch, SER_NETWORK, nVersionFlags | SERIALIZE_TRANSACTION_L1);
        try {
            L1MutableTransaction txL1;
            ss >> txL1;
            if (ss.empty()) {
                tx = txL1;
                return L1TxFetch::OK;
            }
        } catch (const std::exception&) {
        }
    }
    return L1TxFetch::UNDECODABLE;
}


//
// EnforcerL1Client
//

int EnforcerL1Client::RunEnforcerCall(const std::string& strService, const std::string& strMethod, const std::string& strRequest, bool fStderr, std::string& strOutput,
                                      bool fRetrySafe, int nTimeoutSecs)
{
    if (GetEnforcerTransport() == EnforcerTransport::GRPCURL)
        return RunGrpcurl(strService, strMethod, strRequest, fStderr, strOutput, nTimeoutSecs);

    const std::string strAddr = gArgs.GetArg("-enforceraddr", "127.0.0.1:50051");
    std::string strReply;
    int nStatus = connectClient.Call(strAddr, strService, strMethod, strRequest, nTimeoutSecs, fRetrySafe, strReply);
    // grpcurl sent its error text to stderr: into the output only if fStderr
    if (nStatus == 0 || fStderr)
        strOutput += strReply;
    return nStatus;
}

int EnforcerL1Client::RunGrpcurl(const std::string& strService, const std::string& strMethod, const std::string& strRequest, bool fStderr, std::string& strOutput,
                                 int nTimeoutSecs)
{
    // Requests are built internally from hex strings and integers only; the
    // binary and address come from the node operator's own configuration.
    // (base64 in the withdrawal-bundle payload has no single quote, so the
    // single-quoted -d '...' stays safe.)
    if (strRequest.find('\'') != std::string::npos)
        return -1;

    std::string strBin = GetGrpcurlLocation().strPath;
    std::string strAddr = gArgs.GetArg("-enforceraddr", "127.0.0.1:50051");

    std::string strCommand = BuildGrpcurlCommand(strBin, strRequest, strAddr, strService, strMethod, fStderr, nTimeoutSecs);
    if (strCommand.empty()) {
        LogOnce("grpcurl-badpath", "ERROR Enforcer client: -grpcurlbin path '" + strBin +
            "' contains a double quote and cannot be run; set -grpcurlbin to a plain path\n");
        return -1;
    }

    FILE* pipe = popen(strCommand.c_str(), "r");
    if (!pipe) {
        LogPrintf("ERROR Enforcer client failed to run grpcurl (%s)\n", strMethod);
        return -1;
    }

    char buffer[4096];
    size_t nRead;
    while ((nRead = fread(buffer, 1, sizeof(buffer), pipe)) > 0)
        strOutput.append(buffer, nRead);

    int status = pclose(pipe);
    if (status == -1 || !WIFEXITED(status))
        return -1;

    // 127 = the shell couldn't find the grpcurl binary at all - that is
    // misconfiguration, not a routine failure, so say so once
    if (WEXITSTATUS(status) == 127)
        LogOnce("grpcurl-missing", "ERROR Enforcer client: grpcurl binary '" + strBin +
            "' not found - the enforcer transport cannot work; install grpcurl, set -grpcurlbin, or drop "
            "-enforcertransport=grpcurl (getmainchaininfo shows where it was looked for)\n");

    return WEXITSTATUS(status);
}

int EnforcerL1Client::CallEnforcerStatus(const std::string& strService, const std::string& strMethod, const std::string& strRequest, std::string& strError)
{
    // stderr is merged into the output: on success the reply is not needed, and
    // on failure grpcurl prints nothing to stdout, so the output is its stderr
    std::string strOutput;
    int nExit = RunEnforcerCall(strService, strMethod, strRequest, true, strOutput);
    if (nExit != 0)
        strError = strOutput;
    return nExit;
}

bool EnforcerL1Client::CallEnforcer(const std::string& strService, const std::string& strMethod, const std::string& strRequest, UniValue& result)
{
    std::string strOutput;
    if (RunEnforcerCall(strService, strMethod, strRequest, false, strOutput) != 0) {
        // Can be enabled for debug -- too noisy (includes routine "block not
        // found" gRPC errors)
        // LogPrintf("ERROR Enforcer client %s failed\n", strMethod);
        return false;
    }

    if (!result.read(strOutput)) {
        LogPrintf("ERROR Enforcer client %s returned unparseable JSON\n", strMethod);
        return false;
    }

    return true;
}

bool EnforcerL1Client::CallValidator(const std::string& strMethod, const std::string& strRequest, UniValue& result)
{
    return CallEnforcer("cusf.mainchain.v1.ValidatorService", strMethod, strRequest, result);
}

bool EnforcerL1Client::CallWallet(const std::string& strMethod, const std::string& strRequest, UniValue& result)
{
    return CallEnforcer("cusf.mainchain.v1.WalletService", strMethod, strRequest, result);
}

bool EnforcerL1Client::GetChainTip(L1BlockHeader& header)
{
    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetChainTip", "{}", result))
        return false;

    return ParseEnforcerChainTip(result, header);
}

bool EnforcerL1Client::GetHeaderInfos(const uint256& hashBlock, uint32_t nMaxAncestors, std::vector<L1BlockHeader>& vHeader)
{
    std::string strRequest = "{\"block_hash\": {\"hex\": \"" + hashBlock.ToString() + "\"}";
    if (nMaxAncestors > 0)
        strRequest += ", \"max_ancestors\": " + std::to_string(nMaxAncestors);
    strRequest += "}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetBlockHeaderInfo", strRequest, result))
        return false;

    return ParseEnforcerHeaderInfos(result, vHeader);
}

void EnforcerL1Client::LogOnce(const std::string& strKey, const std::string& strMessage)
{
    std::lock_guard<std::mutex> lock(mutexLogged);
    if (setLogged.count(strKey))
        return;

    setLogged.insert(strKey);
    LogPrintf("%s", strMessage);
}

void EnforcerL1Client::LogUnimplemented(const std::string& strMethod, const std::string& strReason)
{
    LogOnce(strMethod, "Enforcer client: " + strMethod +
        " is not available on the enforcer transport yet (" + strReason + ")\n");
}

void EnforcerL1Client::LogBundleFailure(const BundleMethod& method, int nExit, const std::string& strError, const std::string& strHint)
{
    // The auto-send in ConnectBlock retries on every block until a call
    // succeeds, so one line per method and exit status is enough
    std::string strDetail = strError.substr(0, 300);
    std::replace(strDetail.begin(), strDetail.end(), '\n', ' ');
    std::string strMethod = std::string(method.pszService) + "/" + method.pszMethod;
    LogOnce("bundle-fail:" + strMethod + ":" + std::to_string(nExit),
        "ERROR Enforcer client: withdrawal bundle not accepted by " + strMethod +
        " (" + EnforcerStatusLabel() + " " + std::to_string(nExit) + ": " + strDetail + ")" + strHint +
        "; retried on every block, logged once per method and exit status\n");
}

bool EnforcerL1Client::BroadcastWithdrawalBundle(const std::string& hex)
{
    // The enforcer expects a BLINDED M6: a ZERO-input tx (the input spending the
    // sidechain CTIP is implied), serialized in LEGACY (non-witness) form. Our
    // chassis bundle carries a null-prevout placeholder input and would be
    // rejected ("Blinded M6 error: Inputs must be empty"), so we strip the inputs
    // and re-serialize without the witness marker (a 0-input tx in the segwit
    // encoding would be misread as a witness marker).
    if (!IsHex(hex))
        return false;

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, hex))
        return false;

    mtx.vin.clear();

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
    ss << CTransaction(mtx);
    std::vector<unsigned char> vch(ss.begin(), ss.end());
    std::string strB64 = EncodeBase64(vch.data(), vch.size());

    std::string strRequest = "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"transaction\": \"" + strB64 + "\"}";

    // D7 (v0.2.16): the bundle goes to BlockProducerService/
    // ProposeWithdrawalBundle (enforcer 7958cef and later). The enforcer
    // registers that service with --enable-wallet or with
    // --enable-block-template-server, so it also reaches BitWindow's enforcer,
    // which runs no wallet and so has no WalletService. Enforcers older than
    // 7958cef only have WalletService/BroadcastWithdrawalBundle. Both take the
    // same request and do the same thing: store the bundle in the enforcer's DB
    // (INSERT OR IGNORE), so calling both is harmless. Try the method that last
    // worked; only when the enforcer says it lacks it (Unimplemented) try the
    // other once, and remember that one if it works. A transient failure
    // changes nothing: the next call tries the same method again.
    static const BundleMethod PROPOSE = {"cusf.mainchain.v1.BlockProducerService", "ProposeWithdrawalBundle"};
    static const BundleMethod BROADCAST = {"cusf.mainchain.v1.WalletService", "BroadcastWithdrawalBundle"};

    const bool fViaWallet = fBundleViaWallet.load();
    const BundleMethod& first = fViaWallet ? BROADCAST : PROPOSE;
    const BundleMethod& second = fViaWallet ? PROPOSE : BROADCAST;

    std::string strError;
    int nExit = CallEnforcerStatus(first.pszService, first.pszMethod, strRequest, strError);
    if (nExit != 0) {
        if (ClassifyGrpcurlFailure(nExit, strError) != GrpcurlFailure::UNIMPLEMENTED) {
            LogBundleFailure(first, nExit, strError, "");
            return false;
        }

        std::string strError2;
        int nExit2 = CallEnforcerStatus(second.pszService, second.pszMethod, strRequest, strError2);
        if (nExit2 != 0) {
            std::string strHint;
            if (ClassifyGrpcurlFailure(nExit2, strError2) == GrpcurlFailure::UNIMPLEMENTED)
                strHint = "; the enforcer serves neither ProposeWithdrawalBundle nor BroadcastWithdrawalBundle: "
                    "it needs --enable-wallet or --enable-block-template-server";
            LogBundleFailure(first, nExit, strError, "");
            LogBundleFailure(second, nExit2, strError2, strHint);
            return false;
        }

        fBundleViaWallet = !fViaWallet;
        LogPrintf("Enforcer client: this enforcer does not have %s/%s; withdrawal bundles now go to %s/%s\n",
            first.pszService, first.pszMethod, second.pszService, second.pszMethod);
    }

    // A successful call registers the (blinded) bundle with the enforcer; its
    // block producer then proposes it (M3) and acks it (M4) via generate_blocks
    // / getblocktemplate, driving it to the M6 payout once workscore is reached.
    return true;
}

//
// Mainchain REST client + deposit parsing (enforcer transport deposit path)
//

bool EnforcerL1Client::RestGet(const std::string& strPath, std::string& strBody)
{
    std::string strHostPort = gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST);
    if (strHostPort.empty())
        return false;

    std::string strHost = strHostPort;
    std::string strPort = "8332";
    size_t colon = strHostPort.rfind(':');
    if (colon != std::string::npos) {
        strHost = strHostPort.substr(0, colon);
        strPort = strHostPort.substr(colon + 1);
    }

    try {
        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(strHost, strPort);
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        tcp::resolver::iterator end;

        tcp::socket socket(io_service);
        boost::system::error_code error = boost::asio::error::host_not_found;
        while (error && endpoint_iterator != end) {
            socket.close();
            socket.connect(*endpoint_iterator++, error);
        }
        if (error) throw boost::system::system_error(error);

        // HTTP/1.0 + Connection: close -> a simple close-delimited body (no
        // chunked-encoding parsing needed)
        boost::asio::streambuf output;
        std::ostream os(&output);
        os << "GET " << strPath << " HTTP/1.0\r\n";
        os << "Host: " << strHost << "\r\n";
        os << "Connection: close\r\n\r\n";
        boost::asio::write(socket, output);

        std::string data;
        for (;;) {
            boost::array<char, 8192> buf;
            boost::system::error_code e;
            size_t sz = socket.read_some(boost::asio::buffer(buf), e);
            data.insert(data.size(), buf.data(), sz);
            if (e == boost::asio::error::eof)
                break;
            else if (e)
                throw boost::system::system_error(e);
        }

        size_t sp = data.find(' ');
        if (sp == std::string::npos)
            return false;
        int code = atoi(data.substr(sp + 1, 4).c_str());
        if (code != 200)
            return false;

        size_t bodyStart = data.find("\r\n\r\n");
        if (bodyStart == std::string::npos)
            return false;
        strBody = data.substr(bodyStart + 4);
        return true;
    } catch (std::exception& e) {
        LogPrintf("ERROR Enforcer REST GET %s: %s\n", strPath, e.what());
        return false;
    }
}

/** Hex compares case-insensitively; a pin must not fail on 00AB vs 00ab. */
static bool HexEqualNoCase(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

bool ProbeMainchainRest(std::string& strError, bool* pfIdentityMismatch)
{
    if (pfIdentityMismatch) *pfIdentityMismatch = false;
    EnforcerL1Client client;
    std::string strBody;
    if (!client.RestGet("/rest/chaininfo.json", strBody) || strBody.empty()) {
        strError = strprintf("mainchain REST endpoint %s did not answer /rest/chaininfo.json",
                             gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST));
        return false;
    }

    // L1 IDENTITY PIN. Reachability alone is not identity: a REST endpoint that
    // answers is not necessarily the L1 this node's history was built against.
    // Failure observed 2026-07-28: a second freebankd took the DEFAULT
    // -mainchainrest and silently BMM'd against a different node's mainchain -
    // one that is wiped nightly. Everything looked healthy; the probe was
    // satisfied because a mainchain replied.
    //
    // NOTE the pinned fields. `chain` alone catches signet-vs-mainnet (the
    // threat the plan docs anticipated) but NOT signet-vs-signet, and the
    // genesis hash catches neither: Core's signet genesis is HARDCODED and does
    // not derive from the challenge, so two custom signets share it byte for
    // byte (verified on these two chains). The `signetchallenge` IS the network
    // identity for signet, and it is already in this same response.
    UniValue info;
    if (!info.read(strBody) || !info.isObject()) {
        strError = "mainchain REST /rest/chaininfo.json was unparseable";
        return false;
    }

    // A9: record the L1 family for mainchain-address decoding. Read from the
    // L1 itself, never from configuration, so every node following this L1
    // derives the same withdrawal-destination prefix (bundle build/validate).
    {
        const UniValue& chainName = find_value(info, "chain");
        g_fMainchainMainFamily = chainName.isStr() && chainName.get_str() == "main";
    }

    const std::string strWantChain = gArgs.GetArg("-mainchainchain", "");
    if (!strWantChain.empty()) {
        const UniValue& chain = find_value(info, "chain");
        if (!chain.isStr() || chain.get_str() != strWantChain) {
            strError = strprintf("mainchain identity mismatch: -mainchainchain=%s but %s reports "
                                 "chain=%s. Refusing to start against the wrong L1.",
                                 strWantChain, gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST),
                                 chain.isStr() ? chain.get_str() : "(absent)");
            if (pfIdentityMismatch) *pfIdentityMismatch = true;
            return false;
        }
    }

    const std::string strWantChallenge = gArgs.GetArg("-mainchainchallenge", "");
    if (!strWantChallenge.empty()) {
        const UniValue& chal = find_value(info, "signet_challenge");
        if (!chal.isStr() || !HexEqualNoCase(chal.get_str(), strWantChallenge)) {
            strError = strprintf("mainchain identity mismatch: -mainchainchallenge=%s but %s "
                                 "reports signet_challenge=%s. This is a DIFFERENT signet - "
                                 "refusing to start against the wrong L1.",
                                 strWantChallenge,
                                 gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST),
                                 chal.isStr() ? chal.get_str() : "(absent)");
            if (pfIdentityMismatch) *pfIdentityMismatch = true;
            return false;
        }
    }

    // FORKNET / MAINNET-FAMILY PIN. A chain=main L1 (eCash alphanet, beta,
    // mainnet, or real Bitcoin) carries no signet_challenge, so the challenge
    // pin cannot exist there - and `chain` alone cannot tell alphanet from
    // Bitcoin mainnet or from next month's beta forknet: they are byte-identical
    // below the fork height. The block hash AT a height on the active chain is
    // the discriminator (for alphanet, the fork block itself). A node still
    // syncing below the pinned height is NOT a mismatch - report not-ready and
    // let init's retry window run.
    const std::string strWantPin = gArgs.GetArg("-mainchainblockpin", "");
    if (!strWantPin.empty()) {
        int nPinHeight = 0;
        uint256 hashPin;
        if (!ParseMainchainBlockPin(strWantPin, nPinHeight, hashPin)) {
            strError = strprintf("-mainchainblockpin=%s is malformed (expected <height>:<64-hex blockhash>)",
                                 strWantPin);
            if (pfIdentityMismatch) *pfIdentityMismatch = true;
            return false;
        }
        const UniValue& blocks = find_value(info, "blocks");
        if (blocks.isNum() && blocks.get_int() < nPinHeight) {
            strError = strprintf("mainchain %s is at height %d, below the pinned height %d - still syncing",
                                 gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST),
                                 blocks.get_int(), nPinHeight);
            return false;
        }
        std::string strHashBody;
        if (!client.RestGet("/rest/blockhashbyheight/" + std::to_string(nPinHeight) + ".json", strHashBody)
                || strHashBody.empty()) {
            strError = strprintf("mainchain REST endpoint %s did not answer /rest/blockhashbyheight/%d.json",
                                 gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST), nPinHeight);
            return false;
        }
        UniValue hashInfo;
        const UniValue& got = (hashInfo.read(strHashBody) && hashInfo.isObject())
                                  ? find_value(hashInfo, "blockhash") : NullUniValue;
        if (!got.isStr() || uint256S(got.get_str()) != hashPin) {
            strError = strprintf("mainchain identity mismatch: -mainchainblockpin pins block %s at height %d "
                                 "but %s reports %s. This is a DIFFERENT chain (wrong forknet, or real "
                                 "mainnet) - refusing to start against the wrong L1.",
                                 hashPin.ToString(), nPinHeight,
                                 gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST),
                                 got.isStr() ? got.get_str() : "(absent)");
            if (pfIdentityMismatch) *pfIdentityMismatch = true;
            return false;
        }
    }
    return true;
}

bool ParseEnforcerChainInfo(const UniValue& response, EnforcerSettings& settings)
{
    settings = EnforcerSettings();
    if (!response.isObject())
        return false;
    const UniValue& c = find_value(response, "bip300Constants");
    if (!c.isObject())
        return false;
    const std::pair<const char*, uint32_t*> fields[] = {
        {"withdrawalBundleMaxAge", &settings.nBundleMaxAge},
        {"withdrawalBundleInclusionThreshold", &settings.nBundleThreshold},
        {"usedSidechainSlotProposalMaxAge", &settings.nUsedSlotMaxAge},
        {"usedSidechainSlotActivationThreshold", &settings.nUsedSlotThreshold},
        {"unusedSidechainSlotProposalMaxAge", &settings.nUnusedSlotMaxAge},
        {"unusedSidechainSlotActivationThreshold", &settings.nUnusedSlotThreshold},
        {"activationHeight", &settings.nActivationHeight},
    };
    for (const auto& f : fields) {
        const UniValue& v = find_value(c, f.first);
        if (v.isNull())
            continue; // proto3: zero
        if (!v.isNum() || v.get_int64() < 0 || v.get_int64() > std::numeric_limits<uint32_t>::max())
            return false;
        *f.second = (uint32_t)v.get_int64();
    }
    return true;
}

std::string CompareEnforcerSettings(int nForkHeight, const EnforcerSettings& got)
{
    // An enforcer with no preset for this network reports 0 (the eCash mainnet
    // preset is not published yet): nothing to compare then.
    if (got.nActivationHeight != 0 && (int64_t)got.nActivationHeight != nForkHeight)
        return strprintf("its BIP300/301 activation height is %u, not the pinned fork height %d", got.nActivationHeight, nForkHeight);
    if (got.nActivationHeight == 0 && (nForkHeight == 967680 || nForkHeight == 963648))
        return strprintf("it reports no BIP300/301 activation height; this network's is %d (--network-preset)", nForkHeight);

    // The enforcer's presets (lib/types.rs Thresholds, 73d239a)
    EnforcerSettings want;
    const auto Want = [&](uint32_t nMaxAge, uint32_t nThreshold, uint32_t nUnusedMaxAge, uint32_t nUnusedThreshold) {
        want.nBundleMaxAge = want.nUsedSlotMaxAge = nMaxAge;
        want.nBundleThreshold = want.nUsedSlotThreshold = nThreshold;
        want.nUnusedSlotMaxAge = nUnusedMaxAge;
        want.nUnusedSlotThreshold = nUnusedThreshold;
    };
    if (nForkHeight == 967680)      // betanet: mainnet's, unused slots at 51%
        Want(26300, 13150, 2016, 1008);
    else if (nForkHeight == 963648) // alphanet: hours-scale
        Want(144, 72, 36, 30);
    else
        return "";
    if (got.nBundleMaxAge != want.nBundleMaxAge || got.nBundleThreshold != want.nBundleThreshold ||
            got.nUsedSlotMaxAge != want.nUsedSlotMaxAge || got.nUsedSlotThreshold != want.nUsedSlotThreshold ||
            got.nUnusedSlotMaxAge != want.nUnusedSlotMaxAge || got.nUnusedSlotThreshold != want.nUnusedSlotThreshold)
        return strprintf("its BIP300 thresholds (bundle %u of %u, used slot %u of %u, unused slot %u of %u) are not "
                         "this network's (bundle %u of %u, used slot %u of %u, unused slot %u of %u)",
                         got.nBundleThreshold, got.nBundleMaxAge, got.nUsedSlotThreshold, got.nUsedSlotMaxAge,
                         got.nUnusedSlotThreshold, got.nUnusedSlotMaxAge, want.nBundleThreshold, want.nBundleMaxAge,
                         want.nUsedSlotThreshold, want.nUsedSlotMaxAge, want.nUnusedSlotThreshold, want.nUnusedSlotMaxAge);
    return "";
}

bool IsLocalOrPrivateL1Address(const std::string& strHostPort)
{
    std::string strHost = strHostPort;
    const size_t nColon = strHost.rfind(':');
    if (nColon != std::string::npos && strHost.find(']') == std::string::npos && strHost.find(':') == nColon)
        strHost = strHost.substr(0, nColon);          // v4:port
    else if (!strHost.empty() && strHost[0] == '[' && strHost.find(']') != std::string::npos)
        strHost = strHost.substr(1, strHost.find(']') - 1); // [v6]:port
    if (strHost == "localhost")
        return true;
    CNetAddr addr;
    if (!LookupHost(strHost.c_str(), addr, false /* fAllowLookup */))
        return false;
    return addr.IsLocal() || addr.IsRFC1918() || addr.IsRFC6598() || addr.IsRFC4193();
}

bool ParseMainchainBlockPin(const std::string& strPin, int& nHeight, uint256& hashBlock)
{
    const size_t nColon = strPin.find(':');
    if (nColon == std::string::npos || nColon == 0 || nColon + 1 >= strPin.size())
        return false;
    const std::string strHeight = strPin.substr(0, nColon);
    const std::string strHash = strPin.substr(nColon + 1);
    for (char c : strHeight)
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    if (strHeight.size() > 9)
        return false;                              // > 999,999,999 is not a real height
    if (strHash.size() != 64 || !IsHex(strHash))
        return false;
    nHeight = std::atoi(strHeight.c_str());
    hashBlock = uint256S(strHash);
    return true;
}

EnforcerIdentity ClassifyEnforcerIdentity(bool fEnfTipOK, int nEnfTipHeight,
                                          bool fRestOK, int nRestTipHeight,
                                          bool fMemberQueryOK, bool fEnfTipOnRestChain,
                                          int nStaleWarnDepth, bool* pfStale,
                                          std::string& strDetail)
{
    if (pfStale) *pfStale = false;

    // Any read we could not obtain = NOT-READY, never a mismatch. Keeping
    // "couldn't check" strictly separate from "wrong chain" is the whole point:
    // a mismatch refuses startup, so it must be a POSITIVE disagreement, never
    // the absence of an answer.
    if (!fEnfTipOK) {
        strDetail = "enforcer GetChainTip unavailable (down, unreachable at -enforceraddr, grpcurl missing, or unsynced)";
        return ENFORCER_IDENTITY_NOTREADY;
    }
    if (nEnfTipHeight < 1) {
        strDetail = "enforcer at genesis only (still syncing headers)";
        return ENFORCER_IDENTITY_NOTREADY;
    }
    if (!fRestOK) {
        strDetail = "mainchain REST tip height unavailable";
        return ENFORCER_IDENTITY_NOTREADY;
    }

    // Staleness is a WARN, not a refuse: a frozen-but-correct enforcer's tip is
    // still a block on the REST active chain (MATCH below). Surface it; do not
    // brick on it. (Computed before the membership verdict so a stale MATCH
    // still carries the flag.)
    if (pfStale && nStaleWarnDepth > 0 && nEnfTipHeight < nRestTipHeight - nStaleWarnDepth)
        *pfStale = true;

    if (!fMemberQueryOK) {
        strDetail = "mainchain REST membership query failed";
        return ENFORCER_IDENTITY_NOTREADY;
    }

    if (fEnfTipOnRestChain) {
        strDetail = strprintf("enforcer tip @%d is on the challenge-pinned REST node's active chain",
                              nEnfTipHeight);
        return ENFORCER_IDENTITY_MATCH;
    }

    strDetail = strprintf("enforcer tip @%d is NOT on the challenge-pinned REST node's active chain "
                          "(a different L1, or an abandoned fork)", nEnfTipHeight);
    return ENFORCER_IDENTITY_MISMATCH;
}

EnforcerIdentity ProbeEnforcerIdentity(std::string& strError, bool* pfStale)
{
    EnforcerL1Client client;

    // 1. Enforcer chain tip (gRPC ValidatorService/GetChainTip).
    L1BlockHeader enfTip;
    bool fEnfTipOK = client.GetChainTip(enfTip);
    int nEnfTip = fEnfTipOK ? enfTip.nHeight : -1;

    // 2. REST tip height, from the SAME node the REST identity pin validated.
    bool fRestOK = false;
    int nRestTip = -1;
    std::string strBody;
    if (client.RestGet("/rest/chaininfo.json", strBody) && !strBody.empty()) {
        UniValue info;
        if (info.read(strBody) && info.isObject()) {
            const UniValue& blocks = find_value(info, "blocks");
            if (blocks.isNum()) {
                nRestTip = blocks.get_int();
                fRestOK = true;
            }
        }
    }

    // 3. Membership: is the enforcer's tip a block on the REST node's ACTIVE
    //    chain? /rest/headers/1/<hash> returns that one header iff it is on the
    //    active chain (chainActive.Contains), else an EMPTY but HTTP-200 body -
    //    so RestGet succeeds either way and the empty-vs-present distinction is
    //    an unambiguous "not on my chain" rather than a transport error.
    bool fMemberOK = false, fMember = false;
    if (fEnfTipOK) {
        std::string strHdr;
        if (client.RestGet("/rest/headers/1/" + enfTip.hashBlock.ToString() + ".hex", strHdr)) {
            fMemberOK = true;
            while (!strHdr.empty() && (strHdr.back() == '\n' || strHdr.back() == '\r' || strHdr.back() == ' '))
                strHdr.pop_back();
            if (strHdr.empty()) {
                fMember = false; // present-but-empty == not on the active chain
            } else if (IsHex(strHdr)) {
                // Belt-and-braces: confirm the returned header really IS the
                // enforcer tip (guards a misbehaving REST from a false MATCH).
                // This is a MAINCHAIN header: 80 bytes (version, prev, merkle,
                // time, bits, nonce), hash = SHA256d over the 80 bytes. It must
                // NOT be deserialized as the sidechain's CBlockHeader (which has
                // a different layout and no nBits/nNonce) - that was the v0.2.8
                // defect that made this probe report NOT-READY on every network,
                // so the gRPC pin never verified and its refuse path was
                // unreachable (found by the guide's stranger-run, 2026-08-28).
                const std::vector<unsigned char> raw = ParseHex(strHdr);
                if (raw.size() == 80) {
                    fMember = (Hash(raw.begin(), raw.end()) == enfTip.hashBlock);
                } else {
                    fMemberOK = false; // not an 80-byte header == couldn't check, not a mismatch
                }
            } else {
                fMemberOK = false; // unexpected non-hex body == couldn't check
            }
        }
    }

    std::string strDetail;
    EnforcerIdentity r = ClassifyEnforcerIdentity(fEnfTipOK, nEnfTip, fRestOK, nRestTip,
                                                  fMemberOK, fMember, 20, pfStale, strDetail);
    strError = strDetail;
    return r;
}

L1TxFetch EnforcerL1Client::RestGetTxFromBlock(const uint256& hashBlock, const uint256& txid, CMutableTransaction& tx, int& nTx)
{
    nTx = -1;
    std::string body;
    if (!RestGet("/rest/block/" + hashBlock.ToString() + ".hex", body))
        return L1TxFetch::FAILED;
    while (!body.empty() && (body.back() == '\n' || body.back() == '\r' || body.back() == ' '))
        body.pop_back();
    if (body.empty() || !IsHex(body))
        return L1TxFetch::FAILED;
    return FindL1TxInBlock(ParseHex(body), txid, tx, nTx);
}

bool EnforcerL1Client::RestGetBlockTxids(const uint256& hashBlock, std::vector<uint256>& vTxid)
{
    vTxid.clear();

    std::string body;
    if (!RestGet("/rest/block/notxdetails/" + hashBlock.ToString() + ".json", body))
        return false;

    UniValue obj;
    if (!obj.read(body) || !obj.isObject())
        return false;

    const UniValue& tx = find_value(obj, "tx");
    if (!tx.isArray())
        return false;

    for (size_t i = 0; i < tx.size(); i++) {
        if (!tx[i].isStr())
            return false;
        vTxid.push_back(uint256S(tx[i].get_str()));
    }
    return true;
}

// One enforcer Deposit event, flattened. output.address is a Hex of the ASCII
// bytes of the sidechain address string (== the jsonrpc strdest, verified
// live), so we decode it back to the string. value_sats is deliberately NOT
// kept: it is the deposit INCREMENT, whereas the chassis needs the cumulative
// CTIP value (read from the raw tx's burn output) and computes the delta itself.
std::vector<SidechainDeposit> EnforcerL1Client::UpdateDeposits(const uint256& hashLastDeposit, const uint32_t nLastBurnIndex)
{
    std::vector<SidechainDeposit> incoming;

    if (gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST).empty()) {
        LogUnimplemented("UpdateDeposits", "set -mainchainrest=<host:port> to enable enforcer deposit crediting");
        return incoming;
    }

    // The treasury's changes over the whole L1 history (a full rescan each
    // call; the caller dedups with HaveDepositNonAmount). A start block is a
    // follow-up: the caller passes the last record's txid, not its L1 block.
    L1BlockHeader tip;
    if (!GetChainTip(tip))
        return incoming;
    L1PegEvents events;
    if (GetPegEvents(uint256(), tip.hashBlock, events) != L1Answer::YES) {
        LogPrintf("Enforcer client: UpdateDeposits: no answer for the peg events up to %s; no new deposits this time\n",
                  tip.hashBlock.ToString());
        return incoming;
    }

    // v0.2.17 A9 + D7: every change to the treasury in running-number order,
    // deposits and bundle payouts together (they share the counter). A payout's
    // M6 is the tx the enforcer sends with its "paid" event; freebankd searched
    // the L1 block for it (BuildM6Candidates). A6: a deposit with an empty
    // address is kept (the parser used to drop it, leaving a gap in the
    // treasury chain that stopped every later deposit); it is recorded and paid
    // to no one.
    struct Change {
        uint64_t nSequence;
        const L1DepositEvent* pDeposit;
        const L1WithdrawalEvent* pPaid;
    };
    std::vector<Change> vChange;
    for (const L1DepositEvent& ev : events.vDeposit)
        vChange.push_back({ev.nSequence, &ev, nullptr});
    for (const L1WithdrawalEvent& ev : events.vWithdrawal) {
        if (ev.status != 'S')
            continue;
        if (!ev.fHaveSequence || ev.vchTx.empty()) {
            LogPrintf("ERROR Enforcer client: a \"paid\" event for m6id %s without its running number or M6 (batch failed closed)\n",
                      ev.m6id.ToString());
            return incoming;
        }
        vChange.push_back({ev.nSequence, nullptr, &ev});
    }
    std::sort(vChange.begin(), vChange.end(), [](const Change& a, const Change& b) { return a.nSequence < b.nSequence; });

    // Each change as a record (without its tx yet): the outpoint from the
    // event, a payout's txid from the M6 the event carries
    std::vector<SidechainDeposit> vRecord;
    std::vector<uint256> vTxid;
    for (const Change& c : vChange) {
        SidechainDeposit deposit;
        deposit.nSidechain = THIS_SIDECHAIN;
        if (c.pDeposit) {
            deposit.strDest = std::string(c.pDeposit->vchAddress.begin(), c.pDeposit->vchAddress.end());
            deposit.nBurnIndex = c.pDeposit->outpoint.n;
            deposit.hashMainchainBlock = c.pDeposit->hashMainBlock;
            vTxid.push_back(c.pDeposit->outpoint.hash);
        } else {
            L1MutableTransaction mtxM6;
            try {
                CDataStream ss(c.pPaid->vchTx, SER_NETWORK, PROTOCOL_VERSION);
                ss >> mtxM6;
            } catch (const std::exception&) {
                LogPrintf("ERROR Enforcer client: the M6 of m6id %s does not decode (batch failed closed)\n", c.pPaid->m6id.ToString());
                return incoming;
            }
            deposit.strDest = SIDECHAIN_WITHDRAWAL_BUNDLE_RETURN_DEST;
            deposit.nBurnIndex = 0; // into_m6 puts the treasury change at vout[0]
            deposit.hashMainchainBlock = c.pPaid->hashMainBlock;
            vTxid.push_back(mtxM6.GetHash());
        }
        vRecord.push_back(deposit);
    }

    // Skip everything up to and including the caller's last record
    size_t nStart = 0;
    if (!hashLastDeposit.IsNull()) {
        for (size_t i = 0; i < vRecord.size(); i++) {
            if (vTxid[i] == hashLastDeposit && vRecord[i].nBurnIndex == nLastBurnIndex) {
                nStart = i + 1;
                break;
            }
        }
    }

    // The new ones, each tx read from its own L1 block (which also shows it is
    // there). All or nothing: one failure gives no new deposits this time, and
    // the builder builds without them.
    for (size_t i = nStart; i < vRecord.size(); i++) {
        SidechainDeposit& deposit = vRecord[i];
        int nTx = -1;
        if (RestGetTxFromBlock(deposit.hashMainchainBlock, vTxid[i], deposit.dtx, nTx) != L1TxFetch::OK) {
            LogPrintf("ERROR Enforcer client: treasury change %s (number %u): could not read it from its L1 block %s (batch failed closed)\n",
                      vTxid[i].ToString(), vChange[i].nSequence, deposit.hashMainchainBlock.ToString());
            return std::vector<SidechainDeposit>();
        }
        deposit.nTx = nTx;
        // The record needs the tx's id and outputs, not its witness (the txid
        // does not cover it): a depositor could pad the witness until the
        // record no longer fits a block, stopping every later deposit.
        for (CTxIn& in : deposit.dtx.vin)
            in.scriptWitness.SetNull();
        if (deposit.nBurnIndex >= deposit.dtx.vout.size()) {
            LogPrintf("ERROR Enforcer client: treasury change %s: output %u out of range (batch failed closed)\n",
                      vTxid[i].ToString(), deposit.nBurnIndex);
            return std::vector<SidechainDeposit>();
        }
        // The treasury's value after this change; the builder subtracts the
        // one before (a payout's "D" record is clamped to 0 there)
        deposit.amtUserPayout = deposit.dtx.vout[deposit.nBurnIndex].nValue;
        incoming.push_back(deposit);
    }
    return incoming;
}

bool EnforcerL1Client::VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx)
{
    // Byte-identical to the jsonrpc verifydeposit: confirm the deposit tx sits
    // at index nTx of the named mainchain block (block.vtx[nTx].GetHash()==txid).
    // Fail closed if REST is unavailable or the index is out of range.
    if (gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST).empty()) {
        LogUnimplemented("VerifyDeposit", "set -mainchainrest=<host:port>");
        return false;
    }

    std::vector<uint256> vTxid;
    if (!RestGetBlockTxids(hashMainBlock, vTxid))
        return false;

    if (nTx < 0 || (size_t)nTx >= vTxid.size())
        return false;

    return vTxid[nTx] == txid;
}

bool EnforcerL1Client::VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime)
{
    std::string strRequest = "{\"block_hash\": {\"hex\": \"" + hashMainBlock.ToString() +
        "\"}, \"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) + "}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetBmmHStarCommitment", strRequest, result))
        return false;

    bool fBlockFound = false;
    bool fHaveCommitment = false;
    uint256 hashCommitment;
    if (!ParseEnforcerBmmCommitment(result, fBlockFound, fHaveCommitment, hashCommitment))
        return false;

    if (!fBlockFound || !fHaveCommitment || hashCommitment != hashBMM)
        return false;

    // The sidechain block header copies the mainchain block time
    std::vector<L1BlockHeader> vHeader;
    if (!GetHeaderInfos(hashMainBlock, 0, vHeader) || vHeader.empty())
        return false;

    nTime = vHeader.front().nTime;

    // The enforcer exposes the commitment itself, not the mainchain txid
    // carrying it; callers only log the txid.
    txid.SetNull();

    LogPrintf("Enforcer client found BMM for h*: %s\n", hashBMM.ToString());
    return true;
}

L1Client::Commitment EnforcerL1Client::ReadBmmCommitment(const uint256& hashMainBlock, uint256& hashCommitment)
{
    hashCommitment.SetNull();

    std::string strRequest = "{\"block_hash\": {\"hex\": \"" + hashMainBlock.ToString() +
        "\"}, \"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) + "}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetBmmHStarCommitment", strRequest, result))
        return Commitment::UNKNOWN;

    bool fBlockFound = false;
    bool fHaveCommitment = false;
    if (!ParseEnforcerBmmCommitment(result, fBlockFound, fHaveCommitment, hashCommitment))
        return Commitment::UNKNOWN;

    if (!fBlockFound)
        return Commitment::NOT_FOUND;

    return fHaveCommitment ? Commitment::COMMITTED : Commitment::NONE;
}

uint256 EnforcerL1Client::SendBMMRequest(const uint256& hashBMM, const uint256& hashBlockMain, int nHeight, CAmount amount, bool& fNotSent)
{
    fNotSent = false;
    // WalletService/CreateBmmCriticalDataTransaction. Builds, funds (from the
    // enforcer wallet), signs and broadcasts the BMM request in one call.
    if (amount == CAmount(0))
        amount = DEFAULT_CRITICAL_DATA_AMOUNT;

    // Divergences from the JSON-RPC twin:
    //  - value_sats is an integer of SATS, not a ValueFromAmount decimal string.
    //  - critical_hash is ConsensusHex (internal byte order) - h* is a merkle
    //    root, so encode with ConsensusHexFromUint256, NOT ToString().
    //  - prev_bytes is the FULL mainchain tip hash (display order / ReverseHex);
    //    the enforcer hard-rejects anything but the current tip, so we do NOT
    //    truncate to the last 4 bytes the way the drivechain RPC does.
    std::string strRequest =
        "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"value_sats\": " + std::to_string(amount) +
        ", \"height\": " + std::to_string(nHeight) +
        ", \"critical_hash\": {\"hex\": \"" + ConsensusHexFromUint256(hashBMM) + "\"}" +
        ", \"prev_bytes\": {\"hex\": \"" + hashBlockMain.ToString() + "\"}}";

    // Fails (non-zero status) on: stale prev_bytes (not the tip),
    // inactive sidechain, or a wallet / broadcast error (e.g. unfunded).
    // The enforcer has no AlreadyExists for a second bid on the same tip:
    // one bid per tip is freebankd's own rule (RefreshBMM's
    // StorePrevBlockBMMCreated). A txid back does not prove the L1 mempool
    // took the bid either - the enforcer only pushes it to its P2P peers.
    // It broadcasts before it replies, so a failure without a definite
    // refusal (a timeout, a broadcast error) may still have sent the bid:
    // fNotSent is set only for a refusal (GrpcurlBMMRequestNotSent).
    // stderr is merged into the output, for that classification.
    std::string strOutput;
    // Not retry-safe: a resent request could place a second bid
    int nExit = RunEnforcerCall("cusf.mainchain.v1.WalletService", "CreateBmmCriticalDataTransaction", strRequest, true, strOutput,
                                /*fRetrySafe=*/false);
    if (nExit != 0) {
        fNotSent = GrpcurlBMMRequestNotSent(nExit, strOutput);
        std::string strDetail = strOutput.substr(0, 300);
        std::replace(strDetail.begin(), strDetail.end(), '\n', ' ');
        LogPrintf("ERROR Enforcer client: BMM request failed (%s %d: %s); %s\n", EnforcerStatusLabel(), nExit, strDetail,
            fNotSent ? "no bid was sent" : "the bid may have gone out");
        return uint256();
    }

    UniValue result(UniValue::VOBJ);
    std::string strTxid;
    if (!result.read(strOutput) || !GetHexField(find_value(result, "txid"), strTxid)) {
        LogPrintf("ERROR Enforcer client: BMM request answered without a readable txid; the bid may have gone out\n");
        return uint256();
    }

    uint256 txid = uint256S(strTxid);
    if (!txid.IsNull())
        LogPrintf("Enforcer client created BMM request. TXID: %s\n", txid.ToString());

    return txid;
}

bool EnforcerL1Client::GetCTIP(std::pair<uint256, uint32_t>& ctip)
{
    std::string strRequest = "{\"sidechain_number\": " + std::to_string(THIS_SIDECHAIN) + "}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetCtip", strRequest, result))
        return false;

    uint256 txid;
    uint32_t n = 0;
    if (!ParseEnforcerCtip(result, txid, n))
        return false;

    ctip = std::make_pair(txid, n);
    return true;
}

bool EnforcerL1Client::GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFees)
{
    LogUnimplemented("GetAverageFees", "no enforcer equivalent; informational only");
    return false;
}

bool EnforcerL1Client::GetBlockCount(int& nBlocks)
{
    L1BlockHeader header;
    if (!GetChainTip(header))
        return false;

    nBlocks = header.nHeight;
    return true;
}

bool EnforcerL1Client::GetWorkScore(const uint256& hash, int& nWorkScore)
{
    // No enforcer equivalent: the enforcer surfaces discrete WithdrawalBundleEvents
    // (Submitted/Succeeded/Failed), not a running ACK workscore. GetWorkScore is
    // GUI-display only (qt/sidechainpage.cpp) - consensus/the miner do not use it -
    // so leaving it unavailable is harmless on a headless node.
    LogUnimplemented("GetWorkScore", "no enforcer workscore concept; GUI-only, not consensus");
    return false;
}

bool EnforcerL1Client::ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle)
{
    // Double-propose guard for CreateWithdrawalBundleTx (block-template path
    // only; replication never calls it): true iff L1 is STILL tracking
    // (proposed, not yet paid or expired) a bundle on this slot - the legacy
    // listwithdrawalstatus semantics. v0.2.12 kept every Submitted/Succeeded
    // event in the full L1 history (FetchWithdrawalEvents has no start block),
    // so once the first bundle was ever proposed this returned true forever and
    // no second bundle could be created (v0.2.13 item 2). Any pending bundle
    // blocks, ours or foreign: an m6id cannot tell a foreign bundle from one of
    // ours broadcast from an orphaned branch carrying the same withdrawals.
    // NB the returned hashes are enforcer m6ids (blinded txids), not chassis
    // bundle hashes; do not match them against chassis hashes.
    std::vector<L1WithdrawalEvent> vEvents;
    if (!FetchWithdrawalEvents(vEvents)) {
        // Fail CLOSED: an unreachable or timed-out enforcer must not read as
        // "nothing pending" (v0.2.12 failed open). It only delays a proposal to
        // a later block; with the events unreadable HaveSpent/HaveFailed fail
        // too, so the chassis would keep the previous bundle CREATED anyway.
        LogOnce("bundle-guard-fetch", "Enforcer client: could not fetch L1 withdrawal events; "
            "not proposing a withdrawal bundle until L1 state is readable\n");
        return true;
    }

    return L1StillTracksWithdrawalBundle(vEvents, vHashWithdrawalBundle);
}

bool EnforcerL1Client::GetBlockHash(int nHeight, uint256& hashBlock)
{
    // The enforcer indexes by block hash, not height: walk back from the tip
    // in batched ancestor chunks until the requested height. Steady-state
    // callers ask for heights at or near the tip; deep walks only happen on
    // a cold header-cache sync.
    L1BlockHeader tip;
    if (!GetChainTip(tip))
        return false;

    if (nHeight < 0 || nHeight > tip.nHeight)
        return false;

    if (nHeight == tip.nHeight) {
        hashBlock = tip.hashBlock;
        return true;
    }

    uint256 hashCursor = tip.hashBlock;
    int nCursor = tip.nHeight;
    while (nCursor > nHeight) {
        uint32_t nWant = std::min(nCursor - nHeight, 1000);

        std::vector<L1BlockHeader> vHeader;
        if (!GetHeaderInfos(hashCursor, nWant, vHeader))
            return false;

        // Newest-first: [0] is the cursor block itself
        for (const L1BlockHeader& header : vHeader) {
            if (header.nHeight == nHeight) {
                hashBlock = header.hashBlock;
                return true;
            }
        }

        // Continue from the oldest returned header; require progress
        const L1BlockHeader& oldest = vHeader.back();
        if (oldest.nHeight >= nCursor)
            return false;

        hashCursor = oldest.hashBlock;
        nCursor = oldest.nHeight;
    }

    return false;
}

bool EnforcerL1Client::GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash)
{
    // The enforcer indexes by hash, so a batch of ancestors is a single call:
    // ask for the cursor block plus its (nMax - 1) ancestors.
    vHash.clear();
    if (nMax == 0)
        return true;

    std::vector<L1BlockHeader> vHeader;
    if (!GetHeaderInfos(hashBlock, nMax - 1, vHeader))
        return false;

    // Newest-first, [0] == hashBlock. Stop at genesis rather than trusting the
    // caller's count.
    for (const L1BlockHeader& header : vHeader) {
        vHash.push_back(header.hashBlock);
        if (header.nHeight == 0)
            break;
    }

    return !vHash.empty();
}

L1Answer EnforcerL1Client::GetPegEvents(const uint256& hashStart, const uint256& hashEnd, L1PegEvents& events)
{
    events = L1PegEvents();
    const std::string strRequest = "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"start_block_hash\": {\"hex\": \"" + hashStart.ToString() + "\"}" +
        ", \"end_block_hash\": {\"hex\": \"" + hashEnd.ToString() + "\"}}";

    std::string strOutput;
    const int nTimeout = hashStart.IsNull() ? 60 : enforcerconnect::DEFAULT_CALL_TIMEOUT; // null: the whole history
    if (RunEnforcerCall("cusf.mainchain.v1.ValidatorService", "GetTwoWayPegData", strRequest, true, strOutput,
                        true /* fRetrySafe */, nTimeout) != 0) {
        const L1Answer answer = ClassifyPegEventsError(strOutput);
        LogPrint(BCLog::NET, "Enforcer client: GetTwoWayPegData (%s, %s] %s: %s\n", hashStart.ToString(), hashEnd.ToString(),
                 answer == L1Answer::NO ? "no" : "can't tell", strOutput);
        return answer;
    }

    UniValue result(UniValue::VOBJ);
    if (!result.read(strOutput) || !ParsePegEvents(result, events)) {
        events = L1PegEvents();
        LogPrintf("Enforcer client: GetTwoWayPegData (%s, %s]: a reply we cannot fully read (can't tell)\n",
                  hashStart.ToString(), hashEnd.ToString());
        return L1Answer::UNKNOWN;
    }
    return L1Answer::YES;
}

EnforcerSettingsCheck CheckEnforcerSettings(std::string& strError)
{
    int nForkHeight = 0;
    uint256 hashPin;
    if (!ParseMainchainBlockPin(gArgs.GetArg("-mainchainblockpin", ""), nForkHeight, hashPin))
        return EnforcerSettingsCheck::OK;
    EnforcerL1Client client;
    UniValue result(UniValue::VOBJ);
    EnforcerSettings settings;
    if (!client.CallValidator("GetChainInfo", "{}", result) || !ParseEnforcerChainInfo(result, settings)) {
        strError = "the enforcer did not answer GetChainInfo";
        return EnforcerSettingsCheck::NOTREADY;
    }
    strError = CompareEnforcerSettings(nForkHeight, settings);
    return strError.empty() ? EnforcerSettingsCheck::OK : EnforcerSettingsCheck::MISMATCH;
}

bool EnforcerL1Client::IsBehindItsNode(std::string& strWhy)
{
    if (gArgs.GetArg("-mainchainrest", DEFAULT_MAINCHAIN_REST).empty())
        return false;
    L1BlockHeader tip;
    if (!GetChainTip(tip))
        return false;
    std::string strBody;
    UniValue info;
    if (!RestGet("/rest/chaininfo.json", strBody) || !info.read(strBody) || !info.isObject())
        return false;
    const UniValue& blocks = find_value(info, "blocks");
    if (!blocks.isNum() || blocks.get_int() <= (int)tip.nHeight)
        return false;
    strWhy = strprintf("the enforcer's eCash tip (%d) is behind its eCash node's (%d); no bid until it catches up",
                       tip.nHeight, blocks.get_int());
    return true;
}

bool EnforcerL1Client::FetchWithdrawalEvents(std::vector<L1WithdrawalEvent>& vEvents)
{
    L1BlockHeader tip;
    if (!GetChainTip(tip))
        return false;

    std::string strRequest = "{\"sidechain_id\": " + std::to_string(THIS_SIDECHAIN) +
        ", \"end_block_hash\": {\"hex\": \"" + tip.hashBlock.ToString() + "\"}}";

    UniValue result(UniValue::VOBJ);
    if (!CallValidator("GetTwoWayPegData", strRequest, result))
        return false;

    return ParseEnforcerWithdrawalEvents(result, vEvents);
}

// Map a chassis bundle hash (the bundle txid, dummy input included - the
// value committed in sidechain blocks and passed to the status queries) to
// the enforcer's m6id: the txid of the SAME bundle with its inputs stripped.
// The enforcer's compute_m6id is compute_txid() of the zero-input BlindedM6
// (bip300301_enforcer lib/types.rs), and a txid is the hash of the
// no-witness serialization on both sides, so stripping vin is the whole map.
char BundleOutcome(const std::vector<L1WithdrawalEvent>& vEvents, const uint256& m6id)
{
    char cLast = 0;
    for (const L1WithdrawalEvent& ev : vEvents) {
        if (ev.m6id != m6id)
            continue;
        if (ev.status == 'S')
            return 'S';
        cLast = ev.status;
    }
    return cLast;
}

uint256 BundleM6id(const CTransaction& txBundle)
{
    CMutableTransaction mtx(txBundle);
    mtx.vin.clear();
    return L1MutableTransaction(mtx).GetHash(); // the L1 layout (A5), as the enforcer hashes it
}

static bool BlindedM6IdForBundle(const uint256& hashBundle, uint256& m6id)
{
    if (!psidechaintree)
        return false;

    SidechainWithdrawalBundle bundle;
    if (!psidechaintree->GetWithdrawalBundle(hashBundle, bundle))
        return false;

    m6id = BundleM6id(bundle.tx);
    return true;
}

bool EnforcerL1Client::HaveSpentWithdrawalBundle(const uint256& hash)
{
    // "Spent" == the bundle's M6 payout succeeded on the mainchain. Translate
    // the chassis bundle hash to the enforcer m6id before matching events; an
    // unknown bundle fails closed.
    uint256 m6id;
    if (!BlindedM6IdForBundle(hash, m6id))
        return false;

    std::vector<L1WithdrawalEvent> vEvents;
    if (!FetchWithdrawalEvents(vEvents))
        return false;

    for (const L1WithdrawalEvent& e : vEvents) {
        if (e.status == 'S' && e.m6id == m6id)
            return true;
    }
    return false;
}

bool EnforcerL1Client::HaveFailedWithdrawalBundle(const uint256& hash)
{
    // Same chassis-hash -> m6id translation as HaveSpentWithdrawalBundle.
    uint256 m6id;
    if (!BlindedM6IdForBundle(hash, m6id))
        return false;

    std::vector<L1WithdrawalEvent> vEvents;
    if (!FetchWithdrawalEvents(vEvents))
        return false;

    for (const L1WithdrawalEvent& e : vEvents) {
        if (e.status == 'F' && e.m6id == m6id)
            return true;
    }
    return false;
}

//
// Transport selection
//

bool IsValidL1Transport(const std::string& strTransport)
{
    return strTransport == "jsonrpc" || strTransport == "enforcer";
}

bool IsValidEnforcerTransport(const std::string& strTransport)
{
    return strTransport == "connect" || strTransport == "grpcurl";
}

EnforcerTransport GetEnforcerTransport()
{
    // Read per call (a string compare next to a network round trip), so the
    // unit tests can switch transports with ForceSetArg
    return gArgs.GetArg("-enforcertransport", DEFAULT_ENFORCER_TRANSPORT) == "grpcurl" ?
        EnforcerTransport::GRPCURL : EnforcerTransport::CONNECT;
}

std::string EnforcerStatusLabel()
{
    return GetEnforcerTransport() == EnforcerTransport::GRPCURL ? "grpcurl exit" : "connect status";
}

std::string BuildGrpcurlCommand(const std::string& strBin, const std::string& strRequest, const std::string& strAddr, const std::string& strService, const std::string& strMethod, bool fStderr, int nMaxTime)
{
    if (strBin.find('"') != std::string::npos)
        return "";
    return "\"" + strBin + "\" -plaintext -max-time " + std::to_string(nMaxTime) + " -d '" + strRequest + "' " +
        strAddr + " " + strService + "/" + strMethod + (fStderr ? " 2>&1" : " 2>/dev/null");
}

static const char* const GRPCURL_EXTRA_DIRS[] = {"/opt/homebrew/bin", "/usr/local/bin"};

/** PATH's entries in order. An empty entry means the current directory to the shell; it is
 *  dropped here, as a daemon's working directory means nothing. */
static std::vector<std::string> SplitPathEnv(const std::string& strPathEnv)
{
    std::vector<std::string> vDir;
    size_t nStart = 0;
    while (nStart <= strPathEnv.size()) {
        size_t nEnd = strPathEnv.find(':', nStart);
        if (nEnd == std::string::npos)
            nEnd = strPathEnv.size();
        if (nEnd > nStart)
            vDir.push_back(strPathEnv.substr(nStart, nEnd - nStart));
        nStart = nEnd + 1;
    }
    return vDir;
}

static std::string JoinPath(const std::string& strDir, const std::string& strName)
{
    return strDir + (strDir.back() == '/' ? "" : "/") + strName;
}

GrpcurlLocation FindGrpcurl(const std::string& strPathEnv, const std::string& strExeDir,
                            const std::function<bool(const std::string&)>& fnIsExecutable)
{
    GrpcurlLocation loc;
    loc.strPath = "grpcurl";

    auto tryDir = [&](const std::string& strDir, const std::string& strSource) {
        if (loc.fFound || strDir.empty())
            return;
        const std::string strCandidate = JoinPath(strDir, "grpcurl");
        if (fnIsExecutable(strCandidate)) {
            loc.strPath = strCandidate;
            loc.strSource = strSource;
            loc.fFound = true;
        }
    };

    for (const std::string& strDir : SplitPathEnv(strPathEnv))
        tryDir(strDir, "PATH");
    // Next to freebankd (a bundle can ship it there), then where Homebrew puts
    // it: a macOS GUI launch has PATH=/usr/bin:/bin:/usr/sbin:/sbin only.
    tryDir(strExeDir, "next to freebankd");
    for (const char* pszDir : GRPCURL_EXTRA_DIRS)
        tryDir(pszDir, pszDir);

    return loc;
}

static bool IsExecutableFile(const std::string& strPath)
{
    struct stat st;
    return stat(strPath.c_str(), &st) == 0 && S_ISREG(st.st_mode) && access(strPath.c_str(), X_OK) == 0;
}

/** The directory holding the running executable, or "" if unknown. */
static std::string ExecutableDir()
{
    std::string strExe;
#ifdef __APPLE__
    char buf[PATH_MAX];
    uint32_t nSize = sizeof(buf);
    if (_NSGetExecutablePath(buf, &nSize) == 0) {
        char bufReal[PATH_MAX];
        strExe = realpath(buf, bufReal) ? bufReal : buf;
    }
#else
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0)
        strExe = std::string(buf, n);
#endif
    size_t nSlash = strExe.rfind('/');
    return nSlash == std::string::npos ? "" : strExe.substr(0, nSlash);
}

// How long a failed lookup is kept before the next call looks again, so a
// grpcurl installed after startup is picked up without a restart.
static const int64_t GRPCURL_MISS_RETRY_SECONDS = 30;

GrpcurlLocation GetGrpcurlLocation()
{
    static std::mutex mutexCache;
    static GrpcurlLocation cache;
    static int64_t nCacheTime = 0;
    static std::string strLogged;

    std::lock_guard<std::mutex> lock(mutexCache);

    GrpcurlLocation loc;
    if (gArgs.IsArgSet("-grpcurlbin")) {
        // The operator's choice is used as given; only "found" is judged here.
        loc.strPath = gArgs.GetArg("-grpcurlbin", "grpcurl");
        loc.strSource = "-grpcurlbin";
        if (loc.strPath.find('/') != std::string::npos) {
            loc.fFound = IsExecutableFile(loc.strPath);
        } else {
            // A bare name: the shell looks it up in PATH
            const char* pszPath = getenv("PATH");
            for (const std::string& strDir : SplitPathEnv(pszPath ? pszPath : ""))
                loc.fFound = loc.fFound || IsExecutableFile(JoinPath(strDir, loc.strPath));
        }
    } else {
        const int64_t nNow = GetTime();
        if (nCacheTime != 0 && (cache.fFound || nNow - nCacheTime < GRPCURL_MISS_RETRY_SECONDS))
            return cache;
        const char* pszPath = getenv("PATH");
        loc = FindGrpcurl(pszPath ? pszPath : "", ExecutableDir(), IsExecutableFile);
        cache = loc;
        nCacheTime = nNow;
    }

    const std::string strKey = loc.strPath + "|" + loc.strSource + "|" + (loc.fFound ? "1" : "0");
    if (strKey != strLogged) {
        strLogged = strKey;
        if (loc.fFound)
            LogPrintf("Enforcer client: using grpcurl %s (%s)\n", loc.strPath, loc.strSource);
        else
            LogPrintf("ERROR Enforcer client: grpcurl not found (%s); the enforcer transport cannot work. "
                      "Install grpcurl or set -grpcurlbin=<path>\n",
                      loc.strSource == "-grpcurlbin" ? "-grpcurlbin=" + loc.strPath
                                                     : std::string("looked in PATH, next to freebankd, /opt/homebrew/bin, /usr/local/bin"));
    }
    return loc;
}

GrpcurlFailure ClassifyGrpcurlFailure(int nExit, const std::string& strError)
{
    if (nExit == 0)
        return GrpcurlFailure::NONE;
    // The server answered Unimplemented (64 + gRPC code 12)
    if (nExit == 76)
        return GrpcurlFailure::UNIMPLEMENTED;
    // grpcurl resolves the method through the server's reflection before it
    // calls; a method the enforcer does not know never reaches the server
    if (nExit == 1 && (strError.find("does not include a method named") != std::string::npos ||
            strError.find("does not expose service") != std::string::npos))
        return GrpcurlFailure::UNIMPLEMENTED;
    return GrpcurlFailure::OTHER;
}

bool GrpcurlBMMRequestNotSent(int nExit, const std::string& strError)
{
    if (nExit == 0 || nExit == -1)
        return false;
    // The shell could not find grpcurl, or the enforcer lacks the method
    if (nExit == 127 || ClassifyGrpcurlFailure(nExit, strError) == GrpcurlFailure::UNIMPLEMENTED)
        return true;
    // InvalidArgument / FailedPrecondition: refused before the tx was built
    if (nExit == 67 || nExit == 73)
        return true;
    // Unknown from create_bmm_request's build or sign step, before the broadcast
    if (nExit == 66 && (strError.find("failed to build BMM tx") != std::string::npos ||
            strError.find("failed to sign BMM tx") != std::string::npos))
        return true;
    // grpcurl never reached the enforcer
    if (nExit == 1 && strError.find("Failed to dial target host") != std::string::npos)
        return true;
    return false;
}

const std::string& DefaultMainchainTransport()
{
    static const std::string jsonrpc = "jsonrpc";
    static const std::string enforcer = "enforcer";
    return Params().NetworkIDString() == CBaseChainParams::REGTEST ? jsonrpc : enforcer;
}

L1Transport GetL1Transport()
{
    static const L1Transport transport =
        gArgs.GetArg("-mainchaintransport", DefaultMainchainTransport()) == "enforcer" ?
            L1Transport::ENFORCER : L1Transport::JSONRPC;
    return transport;
}

L1Client& GetEnforcerL1Client()
{
    static EnforcerL1Client clientEnforcer;
    return clientEnforcer;
}

static std::atomic<L1Client*> g_pL1ClientForTest{nullptr};

void SetL1ClientForTest(L1Client* pClient)
{
    g_pL1ClientForTest.store(pClient);
}

L1Client& GetL1Client()
{
    static JsonRpcL1Client clientJsonRpc;

    if (L1Client* pClient = g_pL1ClientForTest.load())
        return *pClient;

    if (GetL1Transport() == L1Transport::ENFORCER)
        return GetEnforcerL1Client();

    return clientJsonRpc;
}

namespace {
/** The production oracle: asks the selected transport (the JSON-RPC mainchain
 *  cannot answer the range question: UNKNOWN). */
class TransportL1Oracle : public L1Oracle
{
public:
    L1Answer EventsInWindow(const uint256& hashStart, const uint256& hashEnd, L1PegEvents& events) override
    {
        return GetL1Client().GetPegEvents(hashStart, hashEnd, events);
    }
    L1Answer BmmCommitment(const uint256& hashMainBlock, const uint256& hashBMM) override
    {
        uint256 hashCommitment;
        switch (GetL1Client().ReadBmmCommitment(hashMainBlock, hashCommitment)) {
        case L1Client::Commitment::COMMITTED: return hashCommitment == hashBMM ? L1Answer::YES : L1Answer::NO;
        case L1Client::Commitment::NONE: return L1Answer::NO;
        case L1Client::Commitment::NOT_FOUND: return L1Answer::UNKNOWN;
        case L1Client::Commitment::UNKNOWN: break;
        }
        // The JSON-RPC mainchain has no reader: its verifybmm, true = yes
        uint256 txid;
        uint32_t nTime = 0;
        return GetL1Client().VerifyBMM(hashMainBlock, hashBMM, txid, nTime) ? L1Answer::YES : L1Answer::UNKNOWN;
    }
};

std::atomic<L1Oracle*> g_pL1OracleForTest{nullptr};
} // namespace

L1Oracle& GetL1Oracle()
{
    static TransportL1Oracle oracleTransport;
    L1Oracle* pOracle = g_pL1OracleForTest.load();
    return pOracle ? *pOracle : oracleTransport;
}

void SetL1OracleForTest(L1Oracle* pOracle)
{
    g_pL1OracleForTest.store(pOracle);
}

//
// JsonRpcL1Client (bodies moved verbatim from SidechainClient)
//

bool JsonRpcL1Client::BroadcastWithdrawalBundle(const std::string& hex)
{
    // JSON for sending the WithdrawalBundle to mainchain via HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"receivewithdrawalbundle\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append(",\"");
    json.append(hex);
    json.append("\"] }");

    // TODO Read result
    // the mainchain will return the txid if WithdrawalBundle has been received
    boost::property_tree::ptree ptree;
    return SendRequestToMainchain(json, ptree);
}

// TODO return bool & state / fail string
std::vector<SidechainDeposit> JsonRpcL1Client::UpdateDeposits(const uint256& hashLastDeposit, uint32_t nLastBurnIndex)
{
    // List of deposits in sidechain format for DB
    std::vector<SidechainDeposit> incoming;

    // JSON for requesting sidechain deposits via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"listsidechaindeposits\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    if (hashLastDeposit.IsNull()) {
        json.append("] }");
    } else {
        json.append(",");
        json.append("\"");
        json.append(hashLastDeposit.ToString());
        json.append("\",");
        json.append(UniValue(uint64_t(nLastBurnIndex)).write());
        json.append("] }");
    }

    // Try to request deposits from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request new deposits\n");
        return incoming;
    }

    // Process deposits
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        // Looping through list of deposits
        SidechainDeposit deposit;
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            // Looping through this deposit's members
            if (v.first == "nsidechain") {
                // Read sidechain number
                std::string data = v.second.data();
                if (!data.length())
                    continue;
                uint8_t nSidechain = std::stoi(data);
                if (nSidechain != THIS_SIDECHAIN)
                    continue;

                deposit.nSidechain = nSidechain;
            }
            else
            if (v.first == "strdest") {
                // Read destination string
                std::string strDest = v.second.data();
                if (strDest.empty())
                    continue;

                deposit.strDest = strDest;
            }
            else
            if (v.first == "txhex") {
                // Read deposit transaction hex
                std::string data = v.second.data();
                if (!data.length())
                    continue;
                if (!IsHex(data))
                    continue;
                if (!DecodeHexTx(deposit.dtx, data))
                    continue;
            }
            else
            if (v.first == "nburnindex") {
                // Read deposit output index
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                deposit.nBurnIndex = std::stoi(data);
            }
            else
            if (v.first == "ntx") {
                // Read mainchain block hash
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                deposit.nTx = std::stoi(data);
            }
            else
            if (v.first == "hashblock") {
                // Read mainchain block hash
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                deposit.hashMainchainBlock = uint256S(data);
            }
        }

        if (deposit.nBurnIndex >= deposit.dtx.vout.size()) {
            LogPrintf("%s: Error invalid deposit output index!\n", __func__);
            continue;
        }

        // Get the user payout amount from the deposit output. At this point the
        // amount is the total CTIP, and the real payout will be calculated
        // later.
        deposit.amtUserPayout = deposit.dtx.vout[deposit.nBurnIndex].nValue;

        // Add this deposit to the list
        incoming.push_back(deposit);
    }
    // LogPrintf("Sidechain client received %d deposits\n", incoming.size());

    // The deposits are sent in reverse order. Putting the deposits back in
    // order should make sorting faster.
    std::reverse(incoming.begin(), incoming.end());

    // return valid (in terms of format) deposits in sidechain format
    return incoming;
}

bool JsonRpcL1Client::VerifyDeposit(const uint256& hashMainBlock, const uint256& txid, const int nTx)
{
    // JSON for requesting deposit verification via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"verifydeposit\", \"params\": ");
    json.append("[\"");
    json.append(hashMainBlock.ToString());
    json.append("\",\"");
    json.append(txid.ToString());
    json.append("\",");
    json.append(UniValue(nTx).write());
    json.append("] }");

    // Ask mainchain node to verify deposit
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        // Can be enabled for debug -- too noisy
        // LogPrintf("ERROR Sidechain client failed to verify deposit!\n");
        return false;
    }

    // Process result
    uint256 txidRet = uint256S(ptree.get("result", ""));
    return (txid == txidRet);
}

bool JsonRpcL1Client::VerifyBMM(const uint256& hashMainBlock, const uint256& hashBMM, uint256& txid, uint32_t& nTime)
{
    // JSON for requesting BMM proof via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"verifybmm\", \"params\": ");
    json.append("[\"");
    json.append(hashMainBlock.ToString());
    json.append("\",\"");
    json.append(hashBMM.ToString());
    json.append("\",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request BMM proof from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        // Can be enabled for debug -- too noisy
        // LogPrintf("ERROR Sidechain client failed to request BMM proof\n");
        return false;
    }

    // Process result
    bool fFoundTx = false;
    bool fFoundTime = false;
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            if (v.first == "txid") {
                // Read BMM txid
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                txid = uint256S(data);
                fFoundTx = true;
            }
            else
            if (v.first == "time") {
                // Read mainchain block time
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                nTime = std::stoi(data);
                fFoundTime = true;
            }
        }
    }

    if (fFoundTx && fFoundTime) {
        LogPrintf("Sidechain client found BMM for h*: %s\n", hashBMM.ToString());
        return true;
    } else {
        // Can be enabled for debug -- too noisy
        // LogPrintf("Sidechain client found no BMM.\n");
        return false;
    }
}

uint256 JsonRpcL1Client::SendBMMRequest(const uint256& hashCritical, const uint256& hashBlockMain, int nHeight, CAmount amount, bool& fNotSent)
{
    // A failed call here cannot tell a refusal from a lost reply: never
    // report "not sent", so the tip stays claimed (the pre-v0.2.16 rule).
    fNotSent = false;
    uint256 txid = uint256();
    std::string strPrevHash = hashBlockMain.ToString();

    if (amount == CAmount(0))
        amount = DEFAULT_CRITICAL_DATA_AMOUNT;

    // JSON for sending critical data request to mainchain via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"createbmmcriticaldatatx\", \"params\": ");
    json.append("[\"");
    json.append(ValueFromAmount(amount).write());
    json.append("\",");
    json.append(UniValue(nHeight).write());
    json.append(",\"");
    json.append(hashCritical.ToString());
    json.append("\",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append(",\"");
    json.append(strPrevHash.substr(strPrevHash.size() - 8, strPrevHash.size() - 1));
    json.append("\"");
    json.append("] }");

    // Try to send critical data request to mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to create BMM request on mainchain!\n");
        return txid; // TODO
    }

    // Process result
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            // Looping through members
            if (v.first == "txid") {
                // Read txid
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                txid = uint256S(data);
            }
        }
    }
    if (!txid.IsNull())
        LogPrintf("Sidechain client created critical data request. TXID: %s\n", txid.ToString());

    return txid;
}

bool JsonRpcL1Client::GetCTIP(std::pair<uint256, uint32_t>& ctip)
{
    // JSON for requesting sidechain CTIP via mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"listsidechainctip\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request CTIP from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        // TODO LogPrintf("ERROR Sidechain client failed to request CTIP\n");
        return false;
    }

    // Process CTIP
    uint256 txid;
    uint32_t n = 0;
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        if (value.first == "n") {
            // Read n
            std::string data = value.second.data();
            if (!data.length())
                continue;
            n = std::stoi(data);
        }
        else
        if (value.first == "txid") {
            // Read TXID
            std::string data = value.second.data();
            if (!data.length())
                continue;

            txid = uint256S(data);
        }
    }
    // TODO LogPrintf("Sidechain client received CTIP\n");

    ctip = std::make_pair(txid, n);

    return true;
}

bool JsonRpcL1Client::GetAverageFees(int nBlocks, int nStartHeight, CAmount& nAverageFee)
{
    // JSON for 'getaveragefees' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getaveragefee\", \"params\": ");
    json.append("[");
    json.append(UniValue(nBlocks).write());
    json.append(",");
    json.append(UniValue(nStartHeight).write());
    json.append("]");
    json.append("}");

    // Try to request average fees from mainchain
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request average fees\n");
        return false;
    }

    // Process result
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        // Looping through members
        if (value.first == "feeaverage") {
            // Read
            std::string data = value.second.data();
            if (!data.length()) {
                LogPrintf("ERROR Sidechain client received invalid data\n");
                return false;
            }

            if (ParseMoney(data, nAverageFee)) {
                LogPrintf("Sidechain client received average mainchain fee: %d.\n", nAverageFee);
                return true;
            }
        }
    }
    return false;
}

bool JsonRpcL1Client::GetBlockCount(int& nBlocks)
{
    // JSON for 'getblockcount' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getblockcount\", \"params\": ");
    json.append("[] }");

    // Try to request mainchain block count
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request block count\n");
        return false;
    }

    // Process result
    nBlocks = ptree.get("result", 0);

    return nBlocks >= 0;
}

bool JsonRpcL1Client::GetWorkScore(const uint256& hash, int& nWorkScore)
{
    // JSON for 'getworkscore' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getworkscore\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append(",");
    json.append("\"");
    json.append(hash.ToString());
    json.append("\"");
    json.append("] }");

    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request workscore\n");
        return false;
    }

    // Process result, note that starting workscore on mainchain is 1
    nWorkScore = ptree.get("result", -1);

    return nWorkScore >= 0;
}

bool JsonRpcL1Client::ListWithdrawalBundleStatus(std::vector<uint256>& vHashWithdrawalBundle)
{
    // TODO for now this function is only being used to see if there are any
    // WithdrawalBundle(s) for nSidechain. The rest of the results could be useful for the
    // GUI though.

    // JSON for 'listwithdrawalstatus' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"listwithdrawalstatus\", \"params\": ");
    json.append("[");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request WithdrawalBundle status\n");
        return false;
    }

    // Process result
    BOOST_FOREACH(boost::property_tree::ptree::value_type &value, ptree.get_child("result")) {
        BOOST_FOREACH(boost::property_tree::ptree::value_type &v, value.second.get_child("")) {
            // Looping through members
            if (v.first == "hash") {
                // Read txid
                std::string data = v.second.data();
                if (!data.length())
                    continue;

                uint256 hash = uint256S(data);
                if (!hash.IsNull())
                    vHashWithdrawalBundle.push_back(hash);
            }
        }
    }

    return vHashWithdrawalBundle.size() > 0;
}

bool JsonRpcL1Client::GetBlockHash(int nHeight, uint256& hashBlock)
{
    // JSON for 'getblockhash' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"getblockhash\", \"params\": ");
    json.append("[");
    json.append(UniValue(nHeight).write());
    json.append("] }");

    // Try to request mainchain block hash
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request block hash!\n");
        return false;
    }

    std::string strHash = ptree.get("result", "");
    hashBlock = uint256S(strHash);

    return (!hashBlock.IsNull());
}

bool JsonRpcL1Client::GetAncestorHashes(const uint256& hashBlock, int nHeight, uint32_t nMax, std::vector<uint256>& vHash)
{
    // The JSON-RPC mainchain indexes by height, so each hash is a direct
    // lookup: walk heights down from the cursor. Unchanged from the historical
    // per-block behaviour (getblockhash is O(1) on this transport).
    vHash.clear();
    if (nMax == 0)
        return true;

    // The cursor block's own hash is already known - do not re-request it.
    vHash.push_back(hashBlock);

    for (uint32_t i = 1; i < nMax; i++) {
        const int nWant = nHeight - (int)i;
        if (nWant < 0)
            break;

        uint256 hash;
        if (!GetBlockHash(nWant, hash))
            return false;

        vHash.push_back(hash);
    }

    return true;
}

bool JsonRpcL1Client::HaveSpentWithdrawalBundle(const uint256& hash)
{
    // JSON for 'havespentwithdrawalbundle' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"havespentwithdrawal\", \"params\": ");
    json.append("[");
    json.append("\"");
    json.append(hash.ToString());
    json.append("\"");
    json.append(",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request mainchain block hash
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request spent WithdrawalBundle!\n");
        return false;
    }

    bool fSpent = ptree.get("result", false);

    return fSpent;
}

bool JsonRpcL1Client::HaveFailedWithdrawalBundle(const uint256& hash)
{
    // JSON for 'havefailedwithdrawalbundle' mainchain HTTP-RPC
    std::string json;
    json.append("{\"jsonrpc\": \"1.0\", \"id\":\"SidechainClient\", ");
    json.append("\"method\": \"havefailedwithdrawal\", \"params\": ");
    json.append("[");
    json.append("\"");
    json.append(hash.ToString());
    json.append("\"");
    json.append(",");
    json.append(UniValue((int)THIS_SIDECHAIN).write());
    json.append("] }");

    // Try to request mainchain block hash
    boost::property_tree::ptree ptree;
    if (!SendRequestToMainchain(json, ptree)) {
        LogPrintf("ERROR Sidechain client failed to request failed WithdrawalBundle!\n");
        return false;
    }

    bool fFailed = ptree.get("result", false);

    return fFailed;
}

bool JsonRpcL1Client::SendRequestToMainchain(const std::string& json, boost::property_tree::ptree &ptree)
{
    // Format user:pass for authentication
    std::string auth = gArgs.GetArg("-rpcuser", "") + ":" + gArgs.GetArg("-rpcpassword", "");
    if (auth == ":")
        return false;

    // Mainnet RPC = 8332
    // Testnet RPC = 18332
    // Regtest RPC = 18443
    //
    bool fRegtest = gArgs.GetBoolArg("-regtest", false);
    int port = fRegtest ? 18443 : 8332;

    try {
        // Setup BOOST ASIO for a synchronus call to the mainchain
        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query("127.0.0.1", std::to_string(port));
        tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
        tcp::resolver::iterator end;

        tcp::socket socket(io_service);
        boost::system::error_code error = boost::asio::error::host_not_found;

        // Try to connect
        while (error && endpoint_iterator != end)
        {
          socket.close();
          socket.connect(*endpoint_iterator++, error);
        }

        if (error) throw boost::system::system_error(error);

        // HTTP request (package the json for sending). HTTP/1.0 + Connection:
        // close, same rationale as RestGet: a 1.0 client must not be sent a
        // chunked reply (RFC 7230 3.3.1), so the body is Content-Length-framed
        // or close-delimited. CRLF endings per the RFC - the old bare-\n
        // endings worked only by evhttp leniency.
        boost::asio::streambuf output;
        std::ostream os(&output);
        os << "POST / HTTP/1.0\r\n";
        os << "Host: 127.0.0.1\r\n";
        os << "Content-Type: application/json\r\n";
        os << "Authorization: Basic " << EncodeBase64(auth) << "\r\n";
        os << "Connection: close\r\n";
        os << "Content-Length: " << json.size() << "\r\n\r\n";
        os << json;

        // Send the request
        boost::asio::write(socket, output);

        // Read the reponse
        std::string data;
        for (;;)
        {
            boost::array<char, 4096> buf;

            // Read until end of file (socket closed)
            boost::system::error_code e;
            size_t sz = socket.read_some(boost::asio::buffer(buf), e);

            data.insert(data.size(), buf.data(), sz);

            if (e == boost::asio::error::eof)
                break; // socket closed
            else if (e)
                throw boost::system::system_error(e);
        }

        // Structural response parse. The old positional parse (skip 5 CRs,
        // then a whitespace-delimited `>>` token read) was silently tuned to
        // 0.16-evhttp's exact header emission - which is 6 CRs before the
        // body, not 5, so it only worked because `>>` skipped the leftover
        // line as whitespace - and truncated any body containing a space.
        // That boundary miscount is also why the earlier "read the rest as
        // the body" fix returned an empty body for EVERY call and stalled
        // the whole peg. Parse the framing explicitly instead.

        // Split headers from body at the first blank line.
        size_t headerEnd = data.find("\r\n\r\n");
        size_t bodyStart;
        if (headerEnd != std::string::npos) {
            bodyStart = headerEnd + 4;
        } else {
            headerEnd = data.find("\n\n"); // LF-only server tolerance
            if (headerEnd == std::string::npos)
                return false;
            bodyStart = headerEnd + 2;
        }
        const std::string headers = data.substr(0, headerEnd);

        // Status code: second token of the status line.
        size_t sp = headers.find(' ');
        if (sp == std::string::npos)
            return false;
        int code = atoi(headers.substr(sp + 1, 4).c_str());
        if (code != 200)
            return false;

        // Case-insensitive scan for the framing headers.
        std::string lower;
        lower.reserve(headers.size());
        for (char c : headers)
            lower.push_back(std::tolower(static_cast<unsigned char>(c)));

        bool fChunked = false;
        size_t te = lower.find("transfer-encoding:");
        if (te != std::string::npos) {
            size_t eol = lower.find('\n', te);
            fChunked = lower.substr(te, eol - te).find("chunked") != std::string::npos;
        }

        // Extract the body: de-chunk / Content-Length prefix / close-delimited.
        // Chunked should never happen against an HTTP/1.0 request, but a
        // noncompliant server or interposed proxy must not feed the JSON
        // parser chunk-size lines (a bare hex size even parses as valid
        // JSON - silent garbage, not an error).
        std::string body;
        const std::string raw = data.substr(bodyStart);
        if (fChunked) {
            size_t pos = 0;
            for (;;) {
                size_t eol = raw.find("\r\n", pos);
                if (eol == std::string::npos)
                    return false;
                unsigned long sz = strtoul(raw.substr(pos, eol - pos).c_str(), nullptr, 16);
                if (sz == 0)
                    break;
                pos = eol + 2;
                if (pos + sz > raw.size())
                    return false;
                body.append(raw, pos, sz);
                pos += sz;
                if (raw.compare(pos, 2, "\r\n") == 0)
                    pos += 2;
            }
        } else {
            size_t cl = lower.find("content-length:");
            if (cl != std::string::npos) {
                unsigned long n = strtoul(lower.c_str() + cl + 15, nullptr, 10);
                if (raw.size() < n)
                    return false; // short read
                body = raw.substr(0, n);
            } else {
                body = raw; // close-delimited (Connection: close is requested)
            }
        }

        std::stringstream jss;
        jss << body;
        boost::property_tree::json_parser::read_json(jss, ptree);

        // JSON-RPC-level errors. This L1 can answer HTTP 200 with
        // {"error":{...},"id":...} and NO "result" node, and every caller
        // does a bare get_child("result") - so returning true here would
        // throw "No such node" out through the caller's RPC handler. The
        // old truncating parse never hit this only because the SPACE in the
        // error message crashed read_json first: the truncation bug was
        // doubling as the error handler. Handle it explicitly - and now the
        // actual error message reaches the log instead of being destroyed.
        if (!ptree.get_child_optional("result")) {
            boost::optional<boost::property_tree::ptree&> err = ptree.get_child_optional("error");
            LogPrintf("ERROR Sidechain client (sendRequestToMainchain): mainchain RPC error: %s\n",
                      err ? err->get<std::string>("message", "(no message)") : "(no result node)");
            return false;
        }
    } catch (std::exception &exception) {
        LogPrintf("ERROR Sidechain client (sendRequestToMainchain): %s\n", exception.what());
        return false;
    }
    return true;
}

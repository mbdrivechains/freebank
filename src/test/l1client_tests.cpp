// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <l1client.h>

#include <core_io.h>
#include <fs.h>
#include <primitives/transaction.h>
#include <test/test_bitcoin.h>
#include <uint256.h>
#include <univalue.h>
#include <utilstrencodings.h>
#include <validation.h>

#include <map>
#include <set>

#include <boost/test/unit_test.hpp>

#include <sys/stat.h>

// The canned JSON in this suite is captured from a live bip300301_enforcer
// v0.3.4 ValidatorService via grpcurl (bench, 2026-07-08). If the enforcer
// wire format changes these fixtures must be re-captured, not hand-edited.

BOOST_FIXTURE_TEST_SUITE(l1client_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(l1client_enforcer_transport_values)
{
    BOOST_CHECK(IsValidEnforcerTransport("connect"));
    BOOST_CHECK(IsValidEnforcerTransport("grpcurl"));
    BOOST_CHECK(!IsValidEnforcerTransport(""));
    BOOST_CHECK(!IsValidEnforcerTransport("grpc"));
    BOOST_CHECK(!IsValidEnforcerTransport("Connect"));
    BOOST_CHECK_EQUAL(std::string(DEFAULT_ENFORCER_TRANSPORT), "connect");
    BOOST_CHECK(GetEnforcerTransport() == EnforcerTransport::CONNECT);
    gArgs.ForceSetArg("-enforcertransport", "grpcurl");
    BOOST_CHECK(GetEnforcerTransport() == EnforcerTransport::GRPCURL);
    BOOST_CHECK_EQUAL(EnforcerStatusLabel(), "grpcurl exit");
    gArgs.ForceSetArg("-enforcertransport", DEFAULT_ENFORCER_TRANSPORT);
    BOOST_CHECK_EQUAL(EnforcerStatusLabel(), "connect status");
}

BOOST_AUTO_TEST_CASE(l1client_transport_values)
{
    BOOST_CHECK(IsValidL1Transport("jsonrpc"));
    BOOST_CHECK(IsValidL1Transport("enforcer"));
    BOOST_CHECK(!IsValidL1Transport(""));
    BOOST_CHECK(!IsValidL1Transport("grpc"));
    BOOST_CHECK(!IsValidL1Transport("Enforcer"));
}

BOOST_AUTO_TEST_CASE(l1client_consensus_hex)
{
    // uint256's string form is display order (byte-reversed); ConsensusHex is
    // internal order. Value 1 = internal bytes 01 00 ... 00.
    uint256 one = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    BOOST_CHECK_EQUAL(ConsensusHexFromUint256(one),
        "0100000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK(Uint256FromConsensusHex("0100000000000000000000000000000000000000000000000000000000000000") == one);

    // Round trip an asymmetric value
    uint256 hash = uint256S("412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569");
    BOOST_CHECK(Uint256FromConsensusHex(ConsensusHexFromUint256(hash)) == hash);

    // Bad input -> null
    BOOST_CHECK(Uint256FromConsensusHex("").IsNull());
    BOOST_CHECK(Uint256FromConsensusHex("abcd").IsNull());
    BOOST_CHECK(Uint256FromConsensusHex("zz00000000000000000000000000000000000000000000000000000000000000").IsNull());
}

BOOST_AUTO_TEST_CASE(l1client_parse_chaintip)
{
    // Live GetChainTip response. ReverseHex hashes equal bitcoin display hex
    // (verified against getbestblockhash); uint64 timestamp arrives as a
    // JSON string.
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"blockHeaderInfo\": {"
        "\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"},"
        "\"prevBlockHash\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"},"
        "\"height\": 3,"
        "\"work\": {\"hex\": \"0200000000000000000000000000000000000000000000000000000000000000\"},"
        "\"timestamp\": \"1783480879\"}}"));

    L1BlockHeader header;
    BOOST_REQUIRE(ParseEnforcerChainTip(response, header));
    BOOST_CHECK(header.hashBlock == uint256S("412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569"));
    BOOST_CHECK(header.hashPrevBlock == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));
    BOOST_CHECK_EQUAL(header.nHeight, 3);
    BOOST_CHECK_EQUAL(header.nTime, 1783480879);

    // Missing blockHash -> parse failure
    UniValue bad(UniValue::VOBJ);
    BOOST_REQUIRE(bad.read("{\"blockHeaderInfo\": {\"height\": 3}}"));
    BOOST_CHECK(!ParseEnforcerChainTip(bad, header));
}

BOOST_AUTO_TEST_CASE(l1client_parse_headerinfos)
{
    // GetBlockHeaderInfo with ancestors, newest first. The genesis entry has
    // proto3 zero defaults omitted (no height key).
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"headerInfos\": ["
        "{\"blockHash\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"},"
        "\"prevBlockHash\": {\"hex\": \"6635079af4e71b8e1de215be1ae0ab44def0157506e6226b681ce889d319f740\"},"
        "\"height\": 2, \"timestamp\": \"1783480879\"},"
        "{\"blockHash\": {\"hex\": \"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206\"},"
        "\"timestamp\": \"1296688602\"}"
        "]}"));

    std::vector<L1BlockHeader> vHeader;
    BOOST_REQUIRE(ParseEnforcerHeaderInfos(response, vHeader));
    BOOST_REQUIRE_EQUAL(vHeader.size(), 2);
    BOOST_CHECK_EQUAL(vHeader[0].nHeight, 2);
    BOOST_CHECK(vHeader[0].hashBlock == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));
    BOOST_CHECK_EQUAL(vHeader[1].nHeight, 0);
    BOOST_CHECK(vHeader[1].hashPrevBlock.IsNull());

    // Empty list -> failure (caller always requests at least the block itself)
    UniValue empty(UniValue::VOBJ);
    BOOST_REQUIRE(empty.read("{\"headerInfos\": []}"));
    BOOST_CHECK(!ParseEnforcerHeaderInfos(empty, vHeader));
}

BOOST_AUTO_TEST_CASE(l1client_parse_bmm_commitment)
{
    bool fBlockFound;
    bool fHaveCommitment;
    uint256 hashCommitment;

    // Unknown block
    UniValue notFound(UniValue::VOBJ);
    BOOST_REQUIRE(notFound.read(
        "{\"blockNotFound\": {\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"}}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitment(notFound, fBlockFound, fHaveCommitment, hashCommitment));
    BOOST_CHECK(!fBlockFound);
    BOOST_CHECK(!fHaveCommitment);

    // Known block, no h* for this sidechain (live capture)
    UniValue noCommit(UniValue::VOBJ);
    BOOST_REQUIRE(noCommit.read("{\"commitment\": {}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitment(noCommit, fBlockFound, fHaveCommitment, hashCommitment));
    BOOST_CHECK(fBlockFound);
    BOOST_CHECK(!fHaveCommitment);

    // Known block with a commitment. bmm_commitment is ConsensusHex
    // (internal byte order): the reverse of the display-order h*.
    uint256 hashBMM = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    UniValue commit(UniValue::VOBJ);
    BOOST_REQUIRE(commit.read(
        "{\"commitment\": {\"commitment\": {\"hex\": \"0100000000000000000000000000000000000000000000000000000000000000\"}}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitment(commit, fBlockFound, fHaveCommitment, hashCommitment));
    BOOST_CHECK(fBlockFound);
    BOOST_CHECK(fHaveCommitment);
    BOOST_CHECK(hashCommitment == hashBMM);

    // Commitment present but unreadable -> parse failure ("can't tell"),
    // never a "no" that would fail the side block for good
    for (const char* bad : {"{\"commitment\": {\"commitment\": {\"hex\": \"zz\"}}}",
                            "{\"commitment\": {\"commitment\": {\"hex\": \"0100\"}}}",
                            "{\"commitment\": {\"commitment\": {}}}",
                            "{\"commitment\": {\"commitment\": \"01\"}}"}) {
        UniValue malformed(UniValue::VOBJ);
        BOOST_REQUIRE(malformed.read(bad));
        BOOST_CHECK_MESSAGE(!ParseEnforcerBmmCommitment(malformed, fBlockFound, fHaveCommitment, hashCommitment), bad);
    }

    // Garbage -> parse failure
    UniValue garbage(UniValue::VOBJ);
    BOOST_REQUIRE(garbage.read("{\"unexpected\": 1}"));
    BOOST_CHECK(!ParseEnforcerBmmCommitment(garbage, fBlockFound, fHaveCommitment, hashCommitment));
}

BOOST_AUTO_TEST_CASE(l1client_parse_block_deposit_txids)
{
    // GetBlockInfo response: one deposit event and one withdrawal event; only
    // the deposit txid (ReverseHex = display order) should be collected.
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"infos\": [{"
        "\"headerInfo\": {\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"}, \"height\": 3},"
        "\"blockInfo\": {\"events\": ["
        "{\"deposit\": {\"sequenceNumber\": \"7\","
        "\"outpoint\": {\"txid\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"}, \"vout\": 1},"
        "\"output\": {\"address\": {\"hex\": \"deadbeef\"}, \"valueSats\": \"1000000000\"}}},"
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"6635079af4e71b8e1de215be1ae0ab44def0157506e6226b681ce889d319f740\"}, \"event\": {\"failed\": {}}}}"
        "]}}]}"));

    std::vector<uint256> vTxid;
    BOOST_REQUIRE(ParseEnforcerBlockDepositTxids(response, vTxid));
    BOOST_REQUIRE_EQUAL(vTxid.size(), 1);
    BOOST_CHECK(vTxid[0] == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));

    // Block found, no events for this sidechain
    UniValue noEvents(UniValue::VOBJ);
    BOOST_REQUIRE(noEvents.read(
        "{\"infos\": [{\"headerInfo\": {\"blockHash\": {\"hex\": \"412df67dca755f78c3c05aaece866329490fb446340d4628ab94a3d860ccc569\"}, \"height\": 3}, \"blockInfo\": {}}]}"));
    BOOST_REQUIRE(ParseEnforcerBlockDepositTxids(noEvents, vTxid));
    BOOST_CHECK(vTxid.empty());

    // Unknown block -> empty infos -> failure
    UniValue unknown(UniValue::VOBJ);
    BOOST_REQUIRE(unknown.read("{\"infos\": []}"));
    BOOST_CHECK(!ParseEnforcerBlockDepositTxids(unknown, vTxid));
}

BOOST_AUTO_TEST_CASE(l1client_parse_ctip)
{
    uint256 txid;
    uint32_t n = 999;

    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"ctip\": {\"txid\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"},"
        "\"vout\": 2, \"value\": \"1000000000\", \"sequenceNumber\": \"5\"}}"));
    BOOST_REQUIRE(ParseEnforcerCtip(response, txid, n));
    BOOST_CHECK(txid == uint256S("4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8"));
    BOOST_CHECK_EQUAL(n, 2);

    // Absent vout = proto3 zero default
    UniValue voutZero(UniValue::VOBJ);
    BOOST_REQUIRE(voutZero.read(
        "{\"ctip\": {\"txid\": {\"hex\": \"4c22d412e6132b5724f0b02bd814fa46b4f14c56e1adb71dd6a8833c1fedc1c8\"}, \"value\": \"1000000000\"}}"));
    BOOST_REQUIRE(ParseEnforcerCtip(voutZero, txid, n));
    BOOST_CHECK_EQUAL(n, 0);

    // No ctip (no deposits yet) -> false
    UniValue noCtip(UniValue::VOBJ);
    BOOST_REQUIRE(noCtip.read("{}"));
    BOOST_CHECK(!ParseEnforcerCtip(noCtip, txid, n));
}

BOOST_AUTO_TEST_CASE(l1client_parse_withdrawal_events)
{
    // GetTwoWayPegData with withdrawal_bundle events across two blocks: one
    // Succeeded, one Failed, one Submitted. m6id is ConsensusHex (internal byte
    // order) -> decodes byte-reversed relative to display, like bmm_commitment.
    // m6id 0100..00 (internal) == uint256 value 1 (display ..0001).
    UniValue response(UniValue::VOBJ);
    BOOST_REQUIRE(response.read(
        "{\"blocks\": ["
        "{\"blockHeaderInfo\": {\"blockHash\": {\"hex\": \"00000000000000000000000000000000000000000000000000000000000000aa\"}},"
        "\"blockInfo\": {\"events\": ["
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"0100000000000000000000000000000000000000000000000000000000000000\"},"
        "\"event\": {\"succeeded\": {\"sequenceNumber\": \"3\", \"transaction\": {\"hex\": \"abcd\"}}}}},"
        "{\"deposit\": {\"sequenceNumber\": \"4\"}}"
        "]}},"
        "{\"blockInfo\": {\"events\": ["
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"0200000000000000000000000000000000000000000000000000000000000000\"},"
        "\"event\": {\"failed\": {}}}},"
        "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"0300000000000000000000000000000000000000000000000000000000000000\"},"
        "\"event\": {\"submitted\": {}}}}"
        "]}}"
        "]}"));

    std::vector<L1WithdrawalEvent> vEvents;
    BOOST_REQUIRE(ParseEnforcerWithdrawalEvents(response, vEvents));
    BOOST_REQUIRE_EQUAL(vEvents.size(), 3);   // deposit event ignored

    BOOST_CHECK(vEvents[0].m6id == uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    BOOST_CHECK_EQUAL(vEvents[0].status, 'S');
    // Block hash is ReverseHex (display order) - no byte flip
    BOOST_CHECK(vEvents[0].hashMainBlock == uint256S("00000000000000000000000000000000000000000000000000000000000000aa"));
    // Second fixture block has no blockHeaderInfo: events still parse, hash null
    BOOST_CHECK(vEvents[1].hashMainBlock.IsNull());
    BOOST_CHECK(vEvents[1].m6id == uint256S("0000000000000000000000000000000000000000000000000000000000000002"));
    BOOST_CHECK_EQUAL(vEvents[1].status, 'F');
    BOOST_CHECK(vEvents[2].m6id == uint256S("0000000000000000000000000000000000000000000000000000000000000003"));
    BOOST_CHECK_EQUAL(vEvents[2].status, 'U');

    // Empty / no peg data -> valid empty result
    UniValue empty(UniValue::VOBJ);
    BOOST_REQUIRE(empty.read("{\"blocks\": []}"));
    BOOST_CHECK(ParseEnforcerWithdrawalEvents(empty, vEvents));
    BOOST_CHECK(vEvents.empty());
}

// v0.2.13 item 2: the bundle double-propose guard must count only bundles L1
// is STILL tracking. The events come from the full L1 history (oldest first).
static L1WithdrawalEvent MakeEvent(const uint256& m6id, char status)
{
    L1WithdrawalEvent e;
    e.m6id = m6id;
    e.status = status;
    return e;
}

BOOST_AUTO_TEST_CASE(l1client_pending_m6ids_fold)
{
    const uint256 X = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    const uint256 Y = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    const uint256 Z = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    typedef std::vector<L1WithdrawalEvent> Ev;
    typedef std::vector<uint256> Ids;

    BOOST_CHECK(PendingM6idsFromEvents(Ev{}) == Ids{});
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U')}) == Ids{X});
    // The item-2 regression: a paid or expired bundle is no longer pending
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(X, 'S')}) == Ids{});
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(X, 'F')}) == Ids{});
    // Paid, then a new (ours or foreign) bundle proposed
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(X, 'S'), MakeEvent(Y, 'U')}) == Ids{Y});
    // Re-proposal of the same m6id after expiry
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(X, 'F'), MakeEvent(X, 'U')}) == Ids{X});
    // M6 removes only the paid m6id
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(Y, 'U'), MakeEvent(X, 'S')}) == Ids{Y});
    // First-submission order is kept
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(Y, 'U')}) == (Ids{X, Y}));
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(Y, 'U'), MakeEvent(X, 'U')}) == (Ids{Y, X}));
    // A terminal event with no Submitted in view (truncated history) is ignored
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(Z, 'S')}) == Ids{});
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(Z, 'F'), MakeEvent(X, 'U')}) == Ids{X});
    // A duplicate Submitted is counted once
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(X, 'U')}) == Ids{X});
    // Unknown status bytes are ignored
    BOOST_CHECK(PendingM6idsFromEvents(Ev{MakeEvent(X, 'U'), MakeEvent(X, '?')}) == Ids{X});

    // The guard wrapper appends and reports presence
    Ids vOut{Z};
    BOOST_CHECK(!L1StillTracksWithdrawalBundle(Ev{MakeEvent(X, 'U'), MakeEvent(X, 'S')}, vOut));
    BOOST_CHECK(vOut == Ids{Z});
    BOOST_CHECK(L1StillTracksWithdrawalBundle(Ev{MakeEvent(X, 'U'), MakeEvent(X, 'S'), MakeEvent(Y, 'U')}, vOut));
    BOOST_CHECK(vOut == (Ids{Z, Y}));
}

BOOST_AUTO_TEST_CASE(l1client_bundle_guard_after_payout)
{
    // A GetTwoWayPegData history in the wire shape of l1client_parse_withdrawal_events
    // (captured): block 1 = Submitted X, block 2 = Succeeded X.
    const std::string strX = "1111111111111111111111111111111111111111111111111111111111111111";
    const std::string strY = "2222222222222222222222222222222222222222222222222222222222222222";
    auto block = [](const std::string& strHash, const std::string& strM6, const std::string& strEvent) {
        return "{\"blockHeaderInfo\": {\"blockHash\": {\"hex\": \"" + strHash + "\"}},"
               "\"blockInfo\": {\"events\": [{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"" + strM6 + "\"},"
               "\"event\": {\"" + strEvent + "\": {}}}}]}}";
    };
    const std::string h1(64, 'a'), h2(64, 'b'), h3(64, 'c');

    for (const std::string strTerminal : {"succeeded", "failed"}) {
        UniValue response(UniValue::VOBJ);
        BOOST_REQUIRE(response.read("{\"blocks\": [" + block(h1, strX, "submitted") + "," +
                                    block(h2, strX, strTerminal) + "]}"));
        std::vector<L1WithdrawalEvent> vEvents;
        BOOST_REQUIRE(ParseEnforcerWithdrawalEvents(response, vEvents));
        BOOST_REQUIRE_EQUAL(vEvents.size(), 2U);

        // The v0.2.12 predicate (every Submitted or Succeeded ever seen) still
        // reports "tracked" after the payout: it blocked every later bundle.
        size_t nOld = 0;
        for (const L1WithdrawalEvent& e : vEvents)
            if (e.status == 'U' || e.status == 'S') nOld++;
        BOOST_CHECK_EQUAL(nOld, strTerminal == std::string("succeeded") ? 2U : 1U);

        std::vector<uint256> vHash;
        BOOST_CHECK(!L1StillTracksWithdrawalBundle(vEvents, vHash));
        BOOST_CHECK(vHash.empty());

        // A third block proposes bundle Y: now exactly Y is pending
        BOOST_REQUIRE(response.read("{\"blocks\": [" + block(h1, strX, "submitted") + "," +
                                    block(h2, strX, strTerminal) + "," + block(h3, strY, "submitted") + "]}"));
        BOOST_REQUIRE(ParseEnforcerWithdrawalEvents(response, vEvents));
        vHash.clear();
        BOOST_CHECK(L1StillTracksWithdrawalBundle(vEvents, vHash));
        BOOST_REQUIRE_EQUAL(vHash.size(), 1U);
        BOOST_CHECK(vHash[0] == Uint256FromConsensusHex(strY));
    }
}

// Drive the REAL EnforcerL1Client::ListWithdrawalBundleStatus (what
// CreateWithdrawalBundleTx calls through SidechainClient) through a fake
// grpcurl that serves a canned GetChainTip + GetTwoWayPegData history.
BOOST_AUTO_TEST_CASE(l1client_bundle_guard_through_enforcer_client)
{
    const fs::path dir = fs::temp_directory_path() / fs::unique_path("fb_fake_grpcurl_%%%%%%%%");
    BOOST_REQUIRE(fs::create_directories(dir));
    const fs::path script = dir / "grpcurl";
    const fs::path peg = dir / "peg.json";
    const fs::path failflag = dir / "fail";
    {
        fs::ofstream f(script);
        f << "#!/bin/sh\n"
             "# Fake grpcurl for l1client_tests: last arg = <service>/<method>\n"
             "for last; do :; done\n"
             "D=$(dirname \"$0\")\n"
             "[ -e \"$D/fail\" ] && exit 1\n"
             "case \"$last\" in\n"
             "  */GetChainTip) echo '{\"blockHeaderInfo\": {\"blockHash\": {\"hex\": \"00000000000000000000000000000000000000000000000000000000000000ff\"}, \"height\": 100}}' ;;\n"
             "  */GetTwoWayPegData) cat \"$D/peg.json\" ;;\n"
             "  *) exit 1 ;;\n"
             "esac\n";
    }
    BOOST_REQUIRE_EQUAL(chmod(script.string().c_str(), 0700), 0);
    gArgs.ForceSetArg("-grpcurlbin", script.string());
    gArgs.ForceSetArg("-enforcertransport", "grpcurl"); // the fake is a grpcurl (v0.2.17 default: connect)

    const std::string X(64, '1'), Y(64, '2');
    auto blk = [](const std::string& strM6, const std::string& strEvent) {
        return "{\"blockInfo\": {\"events\": [{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"" + strM6 +
               "\"}, \"event\": {\"" + strEvent + "\": {}}}}]}}";
    };
    struct Scenario { const char* name; std::string json; bool fBlocks; size_t nPending; };
    const std::vector<Scenario> vScenario = {
        {"empty", "{\"blocks\": []}", false, 0},
        {"pending", "{\"blocks\": [" + blk(X, "submitted") + "]}", true, 1},
        {"succeeded", "{\"blocks\": [" + blk(X, "submitted") + "," + blk(X, "succeeded") + "]}", false, 0},
        {"failed", "{\"blocks\": [" + blk(X, "submitted") + "," + blk(X, "failed") + "]}", false, 0},
        {"paid_then_foreign_pending", "{\"blocks\": [" + blk(X, "submitted") + "," + blk(X, "succeeded") + "," + blk(Y, "submitted") + "]}", true, 1},
        {"failed_then_reproposed", "{\"blocks\": [" + blk(X, "submitted") + "," + blk(X, "failed") + "," + blk(X, "submitted") + "]}", true, 1},
    };
    L1Client& client = GetEnforcerL1Client();
    for (const Scenario& sc : vScenario) {
        {
            fs::ofstream f(peg);
            f << sc.json;
        }
        std::vector<uint256> vHash;
        const bool fBlocks = client.ListWithdrawalBundleStatus(vHash);
        BOOST_CHECK_MESSAGE(fBlocks == sc.fBlocks, "scenario " << sc.name);
        BOOST_CHECK_MESSAGE(vHash.size() == sc.nPending, "scenario " << sc.name << " pending " << vHash.size());
    }

    // Unreadable L1 (grpcurl fails): fail CLOSED - block the proposal (v0.2.12
    // reported "nothing tracked" and let the miner propose blind)
    {
        fs::ofstream f(failflag);
    }
    std::vector<uint256> vHash;
    BOOST_CHECK(client.ListWithdrawalBundleStatus(vHash));
    BOOST_CHECK(vHash.empty());

    gArgs.ForceSetArg("-grpcurlbin", "grpcurl");
    gArgs.ForceSetArg("-enforcertransport", DEFAULT_ENFORCER_TRANSPORT);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(l1client_cusf_fee_codec)
{
    // The enforcer's BlindedM6 fee output is exactly OP_RETURN PUSH8(fee) in
    // BIG-endian byte order (bip300301_enforcer lib/types.rs). 1,000,000 sats
    // = 0x00000000000f4240 big-endian.
    CScript script = EncodeWithdrawalFeesCUSF(1000000);
    BOOST_CHECK_EQUAL(HexStr(script.begin(), script.end()), "6a0800000000000f4240");

    CAmount amount = 0;
    BOOST_REQUIRE(DecodeWithdrawalFeesCUSF(script, amount));
    BOOST_CHECK_EQUAL(amount, 1000000);

    // Round-trip assorted values incl. 0 and MAX_MONEY
    for (const CAmount test : {CAmount(0), CAmount(1), CAmount(546), CAmount(MAX_MONEY)}) {
        CAmount out = -1;
        BOOST_REQUIRE(DecodeWithdrawalFeesCUSF(EncodeWithdrawalFeesCUSF(test), out));
        BOOST_CHECK_EQUAL(out, test);
    }

    // The legacy (little-endian CDataStream) encoding of the same value must
    // NOT decode as CUSF - byte order differs - and vice versa sizes match, so
    // this guards against silently accepting the wrong endianness.
    CScript scriptLegacy = EncodeWithdrawalFees(1000000);
    CAmount cross = 0;
    if (DecodeWithdrawalFeesCUSF(scriptLegacy, cross))
        BOOST_CHECK(cross != 1000000);

    // Over-MAX_MONEY big-endian value is rejected
    CScript bad;
    bad << OP_RETURN;
    bad << std::vector<unsigned char>{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(bad, cross));

    // Wrong shapes rejected
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(CScript(), cross));
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(CScript() << OP_RETURN, cross));
    BOOST_CHECK(!DecodeWithdrawalFeesCUSF(CScript() << OP_RETURN << std::vector<unsigned char>{0x01}, cross));
}

BOOST_AUTO_TEST_CASE(l1client_blinded_m6id)
{
    // The enforcer m6id is the txid of the bundle with inputs stripped. Verify
    // the txid actually changes when the dummy input is removed and that the
    // zero-input txid is stable (it is what BroadcastWithdrawalBundle sends).
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1); // chassis dummy input (null prevout)
    mtx.vin[0].scriptSig = CScript() << OP_0;
    mtx.vout.push_back(CTxOut(0, EncodeWithdrawalFeesCUSF(1000000)));
    mtx.vout.push_back(CTxOut(100000000, CScript() << OP_DUP << OP_HASH160
        << std::vector<unsigned char>(20, 0x11) << OP_EQUALVERIFY << OP_CHECKSIG));

    const uint256 hashBundle = CTransaction(mtx).GetHash();

    CMutableTransaction mtxBlind(mtx);
    mtxBlind.vin.clear();
    const uint256 m6id = CTransaction(mtxBlind).GetHash();

    BOOST_CHECK(hashBundle != m6id);
    BOOST_CHECK(!m6id.IsNull());
    // Deterministic: stripping again yields the same m6id
    BOOST_CHECK(CTransaction(mtxBlind).GetHash() == m6id);
}

// v0.2.13 item 1: locating a Succeeded M6 whatever this L1's OP_DRIVECHAIN is.
// Golden treasury bytes = bip300301_enforcer OpDrivechain::script(130):
// push_opcode(op) + push_slice([0x82]) + OP_TRUE.
static CScript ScriptHex(const std::string& h)
{
    const std::vector<unsigned char> v = ParseHex(h);
    return CScript(v.begin(), v.end());
}

BOOST_AUTO_TEST_CASE(l1client_treasury_script_shape)
{
    const unsigned int S = 130; // THIS_SIDECHAIN
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b4018251"), S), 0xb4); // OP_NOP5: BIP300, alphanet, regtest bench
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b7018251"), S), 0xb7); // OP_NOP8: betanet
    // Every upgradable NOP passes the shape prefilter (an unknown mainnet preset still works)
    for (const unsigned char op : {0xb0, 0xb3, 0xb5, 0xb6, 0xb8, 0xb9}) {
        CScript sc = ScriptHex("b7018251");
        sc[0] = op;
        BOOST_CHECK_EQUAL(TreasuryScriptOpcode(sc, S), op);
    }
    // Never CLTV / CSV, never anything else
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b1018251"), S), 0);
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b2018251"), S), 0);
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("6a018251"), S), 0);
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("61018251"), S), 0); // OP_NOP (0x61)
    // Slot mismatch
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b7018151"), S), 0);
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b7018251"), 129), 0);
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b7018251"), 2), 0);
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b7018251"), 256), 0);
    // Other encodings of "the same thing" are not the treasury script
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b701825151"), S), 0);   // trailing byte
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b70182"), S), 0);       // truncated
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b402820051"), S), 0);   // CScriptNum slot form
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(ScriptHex("b44c018251"), S), 0);   // OP_PUSHDATA1 form
    BOOST_CHECK_EQUAL(TreasuryScriptOpcode(CScript(), S), 0);

    // NOP5 no-regress: v0.2.12's exact scriptTreasury is still recognised...
    const CScript scriptV0212 = CScript() << OP_NOP5 << std::vector<unsigned char>{(unsigned char)S} << OP_TRUE;
    BOOST_CHECK_EQUAL(HexStr(scriptV0212.begin(), scriptV0212.end()), "b4018251");
    BOOST_CHECK(IsTreasuryScript(scriptV0212, S));
    BOOST_CHECK(IsTreasuryScript(CScript() << OP_NOP8 << std::vector<unsigned char>{(unsigned char)S} << OP_TRUE, S));
    // ...and the betanet treasury script is NOT the one v0.2.12 compared against (the bug)
    BOOST_CHECK(ScriptHex("b7018251") != scriptV0212);
}

// A chassis bundle in the CUSF (BlindedM6) format and the L1 M6 the enforcer
// builds from it (BlindedM6::into_m6: vout[0] := treasury change under the
// preset opcode, vin := [CTIP]).
static CMutableTransaction MakeBlindedBundle(CAmount nFee, const std::vector<CTxOut>& vPayout)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vout.push_back(CTxOut(0, EncodeWithdrawalFeesCUSF(nFee)));
    for (const CTxOut& out : vPayout)
        mtx.vout.push_back(out);
    return mtx; // vin empty: exactly what the enforcer hashes as the m6id
}

static CMutableTransaction IntoM6(const CMutableTransaction& blinded, unsigned char op, const COutPoint& ctip, CAmount nTreasury, CAmount nFee)
{
    CMutableTransaction m6(blinded);
    CAmount nPayout = 0;
    for (size_t i = 1; i < m6.vout.size(); i++)
        nPayout += m6.vout[i].nValue;
    CScript scriptTreasury;
    scriptTreasury << (opcodetype)op << std::vector<unsigned char>{130} << OP_TRUE;
    m6.vout[0] = CTxOut(nTreasury - nPayout - nFee, scriptTreasury);
    m6.vin.clear();
    m6.vin.push_back(CTxIn(ctip));
    return m6;
}

static std::vector<CTxOut> Payouts(unsigned char tag)
{
    return {CTxOut(COIN, CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag) << OP_EQUALVERIFY << OP_CHECKSIG),
            CTxOut(COIN / 2, CScript() << OP_0 << std::vector<unsigned char>(20, tag + 1))};
}

BOOST_AUTO_TEST_CASE(l1client_m6id_roundtrip)
{
    const CAmount nTreasury = 10 * COIN, nFee = 5000;
    const CMutableTransaction blinded = MakeBlindedBundle(nFee, Payouts(0x11));
    const uint256 m6idChassis = CTransaction(blinded).GetHash(); // == BlindedM6IdForBundle
    const COutPoint ctip(uint256S("aa00000000000000000000000000000000000000000000000000000000000001"), 0);

    // Recomputed from the L1 M6 under either opcode: the blinded form carries no opcode
    for (const unsigned char op : {0xb4, 0xb7}) {
        const CMutableTransaction m6 = IntoM6(blinded, op, ctip, nTreasury, nFee);
        uint256 m6id;
        BOOST_REQUIRE(ComputeM6id(m6, nTreasury, 130, m6id));
        BOOST_CHECK(m6id == m6idChassis);
        // T_{n-1} is part of the identity: a wrong previous treasury gives another fee
        BOOST_REQUIRE(ComputeM6id(m6, nTreasury + 1, 130, m6id));
        BOOST_CHECK(m6id != m6idChassis);
        // Negative fee (T_{n-1} < T_n + P_total), wrong slot: not an M6
        BOOST_CHECK(!ComputeM6id(m6, m6.vout[0].nValue, 130, m6id));
        BOOST_CHECK(!ComputeM6id(m6, nTreasury - nFee - 1, 130, m6id));
        BOOST_CHECK(!ComputeM6id(m6, nTreasury, 129, m6id));
        // Input count must be exactly one
        CMutableTransaction two(m6);
        two.vin.push_back(CTxIn(COutPoint(uint256S("bb"), 1)));
        BOOST_CHECK(!ComputeM6id(two, nTreasury, 130, m6id));
        CMutableTransaction none(m6);
        none.vin.clear();
        BOOST_CHECK(!ComputeM6id(none, nTreasury, 130, m6id));
    }
    // Zero fee is a valid M6 (enforcer compute_m6id_valid_inputs)
    const CMutableTransaction blinded0 = MakeBlindedBundle(0, Payouts(0x21));
    uint256 m6id0;
    BOOST_REQUIRE(ComputeM6id(IntoM6(blinded0, 0xb7, ctip, nTreasury, 0), nTreasury, 130, m6id0));
    BOOST_CHECK(m6id0 == CTransaction(blinded0).GetHash());
}

// v0.2.15: a REST /rest/tx/<txid>.hex body. A body that is not a tx (empty, not
// hex, odd length) is a misbehaving server: FAILED, which fails the batch closed.
// Valid hex FreeBank cannot decode is UNDECODABLE, which the M6 scan may skip.
BOOST_AUTO_TEST_CASE(l1client_classify_raw_tx_body)
{
    CMutableTransaction plain;
    plain.nVersion = 2;
    plain.vin.push_back(CTxIn(COutPoint(uint256S("f0"), 1)));
    plain.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    const std::string strV2 = EncodeHexTx(CTransaction(plain));
    std::string strTruc = strV2;
    strTruc.replace(0, 8, "03000000");

    CMutableTransaction tx;
    BOOST_CHECK(ClassifyRawTxBody("", tx) == L1TxFetch::FAILED);
    BOOST_CHECK(ClassifyRawTxBody(" \r\n", tx) == L1TxFetch::FAILED);
    BOOST_CHECK(ClassifyRawTxBody("<html>502 Bad Gateway</html>", tx) == L1TxFetch::FAILED);
    BOOST_CHECK(ClassifyRawTxBody(strV2.substr(0, strV2.size() - 1), tx) == L1TxFetch::FAILED); // odd length
    BOOST_CHECK(ClassifyRawTxBody(strV2.substr(0, strV2.size() - 2), tx) == L1TxFetch::UNDECODABLE); // truncated
    BOOST_CHECK(ClassifyRawTxBody("00", tx) == L1TxFetch::UNDECODABLE);
    BOOST_CHECK(ClassifyRawTxBody(strV2 + "\n", tx) == L1TxFetch::OK);
    BOOST_CHECK(CTransaction(tx).GetHash() == CTransaction(plain).GetHash());

    // v0.2.17 A5: an eCash v3 (TRUC) tx reads in the L1's layout, and its txid
    // as an L1 tx is the double SHA-256 of its bytes (FreeBank's own layout read
    // a replay byte after nVersion 3 and could not decode it)
    BOOST_CHECK(ClassifyRawTxBody(strTruc, tx) == L1TxFetch::OK);
    BOOST_CHECK_EQUAL(tx.nVersion, 3);
    const std::vector<unsigned char> vchTruc = ParseHex(strTruc);
    BOOST_CHECK(L1MutableTransaction(tx).GetHash() == Hash(vchTruc.begin(), vchTruc.end()));
    // ... and round-trips byte for byte, as a deposit record keeps it
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << L1MutableTransaction(tx);
    BOOST_CHECK_EQUAL(HexStr(ss.begin(), ss.end()), strTruc);
    L1MutableTransaction txBack;
    ss >> txBack;
    BOOST_CHECK(txBack.GetHash() == L1MutableTransaction(tx).GetHash());
    // A FreeBank-layout tx (a bill, v11) is not an L1 tx: its payload is left over
    CMutableTransaction bill = plain;
    bill.nVersion = TRANSACTION_BILL_VERSION;
    BOOST_CHECK(ClassifyRawTxBody(EncodeHexTx(CTransaction(bill)), tx) == L1TxFetch::UNDECODABLE);
}

// A7: the gRPC enforcer identity-pin decision logic. Kept pure (no gRPC/REST I/O)
// precisely so its classification - the part that decides whether a node REFUSES
// to start - is nailed down by vectors rather than by a live two-chain harness.
BOOST_AUTO_TEST_CASE(l1client_mainchain_blockpin_parse)
{
    // The forknet/mainnet-family L1 identity pin: "<height>:<64-hex blockhash>".
    int h = -1;
    uint256 hash;
    const std::string strFork = "00000000000000000001b4a6f9e8c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9";
    BOOST_CHECK(ParseMainchainBlockPin("963648:" + strFork, h, hash));
    BOOST_CHECK_EQUAL(h, 963648);
    BOOST_CHECK(hash == uint256S(strFork));

    // Case-insensitive hex, height 0 allowed (genesis pin)
    BOOST_CHECK(ParseMainchainBlockPin("0:" + std::string(64, 'A'), h, hash));
    BOOST_CHECK_EQUAL(h, 0);

    // Malformed: no colon, empty height, empty hash, non-numeric height,
    // negative height, short hash, long hash, non-hex hash, absurd height.
    BOOST_CHECK(!ParseMainchainBlockPin(strFork, h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin(":" + strFork, h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin("963648:", h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin("96x648:" + strFork, h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin("-1:" + strFork, h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin("963648:" + strFork.substr(0, 63), h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin("963648:" + strFork + "0", h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin("963648:" + std::string(64, 'z'), h, hash));
    BOOST_CHECK(!ParseMainchainBlockPin("9999999999:" + strFork, h, hash));
}

BOOST_AUTO_TEST_CASE(l1client_enforcer_identity_classify)
{
    const int K = 20; // stale-warn depth
    bool fStale = false;
    std::string d;

    // enforcer tip on the REST active chain -> MATCH, not stale
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(true, 100, true, 100, true, true, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_MATCH);
    BOOST_CHECK(!fStale);

    // correct but lagging within K -> still MATCH, not stale (lag-immune)
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(true, 95, true, 100, true, true, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_MATCH);
    BOOST_CHECK(!fStale);

    // correct but lagging BEYOND K -> MATCH + stale WARN (never a refuse)
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(true, 50, true, 100, true, true, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_MATCH);
    BOOST_CHECK(fStale);

    // enforcer tip NOT on the REST active chain -> MISMATCH (wrong L1 / abandoned fork).
    // This is the D-4 shape and the only path that refuses startup.
    fStale = false;
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(true, 100, true, 100, true, false, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_MISMATCH);

    // Every "couldn't obtain a reading" path is NOT-READY, never MISMATCH:
    //   enforcer tip unavailable
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(false, -1, true, 100, false, false, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_NOTREADY);
    //   enforcer at genesis only (syncing)
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(true, 0, true, 100, true, false, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_NOTREADY);
    //   REST tip height unavailable
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(true, 100, false, -1, true, false, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_NOTREADY);
    //   membership query itself failed (transport) -> NOT-READY even though a
    //   false fEnfTipOnRestChain is present; couldn't-check must not refuse.
    BOOST_CHECK_EQUAL((int)ClassifyEnforcerIdentity(true, 100, true, 100, false, false, K, &fStale, d),
                      (int)ENFORCER_IDENTITY_NOTREADY);
}

BOOST_AUTO_TEST_CASE(l1client_grpcurl_command_quotes_binary_path)
{
    // BitWindow's macOS binaries dir contains a space; the shell must see one word.
    const std::string cmd = BuildGrpcurlCommand("/Users/me/Library/Application Support/bitwindow/assets/bin/grpcurl",
        "{}", "127.0.0.1:50051", "cusf.mainchain.v1.ValidatorService", "GetChainTip");
    BOOST_CHECK_EQUAL(cmd.find("\"/Users/me/Library/Application Support/bitwindow/assets/bin/grpcurl\" -plaintext"), 0U);
    BOOST_CHECK(cmd.find(" -plaintext -max-time 15 -d '{}' 127.0.0.1:50051 cusf.mainchain.v1.ValidatorService/GetChainTip 2>/dev/null") != std::string::npos);
    // The plain default keeps working
    BOOST_CHECK_EQUAL(BuildGrpcurlCommand("grpcurl", "{}", "127.0.0.1:50051", "s", "m").find("\"grpcurl\" -plaintext"), 0U);
    // A path that cannot be quoted safely is refused
    BOOST_CHECK(BuildGrpcurlCommand("/tmp/a\"b/grpcurl", "{}", "127.0.0.1:50051", "s", "m").empty());
    // fStderr merges stderr into the output instead
    BOOST_CHECK(BuildGrpcurlCommand("grpcurl", "{}", "127.0.0.1:50051", "s", "m", true).find("s/m 2>&1") != std::string::npos);
    // A per-call budget other than the default 15 s
    BOOST_CHECK(BuildGrpcurlCommand("grpcurl", "{}", "127.0.0.1:50051", "s", "m", false, 60).find(" -max-time 60 -d ") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(l1client_grpcurl_failure_classify)
{
    // grpcurl v1.9.1 against enforcer 73d239a (2026-09-26): a server status exits 64 + code
    BOOST_CHECK(ClassifyGrpcurlFailure(0, "") == GrpcurlFailure::NONE);
    BOOST_CHECK(ClassifyGrpcurlFailure(76, "ERROR:\n  Code: Unimplemented\n") == GrpcurlFailure::UNIMPLEMENTED);
    BOOST_CHECK(ClassifyGrpcurlFailure(1, "Error invoking method \"x\": service \"cusf.mainchain.v1.BlockProducerService\" does not include a method named \"ProposeWithdrawalBundle\"") == GrpcurlFailure::UNIMPLEMENTED);
    BOOST_CHECK(ClassifyGrpcurlFailure(1, "server does not expose service \"cusf.mainchain.v1.WalletService\"") == GrpcurlFailure::UNIMPLEMENTED);
    // Transient: never flips the withdrawal-bundle method
    BOOST_CHECK(ClassifyGrpcurlFailure(78, "ERROR:\n  Code: Unavailable\n") == GrpcurlFailure::OTHER);
    BOOST_CHECK(ClassifyGrpcurlFailure(1, "Failed to dial target host \"127.0.0.1:1\": connection refused") == GrpcurlFailure::OTHER);
    BOOST_CHECK(ClassifyGrpcurlFailure(-1, "") == GrpcurlFailure::OTHER);
}

BOOST_AUTO_TEST_CASE(l1client_bmm_request_not_sent)
{
    // Definite: the enforcer refused before building the tx, or never got the call
    BOOST_CHECK(GrpcurlBMMRequestNotSent(67, "ERROR:\n  Code: InvalidArgument\n  Message: invalid prev_bytes"));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(73, "ERROR:\n  Code: FailedPrecondition\n  Message: sidechain is not active"));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(66, "ERROR:\n  Code: Unknown\n  Message: error creating BMM request: failed to build BMM tx: Insufficient funds"));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(66, "ERROR:\n  Code: Unknown\n  Message: error creating BMM request: failed to sign BMM tx: x"));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(76, "ERROR:\n  Code: Unimplemented\n"));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(1, "server does not expose service \"cusf.mainchain.v1.WalletService\""));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(1, "Failed to dial target host \"127.0.0.1:1\": dial tcp 127.0.0.1:1: connect: connection refused"));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(127, "sh: 1: grpcurl: not found"));
    // Possibly sent: the enforcer broadcasts before it replies
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(0, ""));
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(-1, ""));
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(68, "ERROR:\n  Code: DeadlineExceeded\n"));
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(66, "ERROR:\n  Code: Unknown\n  Message: error creating BMM request: failed to broadcast BMM request tx via RPC: x"));
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(66, "ERROR:\n  Code: Unknown\n  Message: error creating BMM request: broadcast deposit transaction failed: ab"));
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(77, "ERROR:\n  Code: Internal\n"));
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(78, "ERROR:\n  Code: Unavailable\n"));
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(1, "Error invoking method \"x\": rpc error"));
}

// v0.2.17: without -grpcurlbin, grpcurl is looked for in PATH, then next to
// freebankd, then /opt/homebrew/bin and /usr/local/bin (a macOS GUI launch has
// PATH=/usr/bin:/bin:/usr/sbin:/sbin only).
BOOST_AUTO_TEST_CASE(l1client_find_grpcurl_order)
{
    std::set<std::string> setExec;
    auto isExec = [&](const std::string& strPath) { return setExec.count(strPath) > 0; };
    const std::string strMacPath = "/usr/bin:/bin:/usr/sbin:/sbin";
    const std::string strExeDir = "/Applications/BitWindow.app/Contents/MacOS";

    // Nowhere: not found, and the bare name is what would run
    GrpcurlLocation loc = FindGrpcurl(strMacPath, strExeDir, isExec);
    BOOST_CHECK(!loc.fFound);
    BOOST_CHECK_EQUAL(loc.strPath, "grpcurl");
    BOOST_CHECK_EQUAL(loc.strSource, "");

    // Homebrew on Intel, then Apple silicon wins over it
    setExec.insert("/usr/local/bin/grpcurl");
    loc = FindGrpcurl(strMacPath, strExeDir, isExec);
    BOOST_CHECK(loc.fFound);
    BOOST_CHECK_EQUAL(loc.strPath, "/usr/local/bin/grpcurl");
    BOOST_CHECK_EQUAL(loc.strSource, "/usr/local/bin");
    setExec.insert("/opt/homebrew/bin/grpcurl");
    BOOST_CHECK_EQUAL(FindGrpcurl(strMacPath, strExeDir, isExec).strPath, "/opt/homebrew/bin/grpcurl");

    // Next to freebankd beats both
    setExec.insert(strExeDir + "/grpcurl");
    loc = FindGrpcurl(strMacPath, strExeDir, isExec);
    BOOST_CHECK_EQUAL(loc.strPath, strExeDir + "/grpcurl");
    BOOST_CHECK_EQUAL(loc.strSource, "next to freebankd");

    // PATH beats everything, in PATH order; empty entries and a trailing slash are fine
    setExec.insert("/home/u/go/bin/grpcurl");
    setExec.insert("/usr/bin/grpcurl");
    loc = FindGrpcurl("::/home/u/go/bin/:/usr/bin", strExeDir, isExec);
    BOOST_CHECK_EQUAL(loc.strPath, "/home/u/go/bin/grpcurl");
    BOOST_CHECK_EQUAL(loc.strSource, "PATH");
    BOOST_CHECK_EQUAL(FindGrpcurl("/usr/bin:/home/u/go/bin", strExeDir, isExec).strPath, "/usr/bin/grpcurl");

    // No PATH and no executable directory: the fixed directories still count
    BOOST_CHECK_EQUAL(FindGrpcurl("", "", isExec).strPath, "/opt/homebrew/bin/grpcurl");
}

// -grpcurlbin is used as given; "found" says whether it exists.
BOOST_AUTO_TEST_CASE(l1client_grpcurlbin_override)
{
    gArgs.ForceSetArg("-grpcurlbin", "/nonexistent/dir/grpcurl");
    GrpcurlLocation loc = GetGrpcurlLocation();
    BOOST_CHECK(!loc.fFound);
    BOOST_CHECK_EQUAL(loc.strPath, "/nonexistent/dir/grpcurl");
    BOOST_CHECK_EQUAL(loc.strSource, "-grpcurlbin");

    gArgs.ForceSetArg("-grpcurlbin", "/bin/sh");
    loc = GetGrpcurlLocation();
    BOOST_CHECK(loc.fFound);
    BOOST_CHECK_EQUAL(loc.strPath, "/bin/sh");

    gArgs.ForceSetArg("-grpcurlbin", "sh"); // a bare name is looked up in PATH
    BOOST_CHECK(GetGrpcurlLocation().fFound);
    gArgs.ForceSetArg("-grpcurlbin", "no-such-grpcurl-binary");
    BOOST_CHECK(!GetGrpcurlLocation().fFound);

    gArgs.ForceSetArg("-grpcurlbin", "grpcurl"); // as l1client_bundle_guard_through_enforcer_client leaves it
}


// v0.2.17 D3: the strict peg-events parser. Shapes from validator.proto at the
// enforcer we run (73d239a): every field is a wrapper, so zero values and
// empty strings are present; an empty list is omitted.
static L1PegEvents ParsePegOK(const std::string& strJson)
{
    UniValue v;
    BOOST_REQUIRE(v.read(strJson));
    L1PegEvents events;
    BOOST_CHECK_MESSAGE(ParsePegEvents(v, events), "should parse: " << strJson);
    return events;
}
static void ParsePegFails(const std::string& strJson)
{
    UniValue v;
    BOOST_REQUIRE(v.read(strJson));
    L1PegEvents events;
    BOOST_CHECK_MESSAGE(!ParsePegEvents(v, events), "should not parse: " << strJson);
    BOOST_CHECK(events.vDeposit.empty() && events.vWithdrawal.empty());
}

BOOST_AUTO_TEST_CASE(l1client_parse_peg_events)
{
    const std::string H1(64, 'a'), H2(64, 'b'), TX(64, 'c'), M6 = std::string(62, '0') + "01";
    const std::string BLOCK = "\"blockHeaderInfo\": {\"blockHash\": {\"hex\": \"" + H1 + "\"}}";
    const std::string DEP0 = "{\"deposit\": {\"sequenceNumber\": \"0\", \"outpoint\": {\"txid\": {\"hex\": \"" + TX +
        "\"}, \"vout\": 0}, \"output\": {\"address\": {\"hex\": \"616263\"}, \"valueSats\": \"100000\"}}}";

    // Nothing: an empty reply, no blocks, a block with only a BMM commitment
    BOOST_CHECK(ParsePegOK("{}").vDeposit.empty());
    BOOST_CHECK(ParsePegOK("{\"blocks\": []}").vDeposit.empty());
    BOOST_CHECK(ParsePegOK("{\"blocks\": [{" + BLOCK + ", \"blockInfo\": {\"bmmCommitment\": {\"hex\": \"" + H2 + "\"}}}]}").vDeposit.empty());

    // The first deposit: running number 0, output 0, every field read
    {
        const L1PegEvents ev = ParsePegOK("{\"blocks\": [{" + BLOCK + ", \"blockInfo\": {\"events\": [" + DEP0 + "]}}]}");
        BOOST_REQUIRE_EQUAL(ev.vDeposit.size(), 1U);
        const L1DepositEvent& d = ev.vDeposit[0];
        BOOST_CHECK(d.hashMainBlock == uint256S(H1));
        BOOST_CHECK(d.outpoint == COutPoint(uint256S(TX), 0));
        BOOST_CHECK_EQUAL(d.nSequence, 0U);
        BOOST_CHECK_EQUAL(d.nValue, 100000);
        BOOST_CHECK(std::string(d.vchAddress.begin(), d.vchAddress.end()) == "abc");
    }
    // An empty address, three ways; numbers as JSON numbers too
    for (const std::string& strAddr : {std::string("\"address\": {\"hex\": \"\"}, "), std::string("\"address\": {}, "), std::string("")}) {
        const L1PegEvents ev = ParsePegOK("{\"blocks\": [{" + BLOCK + ", \"blockInfo\": {\"events\": [{\"deposit\": {\"sequenceNumber\": 7, "
            "\"outpoint\": {\"txid\": {\"hex\": \"" + TX + "\"}, \"vout\": 2}, \"output\": {" + strAddr + "\"valueSats\": 5}}}]}}]}");
        BOOST_REQUIRE_EQUAL(ev.vDeposit.size(), 1U);
        BOOST_CHECK(ev.vDeposit[0].vchAddress.empty());
        BOOST_CHECK_EQUAL(ev.vDeposit[0].nSequence, 7U);
        BOOST_CHECK_EQUAL(ev.vDeposit[0].outpoint.n, 2U);
    }
    // Withdrawal-bundle events, in order, with a deposit between them
    {
        const std::string WB = "{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"" + M6 + "\"}, \"event\": {\"";
        const L1PegEvents ev = ParsePegOK("{\"blocks\": [{" + BLOCK + ", \"blockInfo\": {\"events\": [" + WB + "submitted\": {}}}}, " + DEP0 +
            "]}}, {\"blockHeaderInfo\": {\"blockHash\": {\"hex\": \"" + H2 + "\"}}, \"blockInfo\": {\"events\": [" + WB +
            "failed\": {}}}}, " + WB + "succeeded\": {\"sequenceNumber\": \"1\", \"transaction\": {\"hex\": \"00\"}}}}}]}}]}");
        BOOST_REQUIRE_EQUAL(ev.vWithdrawal.size(), 3U);
        BOOST_CHECK_EQUAL(ev.vWithdrawal[0].status, 'U');
        BOOST_CHECK(ev.vWithdrawal[0].hashMainBlock == uint256S(H1));
        BOOST_CHECK_EQUAL(ev.vWithdrawal[1].status, 'F');
        BOOST_CHECK_EQUAL(ev.vWithdrawal[2].status, 'S');
        BOOST_CHECK(ev.vWithdrawal[2].hashMainBlock == uint256S(H2));
        // D7: a "paid" event's running number and M6
        BOOST_CHECK(ev.vWithdrawal[2].fHaveSequence);
        BOOST_CHECK_EQUAL(ev.vWithdrawal[2].nSequence, 1U);
        BOOST_CHECK(ev.vWithdrawal[2].vchTx == std::vector<unsigned char>{0x00});
        BOOST_CHECK(!ev.vWithdrawal[1].fHaveSequence && ev.vWithdrawal[1].vchTx.empty());
        BOOST_CHECK(ev.vWithdrawal[0].m6id == Uint256FromConsensusHex(M6));
        BOOST_CHECK_EQUAL(ev.vDeposit.size(), 1U);
    }

    // Anything not fully read fails the whole reply
    auto One = [&](const std::string& strEvent) { return "{\"blocks\": [{" + BLOCK + ", \"blockInfo\": {\"events\": [" + DEP0 + ", " + strEvent + "]}}]}"; };
    ParsePegFails("[]");
    ParsePegFails("{\"blocks\": {}}");
    ParsePegFails("{\"blocks\": [{\"blockInfo\": {}}]}");                                  // no block hash
    ParsePegFails("{\"blocks\": [{" + BLOCK + "}]}");                                      // no blockInfo
    ParsePegFails("{\"blocks\": [{" + BLOCK + ", \"blockInfo\": {\"events\": {}}}]}");
    ParsePegFails(One("{}"));                                                                // an event kind we do not know
    ParsePegFails(One("{\"sidechainProposal\": {}}"));
    ParsePegFails(One("{\"deposit\": {\"outpoint\": {\"txid\": {\"hex\": \"" + TX + "\"}, \"vout\": 0}, \"output\": {\"valueSats\": \"1\"}}}"));  // no running number
    ParsePegFails(One("{\"deposit\": {\"sequenceNumber\": \"1\", \"outpoint\": {\"txid\": {\"hex\": \"" + TX + "\"}, \"vout\": 0}, \"output\": {}}}"));  // no amount
    ParsePegFails(One("{\"deposit\": {\"sequenceNumber\": \"1\", \"outpoint\": {\"txid\": {\"hex\": \"" + TX + "\"}}, \"output\": {\"valueSats\": \"1\"}}}"));  // no output number
    ParsePegFails(One("{\"deposit\": {\"sequenceNumber\": \"1\", \"outpoint\": {\"txid\": {\"hex\": \"abcd\"}, \"vout\": 0}, \"output\": {\"valueSats\": \"1\"}}}"));  // short txid
    ParsePegFails(One("{\"deposit\": {\"sequenceNumber\": \"-1\", \"outpoint\": {\"txid\": {\"hex\": \"" + TX + "\"}, \"vout\": 0}, \"output\": {\"valueSats\": \"1\"}}}"));
    ParsePegFails(One("{\"deposit\": {\"sequenceNumber\": \"1\", \"outpoint\": {\"txid\": {\"hex\": \"" + TX + "\"}, \"vout\": 0}, \"output\": {\"address\": {\"hex\": \"zz\"}, \"valueSats\": \"1\"}}}"));
    ParsePegFails(One("{\"deposit\": {\"sequenceNumber\": \"1\", \"outpoint\": {\"txid\": {\"hex\": \"" + TX + "\"}, \"vout\": 0}, \"output\": {\"valueSats\": \"2100000000000001\"}}}"));
    ParsePegFails(One("{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"" + M6 + "\"}, \"event\": {}}}"));
    ParsePegFails(One("{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"" + M6 + "\"}, \"event\": {\"failed\": {}, \"succeeded\": {}}}}"));
    ParsePegFails(One("{\"withdrawalBundle\": {\"event\": {\"failed\": {}}}}"));
    ParsePegFails(One(DEP0.substr(0, DEP0.size() - 1) + ", \"withdrawalBundle\": {}}"));   // both kinds in one event
}

BOOST_AUTO_TEST_CASE(l1client_classify_peg_events_error)
{
    const std::string S(64, 'a'), E(64, 'b');
    // The enforcer's error texts (lib/validator/dbs/block_hashes.rs), as the
    // Connect transport and grpcurl print them
    BOOST_CHECK(ClassifyPegEventsError("ERROR:\n  Code: Internal\n  Message: Start block `" + S +
        "` is not an ancestor of end block `" + E + "`\n") == L1Answer::NO);
    BOOST_CHECK(ClassifyPegEventsError("ERROR:\n  Code: Internal\n  Message: End block `" + E + "` not found\n") == L1Answer::UNKNOWN);
    BOOST_CHECK(ClassifyPegEventsError("ERROR:\n  Code: Internal\n  Message: Previous block `" + S + "` not found for block `" + E + "`\n") == L1Answer::UNKNOWN);
    BOOST_CHECK(ClassifyPegEventsError("ERROR:\n  Code: DeadlineExceeded\n  Message: timed out waiting for the reply\n") == L1Answer::UNKNOWN);
    BOOST_CHECK(ClassifyPegEventsError("") == L1Answer::UNKNOWN);
}


// v0.2.17 D2: the enforcer's BIP300 settings against the pinned fork.
BOOST_AUTO_TEST_CASE(l1client_enforcer_settings)
{
    auto Settings = [](const std::string& strJson) {
        UniValue v;
        BOOST_REQUIRE(v.read(strJson));
        EnforcerSettings settings;
        BOOST_REQUIRE_MESSAGE(ParseEnforcerChainInfo(v, settings), strJson);
        return settings;
    };
    const std::string BETA = "{\"network\": \"NETWORK_MAINNET\", \"bip300Constants\": {\"withdrawalBundleMaxAge\": 26300, "
        "\"withdrawalBundleInclusionThreshold\": 13150, \"usedSidechainSlotProposalMaxAge\": 26300, "
        "\"usedSidechainSlotActivationThreshold\": 13150, \"unusedSidechainSlotProposalMaxAge\": 2016, "
        "\"unusedSidechainSlotActivationThreshold\": 1008, \"activationHeight\": 967680}}";
    BOOST_CHECK_EQUAL(CompareEnforcerSettings(967680, Settings(BETA)), "");
    // The mainnet preset's 51% slot threshold (1815) on beta: not beta's enforcer
    std::string strWrong = BETA;
    strWrong.replace(strWrong.find("1008"), 4, "1815");
    BOOST_CHECK(CompareEnforcerSettings(967680, Settings(strWrong)).find("thresholds") != std::string::npos);
    // Beta's enforcer against an alphanet pin, and one with no activation height (omitted = 0)
    BOOST_CHECK(CompareEnforcerSettings(963648, Settings(BETA)).find("activation height is 967680") != std::string::npos);
    BOOST_CHECK(!CompareEnforcerSettings(967680, Settings("{\"bip300Constants\": {\"withdrawalBundleMaxAge\": 10}}")).empty());
    // Another fork: the activation height only
    BOOST_CHECK_EQUAL(CompareEnforcerSettings(973728, Settings("{\"bip300Constants\": {\"activationHeight\": 973728}}")), "");
    BOOST_CHECK(!CompareEnforcerSettings(973728, Settings("{\"bip300Constants\": {\"activationHeight\": 967680}}")).empty());
    // An enforcer with no preset for an unknown fork (eCash mainnet today) reports 0: accepted there, not on beta
    BOOST_CHECK_EQUAL(CompareEnforcerSettings(973728, Settings("{\"bip300Constants\": {\"withdrawalBundleMaxAge\": 26300}}")), "");
    BOOST_CHECK(!CompareEnforcerSettings(967680, Settings("{\"bip300Constants\": {\"withdrawalBundleMaxAge\": 26300}}")).empty());
    // Not a reply we can read
    UniValue v;
    EnforcerSettings settings;
    BOOST_REQUIRE(v.read("{\"network\": \"NETWORK_MAINNET\"}"));
    BOOST_CHECK(!ParseEnforcerChainInfo(v, settings));
    BOOST_REQUIRE(v.read("{\"bip300Constants\": {\"activationHeight\": \"x\"}}"));
    BOOST_CHECK(!ParseEnforcerChainInfo(v, settings));
}

// v0.2.17 D6: which enforcer / eCash node addresses count as local or private.
BOOST_AUTO_TEST_CASE(l1client_l1_address_local_or_private)
{
    for (const std::string& str : {"127.0.0.1:50051", "localhost:38332", "10.1.2.3:50051", "192.168.1.5:8332",
                                   "172.16.0.9:1", "100.76.210.26:50051", "[::1]:50051", "[fd00::5]:8332"})
        BOOST_CHECK_MESSAGE(IsLocalOrPrivateL1Address(str), str);
    for (const std::string& str : {"167.172.84.34:50051", "8.8.8.8:8332", "[2001:db8::1]:50051", "enforcer.example.com:50051"})
        BOOST_CHECK_MESSAGE(!IsLocalOrPrivateL1Address(str), str);
}


// v0.2.17 D3: a real reply. GetTwoWayPegData from the betanet enforcer
// (73d239a) on the snapshot droplet, 2026-09-29, range (fork block 967680,
// 970647], trimmed to its first block (a BMM commitment only) and the three
// blocks with slot-130 events: beta's three deposits.
BOOST_AUTO_TEST_CASE(l1client_parse_peg_events_captured_beta)
{
    const std::string strReply = R"JSON({"blocks":[{"blockHeaderInfo":{"blockHash":{"hex":"0000000000000000831f6494abeef0e985a284819447495c427a588a811509df"},"prevBlockHash":{"hex":"00000000000000003d9abf5fe2d19950e2c3d3051377755aa891d2b40868018e"},"height":969849,"work":{"hex":"3edea07a4bab6cee000000000000000000000000000000000000000000000000"},"timestamp":"1789932999"},"blockInfo":{"bmmCommitment":{"hex":"973da6f3eabd7a735a8f5ed5b442fffe499db8a40e8f3e30aba66b150f2a787b"}}},{"blockHeaderInfo":{"blockHash":{"hex":"0000000000000000a54bce2e596fc6a2cfc5ab0aff39b0c94fe2ca9d797d31c1"},"prevBlockHash":{"hex":"000000000000000099be0a8119781fbfff6930059b1583099c87e308c45abc2e"},"height":970432,"work":{"hex":"3edea07a4bab6cee000000000000000000000000000000000000000000000000"},"timestamp":"1790466202"},"blockInfo":{"bmmCommitment":{"hex":"712a2791fa5c26cca46c6aa28d3ca1a2a5f30296acf225f063ddff7885f267c2"},"events":[{"deposit":{"sequenceNumber":"0","outpoint":{"txid":{"hex":"9cc705f3a7ff0f7e84d255ced84dc40c157afce519f5d95a40910f20af66ccbe"},"vout":0},"output":{"address":{"hex":"733133305f5843413676357379704d434c384d564b314c75646d36377a537141685736666e476e5f653863633663"},"valueSats":"1000000000"}}}]}},{"blockHeaderInfo":{"blockHash":{"hex":"00000000000000001fb497b3875eb39aaba739094166023b259138a4ce13108f"},"prevBlockHash":{"hex":"00000000000000001735ec707372e9a47463cb8c711540c2b034779aa595a077"},"height":970436,"work":{"hex":"3edea07a4bab6cee000000000000000000000000000000000000000000000000"},"timestamp":"1790468633"},"blockInfo":{"bmmCommitment":{"hex":"d165888a17f6cdeceb07972938a6418785ed4e6adffc243ccae087452fbd0f0a"},"events":[{"deposit":{"sequenceNumber":"1","outpoint":{"txid":{"hex":"8c7832f624f3f9f57c80731a431d44353e1879b4af787452e3e9437129dcc645"},"vout":0},"output":{"address":{"hex":"5859597664543368434a4742385639505664675978675a4e357a48727a6944343661"},"valueSats":"500000000"}}}]}},{"blockHeaderInfo":{"blockHash":{"hex":"00000000000000000e5ebb5a9df7128d4daca567d545ea04ed2aa5df61805391"},"prevBlockHash":{"hex":"00000000000000008413d40a3107774550fc45d2ff2f2dc06747d433f0c48a0f"},"height":970439,"work":{"hex":"3edea07a4bab6cee000000000000000000000000000000000000000000000000"},"timestamp":"1790472240"},"blockInfo":{"bmmCommitment":{"hex":"1bf57122594f7218ba59ffca439f103f07525061a5c8c04528e3c71def01edfa"},"events":[{"deposit":{"sequenceNumber":"2","outpoint":{"txid":{"hex":"fb65cde5f4166a9e0c2556841205e9290b1f2df0868ed0824c6f5951dfc62895"},"vout":0},"output":{"address":{"hex":"58434d43544c415569537a48586650666e5851614253577638737337687279553850"},"valueSats":"500000000"}}}]}}]})JSON";
    UniValue v;
    BOOST_REQUIRE(v.read(strReply));
    L1PegEvents events;
    BOOST_REQUIRE(ParsePegEvents(v, events));
    BOOST_REQUIRE_EQUAL(events.vDeposit.size(), 3U);
    BOOST_CHECK(events.vWithdrawal.empty());
    for (size_t i = 0; i < 3; i++) {
        BOOST_CHECK_EQUAL(events.vDeposit[i].nSequence, i);
        BOOST_CHECK_EQUAL(events.vDeposit[i].outpoint.n, 0U);
        BOOST_CHECK(!events.vDeposit[i].vchAddress.empty());
    }
    BOOST_CHECK(events.vDeposit[0].outpoint.hash == uint256S("9cc705f3a7ff0f7e84d255ced84dc40c157afce519f5d95a40910f20af66ccbe"));
    BOOST_CHECK_EQUAL(events.vDeposit[0].nValue, 1000000000);
    BOOST_CHECK_EQUAL(std::string(events.vDeposit[0].vchAddress.begin(), events.vDeposit[0].vchAddress.begin() + 5), "s130_");
    BOOST_CHECK_EQUAL(events.vDeposit[2].nValue, 500000000);
}


// v0.2.17 A5: a deposit record's L1 tx. For v1 and v2 the L1 layout is byte for
// byte FreeBank's (so beta's existing deposit records read as before); a v3 tx
// round-trips inside the record with its L1 txid.
BOOST_AUTO_TEST_CASE(l1client_deposit_record_l1_tx)
{
    for (const int nVersion : {1, 2}) {
        CMutableTransaction mtx;
        mtx.nVersion = nVersion;
        mtx.vin.push_back(CTxIn(COutPoint(uint256S("a5"), 3)));
        mtx.vout.push_back(CTxOut(7 * COIN, ScriptHex("b7018251")));
        CDataStream ssOld(SER_NETWORK, PROTOCOL_VERSION), ssNew(SER_NETWORK, PROTOCOL_VERSION);
        ssOld << mtx;
        ssNew << L1MutableTransaction(mtx);
        BOOST_CHECK_EQUAL(HexStr(ssOld.begin(), ssOld.end()), HexStr(ssNew.begin(), ssNew.end()));
        BOOST_CHECK(L1MutableTransaction(mtx).GetHash() == mtx.GetHash());
    }

    SidechainDeposit d;
    d.nSidechain = 130;
    d.strDest = "s130_dest";
    d.dtx.nVersion = 3;
    d.dtx.vin.push_back(CTxIn(COutPoint(uint256S("a6"), 0)));
    d.dtx.vout.push_back(CTxOut(5 * COIN, ScriptHex("b7018251")));
    d.nBurnIndex = 0;
    d.nTx = 4;
    CDataStream ssDtx(SER_NETWORK, PROTOCOL_VERSION);
    ssDtx << d.dtx;
    const std::string strDtx = HexStr(ssDtx.begin(), ssDtx.end());
    BOOST_CHECK_EQUAL(strDtx.substr(0, 10), "0300000001"); // nVersion 3, then one input: no replay byte
    const std::vector<unsigned char> vchDtx = ParseHex(strDtx);
    BOOST_CHECK(d.dtx.GetHash() == Hash(vchDtx.begin(), vchDtx.end()));

    const CScript script = d.GetScript();
    std::vector<unsigned char> vch;
    BOOST_REQUIRE(script.IsSidechainObj(vch));
    std::unique_ptr<SidechainObj> obj(ParseSidechainObj(vch));
    BOOST_REQUIRE(obj && obj->sidechainop == DB_SIDECHAIN_DEPOSIT_OP);
    const SidechainDeposit* back = static_cast<const SidechainDeposit*>(obj.get());
    BOOST_CHECK_EQUAL(back->dtx.nVersion, 3);
    BOOST_CHECK(back->dtx.GetHash() == d.dtx.GetHash());
    BOOST_CHECK(back->GetID() == d.GetID());
}


// v0.2.17: a deposit's tx is read from its L1 block, not /rest/tx (a node
// started from a snapshot has no tx index for recent blocks for weeks).
BOOST_AUTO_TEST_CASE(l1client_find_l1_tx_in_block)
{
    std::vector<L1MutableTransaction> vtx(3);
    for (size_t i = 0; i < vtx.size(); i++) {
        vtx[i].nVersion = i == 2 ? 3 : 2; // the last one an eCash v3 tx
        vtx[i].vin.push_back(CTxIn(COutPoint(ArithToUint256(arith_uint256(0xb10 + i)), 0)));
        vtx[i].vout.push_back(CTxOut((i + 1) * COIN, ScriptHex("b7018251")));
    }
    std::vector<unsigned char> vchBlock(80, 0x11);        // an 80-byte header
    CDataStream ssTxs(SER_NETWORK, PROTOCOL_VERSION);
    WriteCompactSize(ssTxs, vtx.size());
    for (const L1MutableTransaction& tx : vtx)
        ssTxs << tx;
    vchBlock.insert(vchBlock.end(), ssTxs.begin(), ssTxs.end());

    CMutableTransaction tx;
    int nTx = -1;
    BOOST_CHECK(FindL1TxInBlock(vchBlock, vtx[2].GetHash(), tx, nTx) == L1TxFetch::OK);
    BOOST_CHECK_EQUAL(nTx, 2);
    BOOST_CHECK_EQUAL(tx.nVersion, 3);
    BOOST_CHECK(L1MutableTransaction(tx).GetHash() == vtx[2].GetHash());
    BOOST_CHECK(FindL1TxInBlock(vchBlock, vtx[0].GetHash(), tx, nTx) == L1TxFetch::OK);
    BOOST_CHECK_EQUAL(nTx, 0);
    BOOST_CHECK(FindL1TxInBlock(vchBlock, uint256S("99"), tx, nTx) == L1TxFetch::FAILED);
    BOOST_CHECK_EQUAL(nTx, -1);
    vchBlock.resize(vchBlock.size() - 5);
    BOOST_CHECK(FindL1TxInBlock(vchBlock, vtx[2].GetHash(), tx, nTx) == L1TxFetch::UNDECODABLE);
}

BOOST_AUTO_TEST_CASE(v0225_parse_bmm_commitments_batch)
{
    // v0.2.25: a reply asked with max_ancestors: the block's own commitment,
    // then its ancestors newest first. ConsensusHex as in the single reply.
    std::vector<std::pair<bool, uint256>> v;
    UniValue batch(UniValue::VOBJ);
    BOOST_REQUIRE(batch.read(
        "{\"commitment\": {\"commitment\": {\"hex\": \"0100000000000000000000000000000000000000000000000000000000000000\"},"
        " \"ancestorCommitments\": [{}, {\"commitment\": {\"hex\": \"0200000000000000000000000000000000000000000000000000000000000000\"}}, {}]}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitments(batch, v));
    BOOST_REQUIRE_EQUAL(v.size(), 4U);
    BOOST_CHECK(v[0].first && v[0].second == uint256S("01"));
    BOOST_CHECK(!v[1].first && v[1].second.IsNull());
    BOOST_CHECK(v[2].first && v[2].second == uint256S("02"));
    BOOST_CHECK(!v[3].first);

    // No ancestors asked: the block alone, as the single reply
    UniValue single(UniValue::VOBJ);
    BOOST_REQUIRE(single.read("{\"commitment\": {}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitments(single, v));
    BOOST_REQUIRE_EQUAL(v.size(), 1U);
    BOOST_CHECK(!v[0].first);

    // An unreadable ancestor ends the list before it (the ones after are
    // asked one at a time); an unreadable first entry, or an unknown block,
    // is no answer at all
    UniValue badAncestor(UniValue::VOBJ);
    BOOST_REQUIRE(badAncestor.read("{\"commitment\": {\"ancestorCommitments\": [{}, {\"commitment\": {\"hex\": \"zz\"}}, {}]}}"));
    BOOST_REQUIRE(ParseEnforcerBmmCommitments(badAncestor, v));
    BOOST_CHECK_EQUAL(v.size(), 2U);
    for (const char* bad : {"{\"commitment\": {\"commitment\": {\"hex\": \"0100\"}}}",
                            "{\"blockNotFound\": {\"blockHash\": {\"hex\": \"00\"}}}",
                            "{\"commitment\": {\"ancestorCommitments\": 3}}",
                            "{\"unexpected\": 1}"}) {
        UniValue reply(UniValue::VOBJ);
        BOOST_REQUIRE(reply.read(bad));
        BOOST_CHECK_MESSAGE(!ParseEnforcerBmmCommitments(reply, v), bad);
    }
}

BOOST_AUTO_TEST_CASE(v0225_chain_name_from_enforcer)
{
    // v0.2.25: the enforcer's network, for -mainchainchain and the L1 family
    // when no REST endpoint is set. proto3 JSON writes the enum's name.
    const std::pair<const char*, const char*> cases[] = {
        {"{\"network\": \"NETWORK_MAINNET\"}", "main"},
        {"{\"network\": \"NETWORK_TESTNET\"}", "test"},
        {"{\"network\": \"NETWORK_SIGNET\"}", "signet"},
        {"{\"network\": \"NETWORK_REGTEST\"}", "regtest"},
        {"{\"network\": 2}", "main"},
        {"{\"network\": 3}", "regtest"},
        {"{\"network\": \"NETWORK_UNKNOWN\"}", ""},
        {"{\"network\": 1}", ""},
        {"{\"bip300Constants\": {}}", ""},
    };
    for (const auto& c : cases) {
        UniValue reply(UniValue::VOBJ);
        BOOST_REQUIRE(reply.read(c.first));
        BOOST_CHECK_MESSAGE(ChainNameFromEnforcerChainInfo(reply) == c.second, c.first);
    }
    BOOST_CHECK(ChainNameFromEnforcerChainInfo(UniValue(UniValue::VARR)).empty());
}

BOOST_AUTO_TEST_SUITE_END()

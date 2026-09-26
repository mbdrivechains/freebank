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

#include <boost/test/unit_test.hpp>

#include <sys/stat.h>

// The canned JSON in this suite is captured from a live bip300301_enforcer
// v0.3.4 ValidatorService via grpcurl (bench, 2026-07-08). If the enforcer
// wire format changes these fixtures must be re-captured, not hand-edited.

BOOST_FIXTURE_TEST_SUITE(l1client_tests, BasicTestingSetup)

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

BOOST_AUTO_TEST_CASE(l1client_locate_m6)
{
    const CAmount nTreasury = 10 * COIN, nFee = 5000;
    const CScript scriptNop5 = ScriptHex("b4018251"), scriptNop8 = ScriptHex("b7018251");
    const COutPoint ctip(uint256S("aa00000000000000000000000000000000000000000000000000000000000001"), 0);

    const CMutableTransaction blindedOurs = MakeBlindedBundle(nFee, Payouts(0x11));
    const CMutableTransaction blindedForeign = MakeBlindedBundle(nFee, Payouts(0x33));
    const uint256 m6idOurs = CTransaction(blindedOurs).GetHash();
    const uint256 m6idForeign = CTransaction(blindedForeign).GetHash();

    auto candidate = [](int nTx, const CMutableTransaction& mtx, CAmount nPrev, const CScript& scriptPrev) {
        M6Candidate c;
        c.nTx = nTx;
        c.mtx = mtx;
        c.nPrevValue = nPrev;
        c.scriptPrev = scriptPrev;
        return c;
    };
    const CMutableTransaction m6Beta = IntoM6(blindedOurs, 0xb7, ctip, nTreasury, nFee);
    int nMatches = -1;

    // A betanet (NOP8) M6 alone: found
    BOOST_CHECK_EQUAL(LocateM6({candidate(3, m6Beta, nTreasury, scriptNop8)}, m6idOurs, 130, nMatches), 0);
    BOOST_CHECK_EQUAL(nMatches, 1);
    // v0.2.12's exact-NOP5 comparison finds nothing in the same block: the halt
    const CScript scriptV0212 = CScript() << OP_NOP5 << std::vector<unsigned char>{130} << OP_TRUE;
    BOOST_CHECK(m6Beta.vout[0].scriptPubKey != scriptV0212);

    // A NOP5 lookalike in the same block (on beta OP_NOP5 is a plain NOP anyone
    // can mint) does not match; "accept both opcodes" would have counted 2.
    CMutableTransaction lookalike = IntoM6(MakeBlindedBundle(0, Payouts(0x55)), 0xb4, COutPoint(uint256S("cc"), 0), COIN * 2, 0);
    std::vector<M6Candidate> v = {candidate(1, lookalike, COIN * 2, CScript() << OP_TRUE),
                                  candidate(2, m6Beta, nTreasury, scriptNop8)};
    BOOST_CHECK_EQUAL(LocateM6(v, m6idOurs, 130, nMatches), 1);
    BOOST_CHECK_EQUAL(nMatches, 1);
    // ...even if it spends a NOP5 "treasury" of its own
    v[0].scriptPrev = scriptNop5;
    BOOST_CHECK_EQUAL(LocateM6(v, m6idOurs, 130, nMatches), 1);
    BOOST_CHECK_EQUAL(nMatches, 1);

    // Two real M6s in one L1 block (ours + a foreign bundle on the shared slot):
    // each event finds its own
    const CMutableTransaction m6Foreign = IntoM6(blindedForeign, 0xb7, COutPoint(uint256S("dd"), 0), nTreasury, nFee);
    v = {candidate(4, m6Foreign, nTreasury, scriptNop8), candidate(7, m6Beta, nTreasury, scriptNop8)};
    BOOST_CHECK_EQUAL(LocateM6(v, m6idOurs, 130, nMatches), 1);
    BOOST_CHECK_EQUAL(LocateM6(v, m6idForeign, 130, nMatches), 0);

    // The M6 must spend a treasury output under its own script (the CTIP)
    BOOST_CHECK_EQUAL(LocateM6({candidate(3, m6Beta, nTreasury, CScript() << OP_TRUE)}, m6idOurs, 130, nMatches), -1);
    BOOST_CHECK_EQUAL(LocateM6({candidate(3, m6Beta, nTreasury, scriptNop5)}, m6idOurs, 130, nMatches), -1);
    // Wrong previous treasury value -> different m6id -> not found
    BOOST_CHECK_EQUAL(LocateM6({candidate(3, m6Beta, nTreasury + 1, scriptNop8)}, m6idOurs, 130, nMatches), -1);
    BOOST_CHECK_EQUAL(nMatches, 0);
    // Nothing at all
    BOOST_CHECK_EQUAL(LocateM6({}, m6idOurs, 130, nMatches), -1);

    // Residual, fails closed: a duplicate with identical outputs spending another
    // treasury-shaped output of the same value (the attacker pays every payout
    // again) is ambiguous
    const CMutableTransaction dup = IntoM6(blindedOurs, 0xb7, COutPoint(uint256S("ee"), 0), nTreasury, nFee);
    v = {candidate(3, m6Beta, nTreasury, scriptNop8), candidate(5, dup, nTreasury, scriptNop8)};
    BOOST_CHECK_EQUAL(LocateM6(v, m6idOurs, 130, nMatches), -2);
    BOOST_CHECK_EQUAL(nMatches, 2);
}

// v0.2.15: an L1 tx FreeBank cannot decode in the same block as our M6 (an eCash
// v3/TRUC tx: FreeBank's v3 layout reads a replay byte TRUC does not have) is
// skipped instead of failing the whole deposit batch, which v0.2.14 did for good.
BOOST_AUTO_TEST_CASE(l1client_build_m6_candidates_skips_undecodable)
{
    const CAmount nTreasury = 10 * COIN, nFee = 5000;
    const CScript scriptNop8 = ScriptHex("b7018251");

    // The CTIP our M6 spends, and our M6 (built by the enforcer: v2)
    CMutableTransaction ctip;
    ctip.nVersion = 2;
    ctip.vin.push_back(CTxIn(COutPoint(uint256S("c1"), 0)));
    ctip.vout.push_back(CTxOut(nTreasury, scriptNop8));
    const uint256 keyCtip = uint256S("c7"), keyM6 = uint256S("e6"), keyTruc = uint256S("7c"), keyLook = uint256S("1a");
    const CMutableTransaction blindedOurs = MakeBlindedBundle(nFee, Payouts(0x11));
    const uint256 m6idOurs = CTransaction(blindedOurs).GetHash();
    const CMutableTransaction m6 = IntoM6(blindedOurs, 0xb7, COutPoint(keyCtip, 0), nTreasury, nFee);

    // An eCash v3 (TRUC) tx: plain Bitcoin serialization, nVersion 3, no replay byte
    CMutableTransaction plain;
    plain.nVersion = 2;
    plain.vin.push_back(CTxIn(COutPoint(uint256S("f0"), 1)));
    plain.vout.push_back(CTxOut(COIN, CScript() << OP_TRUE));
    std::string strTruc = EncodeHexTx(CTransaction(plain));
    BOOST_REQUIRE_EQUAL(strTruc.substr(0, 8), "02000000");
    strTruc.replace(0, 8, "03000000");
    CMutableTransaction probe;
    BOOST_CHECK(!DecodeHexTx(probe, strTruc)); // the root cause
    BOOST_CHECK(DecodeHexTx(probe, EncodeHexTx(CTransaction(plain)))); // the same tx as v2 is fine

    // A fake L1: txid -> raw hex, decoded with FreeBank's own decoder like RestFetchRawTx
    std::map<uint256, std::string> mapL1 = {
        {keyCtip, EncodeHexTx(CTransaction(ctip))},
        {keyM6, EncodeHexTx(CTransaction(m6))},
        {keyTruc, strTruc},
    };
    auto fetch = [&mapL1](const uint256& txid, CMutableTransaction& mtx) {
        const auto it = mapL1.find(txid);
        if (it == mapL1.end())
            return L1TxFetch::FAILED;
        return ClassifyRawTxBody(it->second, mtx); // what RestFetchRawTx does after RestGet
    };
    const uint256 keyCoinbase = uint256S("cb");
    std::vector<M6Candidate> vCandidate;
    int nSkipped = -1, nMatches = -1;
    std::string strError;

    // A TRUC tx beside our M6: skipped, and our M6 is still found
    BOOST_CHECK(BuildM6Candidates({keyCoinbase, keyTruc, keyM6}, {}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK_EQUAL(nSkipped, 1);
    BOOST_REQUIRE_EQUAL(vCandidate.size(), 1U);
    BOOST_CHECK_EQUAL(vCandidate[0].nTx, 2);
    BOOST_CHECK_EQUAL(vCandidate[0].nPrevValue, nTreasury);
    BOOST_CHECK_EQUAL(LocateM6(vCandidate, m6idOurs, 130, nMatches), 0);

    // A treasury-shaped lookalike whose spent output sits in an undecodable tx: skipped too
    CMutableTransaction look = IntoM6(MakeBlindedBundle(0, Payouts(0x55)), 0xb7, COutPoint(keyTruc, 0), COIN * 2, 0);
    mapL1[keyLook] = EncodeHexTx(CTransaction(look));
    BOOST_CHECK(BuildM6Candidates({keyCoinbase, keyLook, keyM6}, {}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK_EQUAL(nSkipped, 1);
    BOOST_REQUIRE_EQUAL(vCandidate.size(), 1U);
    BOOST_CHECK_EQUAL(LocateM6(vCandidate, m6idOurs, 130, nMatches), 0);

    // Deposit txs are excluded before any fetch
    BOOST_CHECK(BuildM6Candidates({keyCoinbase, keyTruc, keyM6}, {keyTruc}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK_EQUAL(nSkipped, 0);
    BOOST_CHECK_EQUAL(vCandidate.size(), 1U);

    // A fetch that FAILED (transport, not decoding) still fails the batch closed
    const uint256 keyMissing = uint256S("0d");
    strError.clear();
    BOOST_CHECK(!BuildM6Candidates({keyCoinbase, keyMissing, keyM6}, {}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK(strError.find(keyMissing.ToString()) != std::string::npos);
    // ...and so does a failed fetch of a candidate's spent output
    mapL1.erase(keyCtip);
    strError.clear();
    BOOST_CHECK(!BuildM6Candidates({keyCoinbase, keyM6}, {}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK(strError.find("spent by " + keyM6.ToString()) != std::string::npos);
    mapL1[keyCtip] = EncodeHexTx(CTransaction(ctip));

    // A v3 tx FreeBank's decoder reads "successfully" (its own replay-byte layout),
    // treasury-shaped, spending an output the L1 does not have: skipped by version.
    // Without the v1/v2 rule its prevout fetch FAILED and failed the batch closed.
    CMutableTransaction crafted;
    crafted.nVersion = 3;
    crafted.vin.push_back(CTxIn(COutPoint(uint256S("0e"), 0)));
    crafted.vout.push_back(CTxOut(COIN, scriptNop8));
    const uint256 keyCrafted = uint256S("cf");
    mapL1[keyCrafted] = EncodeHexTx(CTransaction(crafted));
    CMutableTransaction probeCrafted;
    BOOST_REQUIRE(ClassifyRawTxBody(mapL1[keyCrafted], probeCrafted) == L1TxFetch::OK);
    BOOST_CHECK(BuildM6Candidates({keyCoinbase, keyCrafted, keyM6}, {}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK_EQUAL(nSkipped, 1);
    BOOST_REQUIRE_EQUAL(vCandidate.size(), 1U);
    BOOST_CHECK_EQUAL(LocateM6(vCandidate, m6idOurs, 130, nMatches), 0);

    // Residual, pinned on purpose: if the CTIP our M6 spends sits in an
    // undecodable tx (a v3 M5, issue 1), our M6 is skipped, and a second M6 with
    // the SAME m6id spending another treasury output of the same value would be
    // selected instead. That needs a v3 M5 (the deposit loop fails closed on it
    // first) and an attacker paying every bundle payout again; v0.2.14 halted on
    // the same block. The consensus release's L1-canonical decoder removes it.
    const uint256 keyM6OnTruc = uint256S("e7"), keyCtip2 = uint256S("c8"), keyDup = uint256S("d0");
    mapL1[keyM6OnTruc] = EncodeHexTx(CTransaction(IntoM6(blindedOurs, 0xb7, COutPoint(keyTruc, 0), nTreasury, nFee)));
    CMutableTransaction ctip2(ctip);
    ctip2.vin[0].prevout = COutPoint(uint256S("c2"), 0);
    mapL1[keyCtip2] = EncodeHexTx(CTransaction(ctip2));
    mapL1[keyDup] = EncodeHexTx(CTransaction(IntoM6(blindedOurs, 0xb7, COutPoint(keyCtip2, 0), nTreasury, nFee)));
    BOOST_CHECK(BuildM6Candidates({keyCoinbase, keyM6OnTruc, keyDup}, {}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK_EQUAL(nSkipped, 1);
    BOOST_REQUIRE_EQUAL(vCandidate.size(), 1U);
    BOOST_CHECK_EQUAL(vCandidate[0].nTx, 2);
    BOOST_CHECK_EQUAL(LocateM6(vCandidate, m6idOurs, 130, nMatches), 0);

    // If our M6 itself were undecodable it is skipped, and LocateM6 still fails closed
    mapL1[keyM6] = "03000000" + EncodeHexTx(CTransaction(m6)).substr(8);
    BOOST_CHECK(BuildM6Candidates({keyCoinbase, keyM6}, {}, 130, fetch, vCandidate, nSkipped, strError));
    BOOST_CHECK_EQUAL(nSkipped, 1);
    BOOST_CHECK(vCandidate.empty());
    BOOST_CHECK_EQUAL(LocateM6(vCandidate, m6idOurs, 130, nMatches), -1);
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
    BOOST_CHECK(ClassifyRawTxBody(strTruc, tx) == L1TxFetch::UNDECODABLE);
    BOOST_CHECK(ClassifyRawTxBody(strV2 + "\n", tx) == L1TxFetch::OK);
    BOOST_CHECK(CTransaction(tx).GetHash() == CTransaction(plain).GetHash());
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

BOOST_AUTO_TEST_SUITE_END()

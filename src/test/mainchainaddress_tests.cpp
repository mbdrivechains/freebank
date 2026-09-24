// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// v0.2.13 item 5: withdrawals to L1 P2SH / P2WPKH / P2WSH / P2TR addresses via
// consensus "carrier" strings (mainchainaddress.h). Vectors were generated with
// an independent Python BIP173/BIP350/base58check implementation.

#include <mainchainaddress.h>

#include <base58.h>
#include <bech32.h>
#include <chainparams.h>
#include <script/standard.h>
#include <test/test_bitcoin.h>
#include <util.h>
#include <utilstrencodings.h>

#include <boost/test/unit_test.hpp>

extern bool g_fMainchainMainFamily; // base58.cpp (A9)

namespace {

enum class Family { MAIN, TEST, REGTEST };

/** Select an L1 family for the scope (restores -regtest and the A9 flag). */
class FamilyScope
{
    std::string m_strRegtest;
    bool m_fMain;
public:
    explicit FamilyScope(Family f) : m_strRegtest(gArgs.GetArg("-regtest", "0")), m_fMain(g_fMainchainMainFamily)
    {
        gArgs.ForceSetArg("-regtest", f == Family::REGTEST ? "1" : "0");
        g_fMainchainMainFamily = f == Family::MAIN;
    }
    ~FamilyScope()
    {
        gArgs.ForceSetArg("-regtest", m_strRegtest);
        g_fMainchainMainFamily = m_fMain;
    }
};

std::string Hex(const CScript& s) { return HexStr(s.begin(), s.end()); }

CScript FromHex(const std::string& h)
{
    const std::vector<unsigned char> v = ParseHex(h);
    return CScript(v.begin(), v.end());
}

// Programs: h20 = 01..14, h32 = 01..20
const std::string SPK_P2PKH = "76a9140102030405060708090a0b0c0d0e0f101112131488ac";
const std::string SPK_P2SH = "a9140102030405060708090a0b0c0d0e0f101112131487";
const std::string SPK_P2WPKH = "00140102030405060708090a0b0c0d0e0f1011121314";
const std::string SPK_P2WSH = "00200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
const std::string SPK_P2TR = "51200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

struct Row { const char* type; const char* l1; std::string spk; };

const std::vector<Row> MAIN_ROWS = {
    {"P2PKH", "16L5yRNPTuciSgXGHqYwn9N6NeoKqopAu", SPK_P2PKH},
    {"P2SH", "31nM1WuowNDzocNxPPW9NQWJEtwWpjfcLj", SPK_P2SH},
    {"P2WPKH", "bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5fcj4z3", SPK_P2WPKH},
    {"P2WSH", "bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqyp0mu0", SPK_P2WSH},
    {"P2TR", "bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqwk0jyn", SPK_P2TR},
};
const std::vector<Row> TEST_ROWS = {
    {"P2PKH", "mfcHP2WMCVLsVZA8yrovmhMgxNFW9r98xw", SPK_P2PKH},
    {"P2SH", "2MsLZ5FqqYpjM1Q1W4X81zMVZTF9gdbhVwd", SPK_P2SH},
    {"P2WPKH", "tb1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5r7fxez", SPK_P2WPKH},
    {"P2WSH", "tb1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqnfe5xq", SPK_P2WSH},
    {"P2TR", "tb1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqe7ea7u", SPK_P2TR},
};
const std::vector<Row> REGTEST_ROWS = {
    {"P2PKH", "mfcHP2WMCVLsVZA8yrovmhMgxNFW9r98xw", SPK_P2PKH},
    {"P2SH", "2MsLZ5FqqYpjM1Q1W4X81zMVZTF9gdbhVwd", SPK_P2SH},
    {"P2WPKH", "bcrt1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5phstwt", SPK_P2WPKH},
    {"P2WSH", "bcrt1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq7snjn6", SPK_P2WSH},
    {"P2TR", "bcrt1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq58nmtx", SPK_P2TR},
};

void CheckFamily(Family f, const std::vector<Row>& rows)
{
    FamilyScope scope(f);
    for (const Row& r : rows) {
        CScript spk;
        std::string err;
        BOOST_CHECK_MESSAGE(ParseMainchainAddress(r.l1, spk, err), r.type << " " << r.l1 << ": " << err);
        BOOST_CHECK_EQUAL(Hex(spk), r.spk);
        // The L1 form round-trips (P2TR re-encoded with bech32m)
        BOOST_CHECK_EQUAL(EncodeMainchainAddress(spk), r.l1);
        // CONSENSUS-COMPAT INVARIANT: the frozen decoder maps the carrier to exactly spk
        const std::string carrier = EncodeMainchainCarrier(spk);
        BOOST_REQUIRE_MESSAGE(!carrier.empty(), r.type);
        BOOST_CHECK_EQUAL(Hex(MainchainPayoutScript(carrier)), r.spk);
        BOOST_CHECK_EQUAL(Hex(GetScriptForDestination(DecodeDestination(carrier, true))), r.spk);
        // Users see the L1 form, never the carrier
        BOOST_CHECK_EQUAL(MainchainDisplayAddress(carrier), r.l1);
        // A P2PKH carrier is the user's L1 string itself
        if (std::string(r.type) == "P2PKH")
            BOOST_CHECK_EQUAL(carrier, r.l1);
    }
}

bool Rejects(const std::string& str, std::string* pErr = nullptr)
{
    CScript spk;
    std::string err;
    const bool fOk = ParseMainchainAddress(str, spk, err);
    if (pErr) *pErr = err;
    return !fOk && spk.empty() && !err.empty();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(mainchainaddress_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mainchainaddress_every_type_every_family)
{
    CheckFamily(Family::MAIN, MAIN_ROWS);
    CheckFamily(Family::TEST, TEST_ROWS);
    CheckFamily(Family::REGTEST, REGTEST_ROWS);
}

BOOST_AUTO_TEST_CASE(mainchainaddress_other_network_rejected)
{
    {
        FamilyScope scope(Family::MAIN);
        for (const Row& r : TEST_ROWS) BOOST_CHECK_MESSAGE(Rejects(r.l1), r.l1);
        for (const Row& r : REGTEST_ROWS) BOOST_CHECK_MESSAGE(Rejects(r.l1), r.l1);
    }
    {
        FamilyScope scope(Family::TEST);
        for (const Row& r : MAIN_ROWS) BOOST_CHECK_MESSAGE(Rejects(r.l1), r.l1);
        BOOST_CHECK(Rejects(REGTEST_ROWS[2].l1)); // bcrt1q on a test-family L1
    }
    {
        FamilyScope scope(Family::REGTEST);
        for (const Row& r : MAIN_ROWS) BOOST_CHECK_MESSAGE(Rejects(r.l1), r.l1);
        BOOST_CHECK(Rejects(TEST_ROWS[2].l1)); // tb1q on regtest
    }
}

BOOST_AUTO_TEST_CASE(mainchainaddress_negatives)
{
    FamilyScope scope(Family::MAIN);
    std::string err;
    // v0 with a bech32m checksum; v1 with a bech32 checksum (the L1 form of P2TR must be bech32m)
    BOOST_CHECK(Rejects("bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5uyze8n"));
    BOOST_CHECK(Rejects("bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqm2l7p3"));
    // v1 that is not 32 bytes; witness v2; v0 of 25 bytes
    BOOST_CHECK(Rejects("bc1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5h64j2c"));
    BOOST_CHECK(Rejects("bc1zqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqxtka2c"));
    BOOST_CHECK(Rejects("bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqemhpk3x"));
    // Bad checksum, mixed case, junk
    BOOST_CHECK(Rejects("bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5fcj4z4"));
    BOOST_CHECK(Rejects("bc1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5FCJ4Z3"));
    BOOST_CHECK(Rejects("16L5yRNPTuciSgXGHqYwn9N6NeoKqopAv"));
    BOOST_CHECK(Rejects(""));
    BOOST_CHECK(Rejects("garbage"));
    // FreeBank sidechain addresses (incl. the carriers themselves) are refused as destinations
    for (const std::string s : {"fbk1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5a6737n",
                                "fbk1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqf5s3v2",
                                "sJLjAYgP91q8wd7MKjUPZTAhmRri9baprg",
                                "XBSZw7mydzfL3x926kpTKBZNJCyYbqe9tN"}) {
        BOOST_CHECK_MESSAGE(Rejects(s, &err), s);
        BOOST_CHECK_MESSAGE(err.find("FreeBank (sidechain) address") != std::string::npos, s << ": " << err);
    }
    // Upper-case bech32 is valid (BIP173)
    CScript spk;
    BOOST_CHECK(ParseMainchainAddress("BC1QQYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5FCJ4Z3", spk, err));
    BOOST_CHECK_EQUAL(Hex(spk), SPK_P2WPKH);
}

BOOST_AUTO_TEST_CASE(mainchainaddress_bip_vectors)
{
    FamilyScope scope(Family::MAIN);
    CScript spk;
    std::string err;
    // BIP350: taproot output of the secp256k1 generator's x coordinate
    BOOST_CHECK(ParseMainchainAddress("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", spk, err));
    BOOST_CHECK_EQUAL(Hex(spk), "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    BOOST_CHECK_EQUAL(Hex(MainchainPayoutScript(EncodeMainchainCarrier(spk))), Hex(spk));
    // BIP173 P2WPKH
    BOOST_CHECK(ParseMainchainAddress("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", spk, err));
    BOOST_CHECK_EQUAL(Hex(spk), "0014751e76e8199196d454941c45d1b3a323f1433bd6");
    BOOST_CHECK_EQUAL(EncodeMainchainAddress(spk), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
}

// GOLDEN PINS. The carrier strings below are what v0.2.13 stores; the frozen
// consensus decoder must keep mapping them to these scripts forever. If this
// test fails, a change to DecodeDestination(fMainchain=true), bech32::Decode or
// the SCRIPT_ADDRESS / bech32_hrp params would split the chain. Do not "fix"
// the test - revert the change.
BOOST_AUTO_TEST_CASE(mainchainaddress_golden_carriers)
{
    FamilyScope scope(Family::MAIN);
    const std::vector<std::pair<std::string, std::string>> vGolden = {
        {"fbk1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5a6737n", SPK_P2WPKH},
        {"fbk1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqklq535", SPK_P2WSH},
        {"fbk1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqf5s3v2", SPK_P2TR},
        {"sJLjAYgP91q8wd7MKjUPZTAhmRri9baprg", SPK_P2SH},
    };
    for (const auto& g : vGolden) {
        BOOST_CHECK_EQUAL(EncodeMainchainCarrier(FromHex(g.second)), g.first);
        BOOST_CHECK_EQUAL(Hex(MainchainPayoutScript(g.first)), g.second);
    }
    // Unsupported payout scripts get no carrier (fail closed)
    BOOST_CHECK(EncodeMainchainCarrier(CScript()).empty());
    BOOST_CHECK(EncodeMainchainCarrier(CScript() << OP_RETURN).empty());
    BOOST_CHECK(EncodeMainchainCarrier(FromHex("5214" + std::string(40, '1'))).empty()); // witness v2
    BOOST_CHECK(EncodeMainchainCarrier(FromHex("5114" + std::string(40, '1'))).empty()); // v1, 20 bytes
    // P2PK is not silently turned into P2PKH
    BOOST_CHECK(EncodeMainchainCarrier(FromHex("21" + std::string(66, '2') + "ac")).empty());
}

// v0.2.12 decoder behaviour, pinned: why carriers exist, and that they still work.
BOOST_AUTO_TEST_CASE(mainchainaddress_frozen_decoder_pins)
{
    FamilyScope scope(Family::MAIN);
    // Real L1 P2SH / bech32 / taproot strings do NOT decode as mainchain destinations
    for (const Row& r : MAIN_ROWS) {
        if (std::string(r.type) == "P2PKH")
            BOOST_CHECK(IsValidDestination(DecodeDestination(r.l1, true)));
        else
            BOOST_CHECK_MESSAGE(!IsValidDestination(DecodeDestination(r.l1, true)), r.l1);
    }
    // A bech32m-checksummed carrier is rejected by the frozen decoder...
    BOOST_CHECK(!IsValidDestination(DecodeDestination("fbk1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqugqafg", true)));
    // ...the BIP173 one is WitnessUnknown{1, 32 bytes}
    const CTxDestination tr = DecodeDestination("fbk1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqf5s3v2", true);
    const WitnessUnknown* pUnk = boost::get<WitnessUnknown>(&tr);
    BOOST_REQUIRE(pUnk);
    BOOST_CHECK_EQUAL(pUnk->version, 1U);
    BOOST_CHECK_EQUAL(pUnk->length, 32U);
    const CTxDestination sh = DecodeDestination("sJLjAYgP91q8wd7MKjUPZTAhmRri9baprg", true);
    BOOST_CHECK(boost::get<CScriptID>(&sh));
    const CTxDestination wpkh = DecodeDestination("fbk1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5a6737n", true);
    BOOST_CHECK(boost::get<WitnessV0KeyHash>(&wpkh));
    // A payout script the bundle builder accepts as standard (TX_WITNESS_UNKNOWN)
    BOOST_CHECK(!MainchainPayoutScript("fbk1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqf5s3v2").empty());
    // A stored string that does not decode yields an empty script (a row no bundle can pay)
    BOOST_CHECK(MainchainPayoutScript("garbage").empty());
    BOOST_CHECK_EQUAL(MainchainDisplayAddress("garbage"), "garbage");
}

BOOST_AUTO_TEST_CASE(mainchainaddress_regtest_params_carriers)
{
    // On FreeBank regtest the carrier uses the regtest sidechain HRP fbkrt
    SelectParams(CBaseChainParams::REGTEST);
    {
        FamilyScope scope(Family::REGTEST);
        const std::string c = EncodeMainchainCarrier(FromHex(SPK_P2WPKH));
        BOOST_CHECK_EQUAL(c, "fbkrt1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5qfg6jx");
        BOOST_CHECK_EQUAL(EncodeMainchainCarrier(FromHex(SPK_P2TR)),
                          "fbkrt1pqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4stfpm");
        BOOST_CHECK_EQUAL(EncodeMainchainCarrier(FromHex(SPK_P2SH)), "sJLjAYgP91q8wd7MKjUPZTAhmRri9baprg");
        BOOST_CHECK_EQUAL(MainchainDisplayAddress(c), "bcrt1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5phstwt");
        // The regtest gates' P2PKH form (BTX hash re-encoded with prefix 111) still works
        CScript spk;
        std::string err;
        BOOST_CHECK(ParseMainchainAddress("mfcHP2WMCVLsVZA8yrovmhMgxNFW9r98xw", spk, err));
        BOOST_CHECK_EQUAL(EncodeMainchainCarrier(spk), "mfcHP2WMCVLsVZA8yrovmhMgxNFW9r98xw");
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()

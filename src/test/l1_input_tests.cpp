// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// testing (L1 inputs, 2026-11-13): the readers of enforcer and L1 answers, held to their own contract. A reader
// answers false ("can't read", the caller's UNKNOWN), never throws: a throw skips the caller's UNKNOWN handling, and on
// a thread with no catch (the import thread behind CheckBlockBMM's GetBlockHeight, the scheduler's L1 cycles) it ends
// the node. Found with the FREEBANK_L1_* fuzz targets in test_bitcoin_fuzzy.cpp. Each case fails on master 198a082.

#include <amount.h>
#include <l1client.h>
#include <test/test_bitcoin.h>
#include <uint256.h>
#include <univalue.h>

#include <functional>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(l1_input_tests, BasicTestingSetup)

static UniValue Json(const std::string& str)
{
    UniValue v;
    BOOST_REQUIRE_MESSAGE(v.read(str), str);
    return v;
}

static const std::string HASH64(64, 'a');

// Numbers proto3 JSON never sends for these fields, but a broken or hostile answer can: past int32, fractions,
// exponents. Each must read as "can't read" (or a correct value), not as an exception.
static const std::vector<std::string> ODD_NUMBERS = {"2147483648", "4294967296", "1.5", "1e10", "-2147483649"};

BOOST_AUTO_TEST_CASE(header_height_is_never_a_throw)
{
    // ParseHeaderObject: header.nHeight = height.isNum() ? height.get_int() : 0 (l1client.cpp ~282)
    for (const std::string& n : ODD_NUMBERS) {
        const std::string hdr = "{\"blockHash\":{\"hex\":\"" + HASH64 + "\"},\"height\":" + n + "}";
        L1BlockHeader tip;
        BOOST_CHECK_NO_THROW(ParseEnforcerChainTip(Json("{\"blockHeaderInfo\":" + hdr + "}"), tip));
        std::vector<L1BlockHeader> vHeader;
        BOOST_CHECK_NO_THROW(ParseEnforcerHeaderInfos(Json("{\"headerInfos\":[" + hdr + "]}"), vHeader));
    }
}

BOOST_AUTO_TEST_CASE(ctip_vout_is_never_a_throw)
{
    // ParseEnforcerCtip: n = vout.isNum() ? (uint32_t)vout.get_int() : 0 (l1client.cpp ~440)
    for (const std::string& n : ODD_NUMBERS) {
        uint256 txid;
        uint32_t nOut = 0;
        BOOST_CHECK_NO_THROW(ParseEnforcerCtip(Json("{\"ctip\":{\"txid\":{\"hex\":\"" + HASH64 + "\"},\"vout\":" + n + "}}"),
                                               txid, nOut));
    }
}

BOOST_AUTO_TEST_CASE(chain_info_numbers_are_never_a_throw)
{
    // ParseEnforcerChainInfo: v.isNum() then v.get_int64() (~1460); ChainNameFromEnforcerChainInfo: network.get_int()
    // (~1333). Both run at startup against the enforcer's GetChainInfo.
    for (const std::string& n : {std::string("1.5"), std::string("1e30"), std::string("18446744073709551616")}) {
        EnforcerSettings settings;
        BOOST_CHECK_NO_THROW(ParseEnforcerChainInfo(Json("{\"bip300Constants\":{\"withdrawalBundleMaxAge\":" + n + "}}"), settings));
        BOOST_CHECK_NO_THROW(ChainNameFromEnforcerChainInfo(Json("{\"network\":" + n + "}")));
    }
}

// A one-input, one-output Bitcoin tx (legacy serialization) paying nValue to OP_TRUE.
static std::string TxHexPaying(const std::string& strValueLE)
{
    return "02000000" "01" + std::string(64, '0') + "00000000" "00" "ffffffff" "01" + strValueLE + "01" "51" "00000000";
}

static std::string Deposit(const std::string& strSide, const std::string& strTxHex, const std::string& strBurn, const std::string& strNtx)
{
    return "{\"nsidechain\":" + strSide + ",\"txhex\":\"" + strTxHex + "\",\"nburnindex\":" + strBurn + ",\"ntx\":" + strNtx +
           ",\"hashblock\":\"" + HASH64 + "\",\"strdest\":\"d\"}";
}

static const std::function<bool(const uint256&, int&)> HEIGHT_10 = [](const uint256&, int& n) { n = 10; return true; };

BOOST_AUTO_TEST_CASE(jsonrpc_deposit_numbers_are_never_a_throw)
{
    // BuildJsonRpcDepositEvents: side.get_int(), burn.get_int(), ntx.get_int() after isNum (l1client.cpp ~2974-2984)
    const std::string tx = TxHexPaying("a086010000000000");   // 100000 sats
    for (const std::string& n : ODD_NUMBERS) {
        for (const std::string& d : {Deposit(n, tx, "0", "1"), Deposit("130", tx, n, "1"), Deposit("130", tx, "0", n)}) {
            std::vector<L1DepositEvent> v;
            BOOST_CHECK_NO_THROW(BuildJsonRpcDepositEvents(Json("[" + d + "]"), HEIGHT_10, -1, v));
        }
    }
}

BOOST_AUTO_TEST_CASE(jsonrpc_deposit_value_is_in_money_range)
{
    // The enforcer's reader refuses a deposit value outside MoneyRange (ParsePegEvents, valueSats). The JSON-RPC reader
    // feeds the same records but takes the first deposit's treasury output as it stands: a negative or over-MAX_MONEY
    // output becomes a deposit of that value.
    for (const std::string& v : {std::string("fbffffffffffffff") /* -5 */, std::string("0140075af0750700") /* MAX_MONEY + 1 */}) {
        std::vector<L1DepositEvent> vOut;
        bool ok = false;
        BOOST_CHECK_NO_THROW(ok = BuildJsonRpcDepositEvents(Json("[" + Deposit("130", TxHexPaying(v), "0", "1") + "]"),
                                                            HEIGHT_10, -1, vOut));
        for (const L1DepositEvent& d : vOut)
            BOOST_CHECK_MESSAGE(MoneyRange(d.nValue), "deposit value " << d.nValue << " handed over (ok " << ok << ")");
    }
}

BOOST_AUTO_TEST_SUITE_END()

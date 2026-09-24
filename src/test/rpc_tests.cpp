// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/server.h>
#include <rpc/client.h>

#include <base58.h>
#include <bill.h>
#include <coins.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <deposit.h>
#include <house.h>
#include <netbase.h>
#include <note.h>
#include <oracle.h>
#include <pool.h>
#include <rpc/blockchain.h>
#include <settle.h>
#include <txmempool.h>
#include <undo.h>
#include <utilstrencodings.h>
#include <validation.h>

#include <test/test_bitcoin.h>

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

#include <univalue.h>

UniValue CallRPC(std::string args)
{
    std::vector<std::string> vArgs;
    boost::split(vArgs, args, boost::is_any_of(" \t"));
    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    JSONRPCRequest request;
    request.strMethod = strMethod;
    request.params = RPCConvertValues(strMethod, vArgs);
    request.fHelp = false;
    BOOST_CHECK(tableRPC[strMethod]);
    rpcfn_type method = tableRPC[strMethod]->actor;
    try {
        UniValue result = (*method)(request);
        return result;
    }
    catch (const UniValue& objError) {
        throw std::runtime_error(find_value(objError, "message").get_str());
    }
}


/** The message of the error an RPC call throws, or "" if it succeeds. */
static std::string RPCErrorMessage(const std::string& args)
{
    try {
        CallRPC(args);
    } catch (const std::runtime_error& e) {
        return e.what();
    }
    return "";
}

BOOST_FIXTURE_TEST_SUITE(rpc_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    UniValue r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] []"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {}"), std::runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [] {}"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {} extra"), std::runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), std::runtime_error);
    std::string rawtx = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx));
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "size").get_int(), 193);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "version").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "locktime").get_int(), 0);
    BOOST_CHECK_THROW(CallRPC(std::string("decoderawtransaction ")+rawtx+" extra"), std::runtime_error);
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false"));
    BOOST_CHECK_THROW(r = CallRPC(std::string("decoderawtransaction ")+rawtx+" false extra"), std::runtime_error);

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC(std::string("sendrawtransaction ")+rawtx+" extra"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_togglenetwork)
{
    UniValue r;

    r = CallRPC("getnetworkinfo");
    bool netState = find_value(r.get_obj(), "networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive false"));
    r = CallRPC("getnetworkinfo");
    int numConnection = find_value(r.get_obj(), "connections").get_int();
    BOOST_CHECK_EQUAL(numConnection, 0);

    netState = find_value(r.get_obj(), "networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, false);

    BOOST_CHECK_NO_THROW(CallRPC("setnetworkactive true"));
    r = CallRPC("getnetworkinfo");
    netState = find_value(r.get_obj(), "networkactive").get_bool();
    BOOST_CHECK_EQUAL(netState, true);
}

BOOST_AUTO_TEST_CASE(rpc_rawsign)
{
    UniValue r;
    // input is a 1-of-2 multisig (so is output):
    std::string prevout =
      "[{\"txid\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
      "\"vout\":1,\"scriptPubKey\":\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
      "\"redeemScript\":\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f9216ecefca5b94d6df834e77e108f68e66f126044c052ae\"}]";
    r = CallRPC(std::string("createrawtransaction ")+prevout+" "+
      "{\"saPYoB7TZqLw1g5T9KWphWTKj7PjjM3pNN\":11}");
    std::string notsigned = r.get_str();
    std::string privkey1 = "\"KzsXybp9jX64P5ekX1KUxRQ79Jht9uzW7LorgwE65i5rWACL6LQe\"";
    std::string privkey2 = "\"Kyhdf5LuKTRx4ge69ybABsiUAWjVRK4XGxAKk2FQLp2HjGMy87Z4\"";
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" [] "+prevout);
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == false);
    r = CallRPC(std::string("signrawtransactionwithkey ")+notsigned+" ["+privkey1+","+privkey2+"] "+prevout);
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == true);
}

BOOST_AUTO_TEST_CASE(rpc_createraw_op_return)
{
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"68656c6c6f776f726c64\"}"));

    // Allow more than one data transaction output
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"68656c6c6f776f726c64\",\"data\":\"68656c6c6f776f726c64\"}"));

    // Key not "data" (bad address)
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"somedata\":\"68656c6c6f776f726c64\"}"), std::runtime_error);

    // Bad hex encoding of data output
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345\"}"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"12345g\"}"), std::runtime_error);

    // Data 81 bytes long
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction [{\"txid\":\"a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed\",\"vout\":0}] {\"data\":\"010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081\"}"));
}

BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).write() == "0.00000000");
    BOOST_CHECK(ValueFromAmount(1LL).write() == "0.00000001");
    BOOST_CHECK(ValueFromAmount(17622195LL).write() == "0.17622195");
    BOOST_CHECK(ValueFromAmount(50000000LL).write() == "0.50000000");
    BOOST_CHECK(ValueFromAmount(89898989LL).write() == "0.89898989");
    BOOST_CHECK(ValueFromAmount(100000000LL).write() == "1.00000000");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).write() == "20999999.99999990");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).write() == "20999999.99999999");

    BOOST_CHECK_EQUAL(ValueFromAmount(0).write(), "0.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount((COIN/10000)*123456789).write(), "12345.67890000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN).write(), "-1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(-COIN/10).write(), "-0.10000000");

    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000000).write(), "100000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000000).write(), "10000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000000).write(), "1000000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100000).write(), "100000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10000).write(), "10000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*1000).write(), "1000.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*100).write(), "100.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN*10).write(), "10.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN).write(), "1.00000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10).write(), "0.10000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100).write(), "0.01000000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000).write(), "0.00100000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000).write(), "0.00010000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000).write(), "0.00001000");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/1000000).write(), "0.00000100");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/10000000).write(), "0.00000010");
    BOOST_CHECK_EQUAL(ValueFromAmount(COIN/100000000).write(), "0.00000001");
}

static UniValue ValueFromString(const std::string &str)
{
    UniValue value;
    BOOST_CHECK(value.setNumStr(str));
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("-0.00000001")), UniValue);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000000")), 0LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001")), 1LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.17622195")), 17622195LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.5")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.50000000")), 50000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.89898989")), 89898989LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1.00000000")), 100000000LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.9999999")), 2099999999999990LL);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("20999999.99999999")), 2099999999999999LL);

    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("1e-8")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.1e-7")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.01e-6")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.0000000000000000000000000000000000000000000000000000000000000000000000000001e+68")), COIN/100000000);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("10000000000000000000000000000000000000000000000000000000000000000e-64")), COIN);
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000e64")), COIN);

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e-9")), UniValue); //should fail
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("0.000000019")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.00000001000000")), 1LL); //should pass, cut trailing 0
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("19e-9")), UniValue); //should fail
    BOOST_CHECK_EQUAL(AmountFromValue(ValueFromString("0.19e-6")), 19); //should pass, leading 0 is present

    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("92233720368.54775808")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e+11")), UniValue); //overflow error
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("1e11")), UniValue); //overflow error signless
    BOOST_CHECK_THROW(AmountFromValue(ValueFromString("93e+9")), UniValue); //overflow error
}

BOOST_AUTO_TEST_CASE(json_parse_errors)
{
    // Valid
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0").get_real(), 1.0);
    // Valid, with leading or trailing whitespace
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue(" 1.0").get_real(), 1.0);
    BOOST_CHECK_EQUAL(ParseNonRFCJSONValue("1.0 ").get_real(), 1.0);

    BOOST_CHECK_THROW(AmountFromValue(ParseNonRFCJSONValue(".19e-6")), std::runtime_error); //should fail, missing leading 0, therefore invalid JSON
    BOOST_CHECK_EQUAL(AmountFromValue(ParseNonRFCJSONValue("0.00000000000000000000000000000000000001e+30 ")), 1);
    // Invalid, initial garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("[1.0"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("a1.0"), std::runtime_error);
    // Invalid, trailing garbage
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0sds"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("1.0]"), std::runtime_error);
    // BTC addresses should fail parsing
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("175tWpb8K1S7NmH4Zx6rewF9WQrcZv245W"), std::runtime_error);
    BOOST_CHECK_THROW(ParseNonRFCJSONValue("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(rpc_ban)
{
    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.0:8334")), std::runtime_error); //portnumber for setban not allowed
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    UniValue ar = r.get_array();
    UniValue o1 = ar[0].get_obj();
    UniValue adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/32");
    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 9907731200 true")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    UniValue banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    BOOST_CHECK_EQUAL(banned_until.get_int64(), 9907731200); // absolute time check

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/24 add 200")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    banned_until = find_value(o1, "banned_until");
    BOOST_CHECK_EQUAL(adr.get_str(), "127.0.0.0/24");
    int64_t now = GetTime();
    BOOST_CHECK(banned_until.get_int64() > now);
    BOOST_CHECK(banned_until.get_int64()-now <= 200);

    // must throw an exception because 127.0.0.1 is in already banned subnet range
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.0.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("setban 127.0.0.0/24 remove")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0);

    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 127.0.0.0/255.255.0.0 add")));
    BOOST_CHECK_THROW(r = CallRPC(std::string("setban 127.0.1.1 add")), std::runtime_error);

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    BOOST_CHECK_EQUAL(ar.size(), 0);

    BOOST_CHECK_THROW(r = CallRPC(std::string("setban test add")), std::runtime_error); //invalid IP

    //IPv6 tests
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban FE80:0000:0000:0000:0202:B3FF:FE1E:8329 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "fe80::202:b3ff:fe1e:8329/128");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:db8::/ffff:fffc:0:0:0:0:0:0 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:db8::/30");

    BOOST_CHECK_NO_THROW(CallRPC(std::string("clearbanned")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("setban 2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128 add")));
    BOOST_CHECK_NO_THROW(r = CallRPC(std::string("listbanned")));
    ar = r.get_array();
    o1 = ar[0].get_obj();
    adr = find_value(o1, "address");
    BOOST_CHECK_EQUAL(adr.get_str(), "2001:4d48:ac57:400:cacf:e9ff:fe1d:9c63/128");
}

BOOST_AUTO_TEST_CASE(rpc_getblockstats_calculate_percentiles_by_weight)
{
    // Ported verbatim from Core v0.19 (src/test/rpc_tests.cpp).
    int64_t total_weight = 200;
    std::vector<std::pair<CAmount, int64_t>> feerates;
    CAmount result[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(std::make_pair(1 ,1));
    }

    for (int64_t i = 0; i < 100; i++) {
        feerates.emplace_back(std::make_pair(2 ,1));
    }

    CalculatePercentilesByWeight(result, feerates, total_weight);
    BOOST_CHECK_EQUAL(result[0], 1);
    BOOST_CHECK_EQUAL(result[1], 1);
    BOOST_CHECK_EQUAL(result[2], 1);
    BOOST_CHECK_EQUAL(result[3], 2);
    BOOST_CHECK_EQUAL(result[4], 2);

    // Test with more pairs, and two pairs overlapping 2 percentiles.
    total_weight = 100;
    CAmount result2[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(std::make_pair(1, 9));
    feerates.emplace_back(std::make_pair(2 , 16)); //10th + 25th percentile
    feerates.emplace_back(std::make_pair(4 ,50)); //50th + 75th percentile
    feerates.emplace_back(std::make_pair(5 ,10));
    feerates.emplace_back(std::make_pair(9 ,15));  // 90th percentile

    CalculatePercentilesByWeight(result2, feerates, total_weight);

    BOOST_CHECK_EQUAL(result2[0], 2);
    BOOST_CHECK_EQUAL(result2[1], 2);
    BOOST_CHECK_EQUAL(result2[2], 4);
    BOOST_CHECK_EQUAL(result2[3], 4);
    BOOST_CHECK_EQUAL(result2[4], 9);

    // Same test as above, but one of the percentile-overlapping pairs is split in 2.
    total_weight = 100;
    CAmount result3[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(std::make_pair(1, 9));
    feerates.emplace_back(std::make_pair(2 , 11)); // 10th percentile
    feerates.emplace_back(std::make_pair(2 , 5)); // 25th percentile
    feerates.emplace_back(std::make_pair(4 ,50)); //50th + 75th percentile
    feerates.emplace_back(std::make_pair(5 ,10));
    feerates.emplace_back(std::make_pair(9 ,15)); // 90th percentile

    CalculatePercentilesByWeight(result3, feerates, total_weight);

    BOOST_CHECK_EQUAL(result3[0], 2);
    BOOST_CHECK_EQUAL(result3[1], 2);
    BOOST_CHECK_EQUAL(result3[2], 4);
    BOOST_CHECK_EQUAL(result3[3], 4);
    BOOST_CHECK_EQUAL(result3[4], 9);

    // Test with one transaction spanning all percentiles.
    total_weight = 104;
    CAmount result4[NUM_GETBLOCKSTATS_PERCENTILES] = { 0 };
    feerates.clear();

    feerates.emplace_back(std::make_pair(1, 100));
    feerates.emplace_back(std::make_pair(2, 1));
    feerates.emplace_back(std::make_pair(3, 1));
    feerates.emplace_back(std::make_pair(3, 1));
    feerates.emplace_back(std::make_pair(999999, 1));

    CalculatePercentilesByWeight(result4, feerates, total_weight);

    for (int64_t i = 0; i < NUM_GETBLOCKSTATS_PERCENTILES; i++) {
        BOOST_CHECK_EQUAL(result4[i], 1);
    }
}

// Explorer RPC batch (v0.2.13 item 4). A FreeBank unit test cannot connect a
// block (TEST_BASELINE.md C2b), so the fee arithmetic is tested on a synthetic
// tx + undo record and the RPCs on the genesis-only chain; the per-block
// numbers are the integration gate's job.
static CMutableTransaction SpendOf(const std::vector<CAmount>& vOut)
{
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.vin.resize(2);
    mtx.vin[0].prevout = COutPoint(uint256S("01"), 0);
    mtx.vin[1].prevout = COutPoint(uint256S("02"), 1);
    for (CAmount n : vOut)
        mtx.vout.emplace_back(n, CScript() << OP_TRUE);
    return mtx;
}

static CTxUndo UndoOf(const std::vector<CAmount>& vIn)
{
    CTxUndo undo;
    for (CAmount n : vIn)
        undo.vprevout.emplace_back(CTxOut(n, CScript() << OP_TRUE), 5, false, false, false, 0);
    return undo;
}

BOOST_AUTO_TEST_CASE(rpc_txfeefromundo)
{
    CAmount fee = -1;
    // in 3 BTX, out 2.999 BTX -> fee 0.001 BTX
    BOOST_CHECK(TxFeeFromUndo(CTransaction(SpendOf({2 * COIN, 99900000})), UndoOf({COIN, 2 * COIN}), fee));
    BOOST_CHECK_EQUAL(fee, 100000);
    // zero fee is a fee
    BOOST_CHECK(TxFeeFromUndo(CTransaction(SpendOf({3 * COIN})), UndoOf({COIN, 2 * COIN}), fee));
    BOOST_CHECK_EQUAL(fee, 0);
    // undo record does not match the tx's inputs: refused, no assert
    BOOST_CHECK(!TxFeeFromUndo(CTransaction(SpendOf({COIN})), UndoOf({COIN}), fee));
    // outputs exceed inputs (negative fee): refused, no assert
    BOOST_CHECK(!TxFeeFromUndo(CTransaction(SpendOf({4 * COIN})), UndoOf({COIN, 2 * COIN}), fee));
    // an input value outside MoneyRange: refused, no assert
    BOOST_CHECK(!TxFeeFromUndo(CTransaction(SpendOf({COIN})), UndoOf({MAX_MONEY, MAX_MONEY}), fee));
    // coinbase has no fee
    CMutableTransaction cb;
    cb.vin.resize(1);
    cb.vin[0].prevout.SetNull();
    cb.vout.emplace_back(0, CScript() << OP_TRUE);
    BOOST_CHECK(!TxFeeFromUndo(CTransaction(cb), CTxUndo(), fee));
}

BOOST_AUTO_TEST_CASE(rpc_txtouniv_weight_and_credit)
{
    // Plain v3 tx: weight present and exact, no credit object.
    const CTransaction plain(SpendOf({COIN}));
    UniValue u(UniValue::VOBJ);
    TxToUniv(plain, uint256(), u);
    BOOST_CHECK_EQUAL(find_value(u, "weight").get_int64(), GetTransactionWeight(plain));
    BOOST_CHECK_EQUAL(find_value(u, "vsize").get_int64(), (GetTransactionWeight(plain) + 3) / 4);
    BOOST_CHECK(find_value(u, "credit").isNull());

    // A v13 note mint: family/op/op_name/payload_hex, and the trailer is in the weight.
    CMutableTransaction mtx = SpendOf({1000});
    mtx.nVersion = TRANSACTION_NOTE_VERSION;
    mtx.nNoteOp = NOTE_OP_MINT;
    mtx.vchNotePayload = ParseHex("deadbeef00");
    const CTransaction note(mtx);
    UniValue n(UniValue::VOBJ);
    TxToUniv(note, uint256(), n);
    const UniValue& credit = find_value(n, "credit");
    BOOST_CHECK_EQUAL(find_value(credit, "family").get_str(), "note");
    BOOST_CHECK_EQUAL(find_value(credit, "op").get_int(), NOTE_OP_MINT);
    BOOST_CHECK_EQUAL(find_value(credit, "op_name").get_str(), "mint");
    BOOST_CHECK_EQUAL(find_value(credit, "payload_hex").get_str(), "deadbeef00");
    BOOST_CHECK_EQUAL(find_value(n, "weight").get_int64(), GetTransactionWeight(note));
    BOOST_CHECK_EQUAL(find_value(n, "weight").get_int64(), 4 * (int64_t)::GetSerializeSize(note, SER_NETWORK, PROTOCOL_VERSION));

    // An op byte the headers do not define.
    mtx.nNoteOp = 200;
    UniValue x(UniValue::VOBJ);
    TxToUniv(CTransaction(mtx), uint256(), x);
    BOOST_CHECK_EQUAL(find_value(find_value(x, "credit"), "op_name").get_str(), "op_200");

    // Every family and every defined op has a name (names match the explorer's parser).
    BOOST_CHECK(CreditFamilyName(3) == nullptr);
    BOOST_CHECK(CreditFamilyName(TRANSACTION_BITASSET_CREATE_VERSION) == nullptr);
    BOOST_CHECK_EQUAL(CreditFamilyName(TRANSACTION_BILL_VERSION), std::string("bill"));
    BOOST_CHECK_EQUAL(CreditFamilyName(TRANSACTION_ORACLE_VERSION), std::string("oracle"));
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_BILL_VERSION, BILL_OP_HCLAIM), "hclaim");
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_HOUSE_VERSION, HOUSE_OP_RELEASE), "release");
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_NOTE_VERSION, NOTE_OP_PROTEST), "protest");
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_DEPOSIT_VERSION, DEPOSIT_OP_CLAIM), "claim");
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_POOL_VERSION, POOL_OP_ADD_LIQ), "add_liq");
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_SETTLE_VERSION, SETTLE_OP_EXCHANGE), "exchange");
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_SETTLE_VERSION, 2), "op_2"); // PRESENT is reserved
    BOOST_CHECK_EQUAL(CreditOpName(TRANSACTION_ORACLE_VERSION, ORACLE_OP_SUBMIT), "submit");
    const std::vector<std::pair<int, int>> vLastOp = {
        {TRANSACTION_BILL_VERSION, BILL_OP_HCLAIM}, {TRANSACTION_HOUSE_VERSION, HOUSE_OP_RELEASE},
        {TRANSACTION_NOTE_VERSION, NOTE_OP_PROTEST}, {TRANSACTION_DEPOSIT_VERSION, DEPOSIT_OP_CLAIM},
        {TRANSACTION_POOL_VERSION, POOL_OP_RETIRE}, {TRANSACTION_SETTLE_VERSION, SETTLE_OP_EXCHANGE},
        {TRANSACTION_ORACLE_VERSION, ORACLE_OP_SUBMIT}};
    for (const auto& fam : vLastOp) {
        for (int op = 1; op <= fam.second; op++)
            BOOST_CHECK_MESSAGE(CreditOpName(fam.first, op).compare(0, 3, "op_") != 0,
                strprintf("v%d op %d has no name", fam.first, op));
        BOOST_CHECK_EQUAL(CreditOpName(fam.first, fam.second + 1).compare(0, 3, "op_"), 0);
    }
}

BOOST_AUTO_TEST_CASE(rpc_mempoolentry_core017_fields)
{
    TestMemPoolEntryHelper entry;
    const CTransaction tx(SpendOf({COIN}));
    {
        LOCK(mempool.cs);
        mempool.addUnchecked(tx.GetHash(), entry.Fee(12345).FromTx(tx));
    }
    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC("getmempoolentry " + tx.GetHash().GetHex()));
    const UniValue& fees = find_value(r, "fees");
    BOOST_CHECK_EQUAL(fees["base"].getValStr(), "0.00012345");
    BOOST_CHECK_EQUAL(fees["modified"].getValStr(), "0.00012345");
    BOOST_CHECK_EQUAL(fees["ancestor"].getValStr(), "0.00012345");   // coins, not the legacy sats
    BOOST_CHECK_EQUAL(fees["descendant"].getValStr(), "0.00012345");
    BOOST_CHECK_EQUAL(find_value(r, "ancestorfees").get_int64(), 12345); // legacy field unchanged
    BOOST_CHECK_EQUAL(find_value(r, "weight").get_int64(), GetTransactionWeight(tx));
    BOOST_CHECK_EQUAL(find_value(r, "vsize").get_int64(), find_value(r, "size").get_int64());
    BOOST_CHECK_NO_THROW(r = CallRPC("getrawmempool true"));
    BOOST_CHECK(!find_value(find_value(r, tx.GetHash().GetHex()), "fees").isNull());
    BOOST_CHECK_NO_THROW(r = CallRPC("getmempoolinfo"));
    BOOST_CHECK_EQUAL(find_value(r, "total_fee").getValStr(), "0.00012345");
    mempool.clear();
    BOOST_CHECK_NO_THROW(r = CallRPC("getmempoolinfo"));
    BOOST_CHECK_EQUAL(find_value(r, "total_fee").getValStr(), "0.00000000");
}

BOOST_AUTO_TEST_CASE(rpc_getblockstats_genesis_and_args)
{
    // Genesis is connected with no undo data; Core v0.19 threw here.
    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC("getblockstats 0"));
    BOOST_CHECK_EQUAL(find_value(r, "height").get_int(), 0);
    BOOST_CHECK_EQUAL(find_value(r, "txs").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(r, "ins").get_int(), 0);
    BOOST_CHECK_EQUAL(find_value(r, "totalfee").get_int64(), 0);
    BOOST_CHECK_EQUAL(find_value(r, "subsidy").get_int64(), 0);
    BOOST_CHECK_EQUAL(find_value(r, "feerate_percentiles").size(), (size_t)NUM_GETBLOCKSTATS_PERCENTILES);
    const std::string genesis = chainActive.Genesis()->GetBlockHash().GetHex();
    BOOST_CHECK_NO_THROW(r = CallRPC("getblockstats \"" + genesis + "\""));
    BOOST_CHECK_EQUAL(find_value(r, "blockhash").get_str(), genesis);
    BOOST_CHECK_NO_THROW(r = CallRPC("getblockstats 0 [\"txs\",\"height\"]"));
    BOOST_CHECK_EQUAL(r.size(), 2U);
    // Core's error messages (the M5 acceptance gate checks them exactly)
    BOOST_CHECK_EQUAL(RPCErrorMessage("getblockstats 0 [\"nosuchstat\"]"), "Invalid selected statistic nosuchstat");
    BOOST_CHECK_EQUAL(RPCErrorMessage("getblockstats 0 [\"txs\",\"nosuchstat\"]"), "Invalid selected statistic nosuchstat");
    BOOST_CHECK_EQUAL(RPCErrorMessage("getblockstats 1"), "Target block height 1 after current tip 0");
    BOOST_CHECK_EQUAL(RPCErrorMessage("getblockstats -1"), "Target block height -1 is negative");
    BOOST_CHECK_EQUAL(RPCErrorMessage("getblockstats \"" + std::string(64, '0') + "\""), "Block not found");
    BOOST_CHECK_THROW(CallRPC("getblockstats"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getblockstats 0 [\"txs\"] 3"), std::runtime_error);
    BOOST_CHECK_THROW(CallRPC("getblockstats 0 \"txs\""), std::runtime_error);
}

// A stale block (not in the active chain) is not refused for being stale (M5
// spec §1, operator agreed): Core v0.17's "Block is not in chain" check is not
// ported. A header-only fake index gets past the lookup and fails on the
// missing block data instead.
BOOST_AUTO_TEST_CASE(rpc_getblockstats_stale_block_not_refused)
{
    const uint256 hashFake = uint256S("00000000000000000000000000000000000000000000000000000000000000fb");
    CBlockIndex* pindexFake = new CBlockIndex();
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hashFake, pindexFake)).first;
        pindexFake->phashBlock = &mi->first;
        pindexFake->pprev = chainActive.Genesis();
        pindexFake->nHeight = 1;
        BOOST_CHECK(!chainActive.Contains(pindexFake));
    }
    BOOST_CHECK_EQUAL(RPCErrorMessage("getblockstats \"" + hashFake.GetHex() + "\""), "Block not found on disk");
    {
        LOCK(cs_main);
        mapBlockIndex.erase(hashFake);
    }
    delete pindexFake;
}

BOOST_AUTO_TEST_CASE(rpc_ntx_blockfee_indexinfo)
{
    const std::string genesis = chainActive.Genesis()->GetBlockHash().GetHex();
    UniValue r;
    BOOST_CHECK_NO_THROW(r = CallRPC("getblockheader " + genesis));
    BOOST_CHECK_EQUAL(find_value(r, "nTx").get_int(), 1);
    BOOST_CHECK_NO_THROW(r = CallRPC("getblock " + genesis + " 2"));
    BOOST_CHECK_EQUAL(find_value(r, "nTx").get_int(), 1);
    const UniValue& cb = find_value(r, "tx")[0];
    BOOST_CHECK(find_value(cb, "fee").isNull());          // coinbase: never a fee
    BOOST_CHECK(!find_value(cb, "weight").isNull());

    const bool fTxIndexWas = fTxIndex;
    fTxIndex = false;
    BOOST_CHECK_NO_THROW(r = CallRPC("getindexinfo"));
    BOOST_CHECK_EQUAL(r.size(), 0U);
    fTxIndex = true;
    BOOST_CHECK_NO_THROW(r = CallRPC("getindexinfo"));
    BOOST_CHECK(find_value(find_value(r, "txindex"), "synced").get_bool());
    BOOST_CHECK_EQUAL(find_value(find_value(r, "txindex"), "best_block_height").get_int(), chainActive.Height());
    BOOST_CHECK_NO_THROW(r = CallRPC("getindexinfo txindex"));
    BOOST_CHECK_EQUAL(r.size(), 1U);
    BOOST_CHECK_NO_THROW(r = CallRPC("getindexinfo coinstatsindex"));
    BOOST_CHECK_EQUAL(r.size(), 0U);
    fTxIndex = fTxIndexWas;
}

BOOST_AUTO_TEST_SUITE_END()

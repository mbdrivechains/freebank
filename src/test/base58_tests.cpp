// Copyright (c) 2011-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>

#include <test/data/base58_encode_decode.json.h>
#include <test/data/base58_keys_invalid.json.h>
#include <test/data/base58_keys_valid.json.h>

#include <key.h>
#include <script/script.h>
#include <test/test_bitcoin.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>

#include <univalue.h>

#include <boost/test/unit_test.hpp>


extern UniValue read_json(const std::string& jsondata);

extern bool g_fMainchainMainFamily;   // defined in base58.cpp (A9); file scope, outside the suite namespace

BOOST_FIXTURE_TEST_SUITE(base58_tests, BasicTestingSetup)

// A9: mainchain (withdrawal-destination) P2PKH decoding follows the L1 family
// observed at init - signet/testnet family -> prefix 111 (m.../n...), main
// family (forknet / mainnet) -> prefix 0 (1...). This prefix feeds bundle
// build/validate, so both directions are pinned here.
BOOST_AUTO_TEST_CASE(base58_mainchain_prefix_follows_l1_family)
{
    std::vector<unsigned char> hash(20, 0x42);
    std::vector<unsigned char> v111(1, 111); v111.insert(v111.end(), hash.begin(), hash.end());
    std::vector<unsigned char> v0(1, 0);     v0.insert(v0.end(), hash.begin(), hash.end());
    const std::string addr111 = EncodeBase58Check(v111);
    const std::string addr0 = EncodeBase58Check(v0);

    // The regtest branch (MAINCHAIN_REGTEST_PUBKEY_ADDRESS) must not mask the
    // family switch: pin -regtest off for this case and restore it after.
    const std::string strRegtestSaved = gArgs.GetArg("-regtest", "");
    gArgs.ForceSetArg("-regtest", "0");
    const bool fSaved = g_fMainchainMainFamily;

    g_fMainchainMainFamily = false;   // signet / testnet family: today's behaviour
    BOOST_CHECK(IsValidDestination(DecodeDestination(addr111, true)));
    BOOST_CHECK(!IsValidDestination(DecodeDestination(addr0, true)));

    g_fMainchainMainFamily = true;    // main family: alphanet / mainnet
    BOOST_CHECK(IsValidDestination(DecodeDestination(addr0, true)));
    BOOST_CHECK(!IsValidDestination(DecodeDestination(addr111, true)));

    // Sidechain (non-mainchain) decoding is untouched by the family flag.
    BOOST_CHECK(!IsValidDestination(DecodeDestination(addr0, false)));

    g_fMainchainMainFamily = fSaved;
    // GetBoolArg("-regtest", false) reads an absent arg as false, so "0" restores
    // the observable state exactly when it was unset before.
    gArgs.ForceSetArg("-regtest", strRegtestSaved.empty() ? "0" : strRegtestSaved);
}

// Goal: test low-level base58 encoding functionality
BOOST_AUTO_TEST_CASE(base58_EncodeBase58)
{
    UniValue tests = read_json(std::string(json_tests::base58_encode_decode, json_tests::base58_encode_decode + sizeof(json_tests::base58_encode_decode)));
    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 2) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::vector<unsigned char> sourcedata = ParseHex(test[0].get_str());
        std::string base58string = test[1].get_str();
        BOOST_CHECK_MESSAGE(
                    EncodeBase58(sourcedata.data(), sourcedata.data() + sourcedata.size()) == base58string,
                    strTest);
    }
}

// Goal: test low-level base58 decoding functionality
BOOST_AUTO_TEST_CASE(base58_DecodeBase58)
{
    UniValue tests = read_json(std::string(json_tests::base58_encode_decode, json_tests::base58_encode_decode + sizeof(json_tests::base58_encode_decode)));
    std::vector<unsigned char> result;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 2) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::vector<unsigned char> expected = ParseHex(test[0].get_str());
        std::string base58string = test[1].get_str();
        BOOST_CHECK_MESSAGE(DecodeBase58(base58string, result), strTest);
        BOOST_CHECK_MESSAGE(result.size() == expected.size() && std::equal(result.begin(), result.end(), expected.begin()), strTest);
    }

    BOOST_CHECK(!DecodeBase58("invalid", result));

    // check that DecodeBase58 skips whitespace, but still fails with unexpected non-whitespace at the end.
    BOOST_CHECK(!DecodeBase58(" \t\n\v\f\r skip \r\f\v\n\t a", result));
    BOOST_CHECK( DecodeBase58(" \t\n\v\f\r skip \r\f\v\n\t ", result));
    std::vector<unsigned char> expected = ParseHex("971a55");
    BOOST_CHECK_EQUAL_COLLECTIONS(result.begin(), result.end(), expected.begin(), expected.end());
}

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(base58_keys_valid_parse)
{
    UniValue tests = read_json(std::string(json_tests::base58_keys_valid, json_tests::base58_keys_valid + sizeof(json_tests::base58_keys_valid)));
    CBitcoinSecret secret;
    CTxDestination destination;
    SelectParams(CBaseChainParams::MAIN);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = find_value(metadata, "isPrivkey").get_bool();
        SelectParams(find_value(metadata, "chain").get_str());
        bool try_case_flip = find_value(metadata, "tryCaseFlip").isNull() ? false : find_value(metadata, "tryCaseFlip").get_bool();
        if (isPrivkey) {
            bool isCompressed = find_value(metadata, "isCompressed").get_bool();
            // Must be valid private key
            BOOST_CHECK_MESSAGE(secret.SetString(exp_base58string), "!SetString:"+ strTest);
            BOOST_CHECK_MESSAGE(secret.IsValid(), "!IsValid:" + strTest);
            CKey privkey = secret.GetKey();
            BOOST_CHECK_MESSAGE(privkey.IsCompressed() == isCompressed, "compressed mismatch:" + strTest);
            BOOST_CHECK_MESSAGE(privkey.size() == exp_payload.size() && std::equal(privkey.begin(), privkey.end(), exp_payload.begin()), "key mismatch:" + strTest);

            // Private key must be invalid public key
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid privkey as pubkey:" + strTest);
        } else {
            // Must be valid public key
            destination = DecodeDestination(exp_base58string);
            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            for (char& c : exp_base58string) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination) == try_case_flip, "!IsValid case flipped:" + strTest);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            secret.SetString(exp_base58string);
            BOOST_CHECK_MESSAGE(!secret.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(base58_keys_valid_gen)
{
    UniValue tests = read_json(std::string(json_tests::base58_keys_valid, json_tests::base58_keys_valid + sizeof(json_tests::base58_keys_valid)));

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = find_value(metadata, "isPrivkey").get_bool();
        SelectParams(find_value(metadata, "chain").get_str());
        if (isPrivkey) {
            bool isCompressed = find_value(metadata, "isCompressed").get_bool();
            CKey key;
            key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            assert(key.IsValid());
            CBitcoinSecret secret;
            secret.SetKey(key);
            BOOST_CHECK_MESSAGE(secret.ToString() == exp_base58string, "result mismatch: " + strTest);
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            ExtractDestination(exp_script, dest);
            std::string address = EncodeDestination(dest);

            BOOST_CHECK_EQUAL(address, exp_base58string);
        }
    }

    SelectParams(CBaseChainParams::MAIN);
}


// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(base58_keys_invalid)
{
    UniValue tests = read_json(std::string(json_tests::base58_keys_invalid, json_tests::base58_keys_invalid + sizeof(json_tests::base58_keys_invalid))); // Negative testcases
    CBitcoinSecret secret;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        UniValue test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (auto chain : { CBaseChainParams::MAIN, CBaseChainParams::REGTEST }) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            secret.SetString(exp_base58string);
            BOOST_CHECK_MESSAGE(!secret.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}


BOOST_AUTO_TEST_SUITE_END()

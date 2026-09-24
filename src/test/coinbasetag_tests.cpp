// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// -coinbasetag (v0.2.14): the block producer's name, pushed after the height and
// the extra nonce in the coinbase scriptSig of every block this node produces.
// The tag is policy, not consensus: these tests show that a tagged block passes
// the node's own validity checks with the BIP34 height rule live, and that the
// only coinbase-scriptSig rules are the height prefix and the 2..100-byte length.

#include "chain.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "miner.h"
#include "script/script.h"
#include "validation.h"

#include "test/test_bitcoin.h"

#include <limits>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

/** Sets COINBASE_FLAGS the way init does for one test, and restores it (the
 *  default is empty) so no other test sees a tag. */
struct CoinbaseTagScope {
    const CScript scriptSaved;
    CoinbaseTagScope() : scriptSaved(COINBASE_FLAGS) {}
    void Set(const std::string& strIn)
    {
        std::string strTag, strError;
        CScript scriptTag;
        BOOST_REQUIRE_MESSAGE(ParseCoinbaseTag(strIn, strTag, scriptTag, strError), strError);
        COINBASE_FLAGS = scriptTag;
    }
    ~CoinbaseTagScope() { COINBASE_FLAGS = scriptSaved; }
};

/** Makes the BIP34 height-in-coinbase rule live on the test's regtest params (it
 *  is at height 1 on main, but far in the future on regtest) for one test. */
struct BIP34Scope {
    Consensus::Params& consensus;
    const int nSaved;
    BIP34Scope()
        : consensus(const_cast<Consensus::Params&>(Params().GetConsensus())),
          nSaved(consensus.BIP34Height)
    {
        consensus.BIP34Height = 1; // as on main
    }
    ~BIP34Scope() { consensus.BIP34Height = nSaved; }
};

std::vector<unsigned char> Bytes(const std::string& str)
{
    return std::vector<unsigned char>(str.begin(), str.end());
}

/** A block this node produces on the current tip: the real BMM path
 *  (GenerateBMMBlock = CreateNewBlock + IncrementExtraNonce). */
CBlock ProduceBlock(const CScript& scriptPubKey)
{
    CBlock block;
    std::string strError;
    BOOST_REQUIRE_MESSAGE(BlockAssembler(Params()).GenerateBMMBlock(block, strError, nullptr,
        std::vector<CMutableTransaction>(), uint256(), scriptPubKey), strError);
    return block;
}

/** The block with its coinbase scriptSig replaced (and the merkle root redone). */
CBlock WithCoinbaseScriptSig(const CBlock& blockIn, const CScript& scriptSig)
{
    CBlock block(blockIn);
    CMutableTransaction txCoinbase(*block.vtx[0]);
    txCoinbase.vin[0].scriptSig = scriptSig;
    block.vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    block.hashMerkleRoot = BlockMerkleRoot(block);
    return block;
}

/** The node's own pre-connect validity check (as CreateNewBlock runs it): header
 *  context, CheckBlock (incl. CheckTransaction), ContextualCheckBlock (incl. the
 *  BIP34 height rule) and ConnectBlock(fJustCheck). BMM is not checked: a unit
 *  test has no mainchain. */
bool BlockIsValid(const CBlock& block, std::string& strReject)
{
    LOCK(cs_main);
    CValidationState state;
    const bool fValid = TestBlockValidity(state, Params(), block, chainActive.Tip(),
        true /* fCheckMerkleRoot */, false /* fCheckBMM */, false /* fReorg */);
    strReject = state.GetRejectReason();
    return fValid;
}

int NextHeight()
{
    LOCK(cs_main);
    return chainActive.Height() + 1;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(coinbasetag_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(coinbasetag_parse)
{
    std::string strTag, strError;
    CScript scriptTag;

    // The seed's tag: one direct push of its 15 bytes
    BOOST_CHECK(ParseCoinbaseTag("ecxfreebank.com", strTag, scriptTag, strError));
    BOOST_CHECK_EQUAL(strTag, "ecxfreebank.com");
    BOOST_CHECK(scriptTag == CScript() << Bytes("ecxfreebank.com"));
    BOOST_CHECK_EQUAL(scriptTag.size(), 16U);
    BOOST_CHECK_EQUAL(scriptTag[0], 15);

    // An eCash pool's tag as it stands, surrounding whitespace trimmed, inner
    // spaces kept
    BOOST_CHECK(ParseCoinbaseTag(" \t/eCPool.tech/\r\n", strTag, scriptTag, strError));
    BOOST_CHECK_EQUAL(strTag, "/eCPool.tech/");
    BOOST_CHECK(scriptTag == CScript() << Bytes("/eCPool.tech/"));
    BOOST_CHECK(ParseCoinbaseTag("Free Bank", strTag, scriptTag, strError));
    BOOST_CHECK_EQUAL(strTag, "Free Bank");

    // One byte, and exactly the 64-byte cap
    BOOST_CHECK(ParseCoinbaseTag("x", strTag, scriptTag, strError));
    BOOST_CHECK(scriptTag == CScript() << Bytes("x"));
    const std::string str64(MAX_COINBASE_TAG_BYTES, 'a');
    BOOST_CHECK_EQUAL(str64.size(), 64U);
    BOOST_CHECK(ParseCoinbaseTag(str64, strTag, scriptTag, strError));
    BOOST_CHECK_EQUAL(scriptTag.size(), 65U);

    // Every printable ASCII byte, 0x20 (space, inside the tag) to 0x7e
    std::string strPrintable;
    for (int c = 0x20; c <= 0x7e; c++)
        strPrintable.push_back((char)c);
    for (size_t i = 0; i < strPrintable.size(); i += 32) {
        const std::string strChunk = "<" + strPrintable.substr(i, 32) + ">";
        BOOST_CHECK_MESSAGE(ParseCoinbaseTag(strChunk, strTag, scriptTag, strError), strChunk);
        BOOST_CHECK_EQUAL(strTag, strChunk);
    }

    // Refused, with the outputs left untouched
    const std::string strSentinel = "unchanged";
    const CScript scriptSentinel = CScript() << OP_TRUE;
    auto Refused = [&](const std::string& strIn, const std::string& strWhy) {
        std::string strT = strSentinel, strE;
        CScript scriptT = scriptSentinel;
        const bool fOk = ParseCoinbaseTag(strIn, strT, scriptT, strE);
        BOOST_CHECK_MESSAGE(!fOk, "accepted: \"" << strIn << "\"");
        BOOST_CHECK_EQUAL(strT, strSentinel);
        BOOST_CHECK(scriptT == scriptSentinel);
        BOOST_CHECK_MESSAGE(strE.find(strWhy) != std::string::npos, "error \"" << strE << "\" lacks \"" << strWhy << "\"");
    };
    Refused("", "is empty");
    Refused("   ", "is empty");
    Refused(" \t\r\n", "is empty");
    Refused(std::string(MAX_COINBASE_TAG_BYTES + 1, 'a'), "65 bytes long; the limit is 64");
    Refused("  " + std::string(MAX_COINBASE_TAG_BYTES + 1, 'a') + "  ", "the limit is 64");
    Refused("tab\there", "printable ASCII (0x09 at position 4)");
    Refused("new\nline", "printable ASCII (0x0a");
    Refused(std::string("nul\0byte", 8), "printable ASCII (0x00");
    Refused("\x1f", "printable ASCII (0x1f");
    Refused("del\x7f", "printable ASCII (0x7f");
    Refused("caf\xc3\xa9", "printable ASCII (0xc3 at position 4)"); // UTF-8 "café"
}

BOOST_AUTO_TEST_CASE(coinbasetag_default_coinbase_unchanged)
{
    // No -coinbasetag: COINBASE_FLAGS is empty and the produced coinbase is
    // exactly v0.2.13's, height then extra nonce and nothing after
    BOOST_REQUIRE(COINBASE_FLAGS.empty());
    const int nHeight = NextHeight();
    const CBlock block = ProduceBlock(GetCoinbaseScript());
    BOOST_CHECK(block.vtx[0]->vin[0].scriptSig == (CScript() << nHeight << CScriptNum(1)));
    BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
}

BOOST_AUTO_TEST_CASE(coinbasetag_bmm_block_carries_tag)
{
    CoinbaseTagScope tag;
    tag.Set("ecxfreebank.com");
    BIP34Scope bip34;

    // The BMM path (CreateNewBlock builds <height> OP_0, IncrementExtraNonce then
    // rewrites it): height · extra nonce · the tag push
    const int nHeight = NextHeight();
    const CBlock block = ProduceBlock(GetCoinbaseScript());
    const CScript& scriptSig = block.vtx[0]->vin[0].scriptSig;
    BOOST_CHECK(scriptSig == (CScript() << nHeight << CScriptNum(1) << Bytes("ecxfreebank.com")));
    const std::vector<unsigned char> vTail(scriptSig.end() - 16, scriptSig.end());
    std::vector<unsigned char> vExpectTail = {15};
    for (unsigned char c : std::string("ecxfreebank.com")) vExpectTail.push_back(c);
    BOOST_CHECK(vTail == vExpectTail);

    // The merkle root, and so the h* the BMM request commits to on L1, covers the
    // tagged coinbase: the tag cannot change after the bid
    BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));

    // Consensus-neutral: the tagged block passes the node's own checks with the
    // BIP34 height rule live
    std::string strReject;
    BOOST_CHECK_MESSAGE(BlockIsValid(block, strReject), strReject);

    // Anything after the height is free: a tail of non-push garbage filling the
    // scriptSig to exactly 100 bytes is valid ...
    CScript scriptFull = CScript() << nHeight;
    while (scriptFull.size() < 100) scriptFull.push_back(0xff);
    BOOST_CHECK_MESSAGE(BlockIsValid(WithCoinbaseScriptSig(block, scriptFull), strReject), strReject);

    // ... while the only two rules bite, so the checks above are live: one byte
    // more is bad-cb-length, and a wrong height prefix is bad-cb-height
    CScript scriptLong = scriptFull;
    scriptLong.push_back(0xff);
    BOOST_CHECK(!BlockIsValid(WithCoinbaseScriptSig(block, scriptLong), strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-cb-length");
    const CScript scriptWrongHeight = CScript() << (nHeight + 1) << CScriptNum(1) << Bytes("ecxfreebank.com");
    BOOST_CHECK(!BlockIsValid(WithCoinbaseScriptSig(block, scriptWrongHeight), strReject));
    BOOST_CHECK_EQUAL(strReject, "bad-cb-height");
}

BOOST_AUTO_TEST_CASE(coinbasetag_scriptsig_bound)
{
    // The 64-byte cap keeps the worst-case scriptSig well inside 100 bytes: an
    // unsigned height and extra nonce are at most 1+5 bytes each
    BOOST_CHECK_EQUAL((CScript() << std::numeric_limits<unsigned int>::max()).size(), 6U);
    BOOST_CHECK_EQUAL((CScript() << CScriptNum(std::numeric_limits<unsigned int>::max())).size(), 6U);
    BOOST_CHECK_LE(6U + 6U + 1U + MAX_COINBASE_TAG_BYTES, 100U);

    // Through the real IncrementExtraNonce (whose assert would abort the suite):
    // the largest block height, the largest extra nonce and a 64-byte tag
    CoinbaseTagScope tag;
    tag.Set(std::string(MAX_COINBASE_TAG_BYTES, 'z'));
    CBlock block = ProduceBlock(GetCoinbaseScript());
    CBlockIndex indexPrev;
    indexPrev.nHeight = std::numeric_limits<int>::max() - 1;
    block.hashPrevBlock = uint256S("c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00");
    unsigned int nExtraNonce = 0;
    IncrementExtraNonce(&block, &indexPrev, nExtraNonce); // new prev block: the nonce restarts at 1
    BOOST_CHECK_EQUAL(nExtraNonce, 1U);
    nExtraNonce = std::numeric_limits<unsigned int>::max() - 1;
    IncrementExtraNonce(&block, &indexPrev, nExtraNonce); // same prev block: the nonce carries on
    BOOST_CHECK_EQUAL(nExtraNonce, std::numeric_limits<unsigned int>::max());

    const CScript& scriptSig = block.vtx[0]->vin[0].scriptSig;
    BOOST_CHECK(scriptSig == (CScript() << std::numeric_limits<int>::max()
                                        << CScriptNum(std::numeric_limits<unsigned int>::max())
                                        << Bytes(std::string(MAX_COINBASE_TAG_BYTES, 'z'))));
    BOOST_CHECK_EQUAL(scriptSig.size(), 5U + 6U + 65U);
    BOOST_CHECK_LE(scriptSig.size(), 100U);
    BOOST_CHECK(block.hashMerkleRoot == BlockMerkleRoot(block));
}

BOOST_AUTO_TEST_SUITE_END()

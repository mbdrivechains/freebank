// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Cashu token checks (cashu.h) against the Cashu specs' own test vectors: https://github.com/cashubtc/nuts,
// tests/00-tests.md (hash_to_curve) and tests/12-tests.md (hash_e, DLEQ), fetched 2026-10-08.

#include <cashu.h>

#include <test/test_bitcoin.h>
#include <utilstrencodings.h>

#include <string.h>

#include <boost/test/unit_test.hpp>

namespace {
CPubKey Pk(const std::string& hex) { std::vector<unsigned char> v = ParseHex(hex); return CPubKey(v.begin(), v.end()); }
CashuScalar Sc(const std::string& hex)
{
    std::vector<unsigned char> v = ParseHex(hex);
    BOOST_REQUIRE_EQUAL(v.size(), 32U);
    CashuScalar s;
    memcpy(s.data(), v.data(), 32);
    return s;
}
std::string Hex(const CPubKey& p) { return HexStr(p.begin(), p.end()); }
CashuScalar Flip(CashuScalar s) { s[31] ^= 1; return s; }
} // namespace

BOOST_FIXTURE_TEST_SUITE(cashu_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hash_to_curve_vectors)
{
    // NUT-00 test vectors: the message is raw bytes (given in hex).
    const char* vectors[][2] = {
        {"0000000000000000000000000000000000000000000000000000000000000000",
         "024cce997d3b518f739663b757deaec95bcd9473c30a14ac2fd04023a739d1a725"},
        {"0000000000000000000000000000000000000000000000000000000000000001",
         "022e7158e11c9506f1aa4248bf531298daa7febd6194f003edcd9b93ade6253acf"},
        {"0000000000000000000000000000000000000000000000000000000000000002",   // takes a few counter steps
         "026cdbe15362df59cd1dd3c9c11de8aedac2106eca69236ecd9fbe117af897be4f"},
    };
    for (const auto& v : vectors) {
        CPubKey Y;
        BOOST_REQUIRE(CashuHashToCurve(ParseHex(v[0]), Y));
        BOOST_CHECK_EQUAL(Hex(Y), v[1]);
    }
}

BOOST_AUTO_TEST_CASE(hash_e_vector)
{
    const CPubKey one = Pk("020000000000000000000000000000000000000000000000000000000000000001");
    const CPubKey C_ = Pk("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
    CashuScalar e;
    BOOST_REQUIRE(CashuHashE({one, one, one, C_}, e));
    BOOST_CHECK_EQUAL(HexStr(e.begin(), e.end()), "a4dc034b74338c28c6bc3ea49731f2a24440fc7c4affc08b31a93fc9fbe6401e");
}

BOOST_AUTO_TEST_CASE(dleq_on_blind_signature)
{
    // The deterministic-nonce vector (a = 2): its (e, s) MUST verify.
    {
        const CPubKey A = Pk("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5");
        const CPubKey B_ = Pk("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
        const CPubKey C_ = Pk("0244eccfc7a348274458bb38044c7f3c389b3c2086c7ec18b5812d2877ab937787");
        const CashuScalar e = Sc("2a16ffee280aff3c429045607f9b8e0bf8b35910c44c1b20b9dfaf01b263d7b3");
        const CashuScalar s = Sc("9df27731238334718d120d4f74611a7c668233f988e687ac3fb188f0a34a2dab");
        BOOST_CHECK(CashuVerifyDLEQ(A, B_, C_, e, s));
        BOOST_CHECK(!CashuVerifyDLEQ(A, B_, C_, Flip(e), s));
        BOOST_CHECK(!CashuVerifyDLEQ(A, B_, C_, e, Flip(s)));
        BOOST_CHECK(!CashuVerifyDLEQ(A, C_, B_, e, s));             // B_ and C_ swapped
    }
    // A BlindSignature with a valid DLEQ (A = G, so C_ = B_).
    {
        const CPubKey A = Pk("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        const CPubKey B_ = Pk("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
        const CPubKey C_ = Pk("02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2");
        const CashuScalar e = Sc("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73d9");
        const CashuScalar s = Sc("9818e061ee51d5c8edc3342369a554998ff7b4381c8652d724cdf46429be73da");
        BOOST_CHECK(CashuVerifyDLEQ(A, B_, C_, e, s));
        BOOST_CHECK(!CashuVerifyDLEQ(A, B_, C_, s, s));
    }
}

BOOST_AUTO_TEST_CASE(dleq_on_proof)
{
    // A Proof (a token as a holder passes it on) with a valid DLEQ; the secret is hashed as its UTF-8 string.
    const CPubKey A = Pk("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const std::string secret = "daf4dd00a2b68a0858a80450f52c8a7d2ccf87d375e43e216e0c571f089f63e9";
    const std::vector<unsigned char> vSecret(secret.begin(), secret.end());
    const CPubKey C = Pk("024369d2d22a80ecf78f3937da9d5f30c1b9f74f0c32684d583cca0fa6a61cdcfc");
    const CashuScalar e = Sc("b31e58ac6527f34975ffab13e70a48b6d2b0d35abc4b03f0151f09ee1a9763d4");
    const CashuScalar s = Sc("8fbae004c59e754d71df67e392b6ae4e29293113ddc2ec86592a0431d16306d8");
    const CashuScalar r = Sc("a6d13fcd7a18442e6076f5e1e7c887ad5de40a019824bdfa9fe740d302e8d861");
    BOOST_CHECK(CashuVerifyProof(A, vSecret, C, e, s, r));

    // Anything else fails: another secret, the secret's decoded bytes, a wrong r/e/s, another mint key.
    std::vector<unsigned char> vOther = vSecret;
    vOther[0] ^= 1;
    BOOST_CHECK(!CashuVerifyProof(A, vOther, C, e, s, r));
    BOOST_CHECK(!CashuVerifyProof(A, ParseHex(secret), C, e, s, r));
    BOOST_CHECK(!CashuVerifyProof(A, vSecret, C, e, s, Flip(r)));
    BOOST_CHECK(!CashuVerifyProof(A, vSecret, C, Flip(e), s, r));
    BOOST_CHECK(!CashuVerifyProof(A, vSecret, C, e, Flip(s), r));
    BOOST_CHECK(!CashuVerifyProof(Pk("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
                                  vSecret, C, e, s, r));

    // Scalars out of range (0, and the curve order n) are refused, never wrapped.
    CashuScalar zero{};
    BOOST_CHECK(!CashuVerifyProof(A, vSecret, C, e, zero, r));
    BOOST_CHECK(!CashuVerifyProof(A, vSecret, C, e, s, Sc("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")));
}

BOOST_AUTO_TEST_SUITE_END()

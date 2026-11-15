// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license.

// A5 strict payload-signature canonicality (SECURITY_GATE_SIGNOFF_A5.md).
//
// Every FreeBank consensus op authenticates its payload with a raw ECDSA
// signature committed by the txid (the version-tagged trailer sits outside
// the witness carve-out). Legacy CPubKey::Verify tolerates two re-encodings
// of any valid signature - a high-S flip and non-minimal DER padding - so a
// relayer holding no key could shift an unconfirmed op's txid. VerifyStrict
// (= CheckStrictDER && CheckLowS && Verify) admits exactly one byte-string
// per (key, message).
//
// This file proves the choke-point: both malleations of a canonical sig are
// byte-distinct, STILL ACCEPTED by legacy Verify (the documented exposure),
// and refused by VerifyStrict - each by its own axis. The per-family red
// tests (a malleated op refused by the family's contextual check) live in
// the family test files next to their existing bad-sig cases.

#include <key.h>
#include <pubkey.h>
#include <script/sigcache.h>
#include <validation.h>
#include <test/strictsig_util.h>
#include <test/test_bitcoin.h>
#include <uint256.h>
#include <utiltime.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(a5_strictsig_tests, BasicTestingSetup)

static CKey DetKey(unsigned char seed)
{
    std::vector<unsigned char> vch(32, seed);
    CKey key;
    key.Set(vch.begin(), vch.end(), true);
    return key;
}

BOOST_AUTO_TEST_CASE(a5_choke_point_axes)
{
    // Several (key, message) pairs so the result does not hinge on one
    // signature's accidental byte shape.
    for (unsigned char i = 1; i <= 8; i++) {
        const CKey key = DetKey(i);
        const CPubKey pub = key.GetPubKey();
        uint256 hash;
        *hash.begin() = i; // distinct message per iteration

        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(hash, sig));

        // Positive regression: the wallet's own canonical sig passes strict.
        BOOST_CHECK(pub.Verify(hash, sig));
        BOOST_CHECK(CPubKey::CheckStrictDER(sig));
        BOOST_CHECK(CPubKey::CheckLowS(sig));
        BOOST_CHECK(pub.VerifyStrict(hash, sig));

        // (A) high-S flip: byte-distinct, legacy-accepted, strict-refused on
        // the low-S axis alone (the encoding stays minimal DER).
        const std::vector<unsigned char> flip = A5HighSFlip(sig);
        BOOST_CHECK(flip != sig);
        BOOST_CHECK(pub.Verify(hash, flip));
        BOOST_CHECK(CPubKey::CheckStrictDER(flip));
        BOOST_CHECK(!CPubKey::CheckLowS(flip));
        BOOST_CHECK(!pub.VerifyStrict(hash, flip));

        // (B) DER padding: byte-distinct, legacy-accepted, strict-refused on
        // the encoding axis alone (S is untouched, so still low).
        const std::vector<unsigned char> pad = A5DerPad(sig);
        BOOST_CHECK(pad != sig);
        BOOST_CHECK(pad.size() <= 72); // refused for minimality, not size
        BOOST_CHECK(pub.Verify(hash, pad));
        BOOST_CHECK(!CPubKey::CheckStrictDER(pad));
        BOOST_CHECK(CPubKey::CheckLowS(pad));
        BOOST_CHECK(!pub.VerifyStrict(hash, pad));
    }
}

BOOST_AUTO_TEST_CASE(a5_bounds)
{
    const CKey key = DetKey(42);
    const CPubKey pub = key.GetPubKey();
    uint256 hash;
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));

    // Truncated / oversized / empty forms never reach Verify.
    BOOST_CHECK(!pub.VerifyStrict(hash, std::vector<unsigned char>()));
    BOOST_CHECK(!pub.VerifyStrict(hash, std::vector<unsigned char>(7, 0x30)));
    std::vector<unsigned char> big = sig;
    big.resize(73, 0x00);
    BOOST_CHECK(!pub.VerifyStrict(hash, big));

    // A wrong-key strict-canonical sig still fails on the verify axis.
    const CKey other = DetKey(43);
    BOOST_CHECK(!other.GetPubKey().VerifyStrict(hash, sig));
}

// UR3-4 (ultra s3 #4): FbVerifyStrict is every payload site's check. Outside an FbSigCacheScope it is VerifyStrict;
// inside one (ATMP, the mempool sweeps) it gives the same answer for every input, the encoding axes are checked before
// the cache is read (so a high-S or padded form can't ride a cached entry, even one planted directly), and only a
// signature that verified is cached.
BOOST_AUTO_TEST_CASE(ur3_4_fbverifystrict_matches_verifystrict)
{
    BOOST_CHECK(!FbSigCacheScopeOpen());
    for (unsigned char i = 101; i <= 106; i++) {
        const CKey key = DetKey(i);
        const CPubKey pub = key.GetPubKey();
        const CPubKey other = DetKey(i + 50).GetPubKey();
        uint256 hash, hash2;
        *hash.begin() = i;
        *hash2.begin() = i + 1;
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(key.Sign(hash, sig));
        const std::vector<unsigned char> flip = A5HighSFlip(sig), pad = A5DerPad(sig), empty;
        struct Case { const CPubKey* pk; const uint256* h; const std::vector<unsigned char>* s; };
        const Case cases[] = {{&pub, &hash, &sig}, {&pub, &hash, &flip}, {&pub, &hash, &pad}, {&pub, &hash, &empty},
                              {&other, &hash, &sig}, {&pub, &hash2, &sig}};

        // Outside a scope: the plain check, and nothing is cached
        for (const Case& c : cases)
            BOOST_CHECK_EQUAL(FbVerifyStrict(*c.pk, *c.h, *c.s), c.pk->VerifyStrict(*c.h, *c.s));
        BOOST_CHECK(!SignatureCacheHas(hash, sig, pub));
        {
            FbSigCacheScope scope;
            BOOST_CHECK(FbSigCacheScopeOpen());
            {
                FbSigCacheScope nested;   // nests
            }
            BOOST_CHECK(FbSigCacheScopeOpen());
            // Twice: the first verifies and caches the good one, the second reads the cache
            for (int pass = 0; pass < 2; pass++)
                for (const Case& c : cases)
                    BOOST_CHECK_EQUAL(FbVerifyStrict(*c.pk, *c.h, *c.s), c.pk->VerifyStrict(*c.h, *c.s));
            BOOST_CHECK(SignatureCacheHas(hash, sig, pub));      // the valid one is cached
            BOOST_CHECK(!SignatureCacheHas(hash, sig, other));   // a failure never is
            BOOST_CHECK(!SignatureCacheHas(hash2, sig, pub));
            // Even a planted entry for a malleated form can't pass: the encoding axes run first
            SignatureCacheAdd(hash, flip, pub);
            SignatureCacheAdd(hash, pad, pub);
            BOOST_CHECK(!FbVerifyStrict(pub, hash, flip));
            BOOST_CHECK(!FbVerifyStrict(pub, hash, pad));
        }
        BOOST_CHECK(!FbSigCacheScopeOpen());
    }

    // The cost the sweep pays per signature, plain vs cached (logged, not asserted: machine-dependent)
    const CKey key = DetKey(120);
    const CPubKey pub = key.GetPubKey();
    uint256 hash;
    *hash.begin() = 120;
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(hash, sig));
    const int N = 500;
    int64_t t0 = GetTimeMicros();
    for (int n = 0; n < N; n++) BOOST_REQUIRE(FbVerifyStrict(pub, hash, sig));
    const int64_t nPlain = GetTimeMicros() - t0;
    int64_t nCached = 0;
    {
        FbSigCacheScope scope;
        BOOST_REQUIRE(FbVerifyStrict(pub, hash, sig));   // admission: verified once and cached
        const int64_t t1 = GetTimeMicros();
        for (int n = 0; n < N; n++) BOOST_REQUIRE(FbVerifyStrict(pub, hash, sig));
        nCached = GetTimeMicros() - t1;
    }
    BOOST_TEST_MESSAGE("ur3_4: " << N << " payload signature checks: plain " << nPlain << " us, cached " << nCached << " us");
}

BOOST_AUTO_TEST_SUITE_END()

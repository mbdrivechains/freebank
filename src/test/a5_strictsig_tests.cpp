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
#include <test/strictsig_util.h>
#include <test/test_bitcoin.h>
#include <uint256.h>

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

BOOST_AUTO_TEST_SUITE_END()

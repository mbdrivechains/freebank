// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license.
#ifndef BITCOIN_TEST_STRICTSIG_UTIL_H
#define BITCOIN_TEST_STRICTSIG_UTIL_H

// A5 malleation vectors (SECURITY_GATE_SIGNOFF_A5.md test plan): the two
// re-encodings of a valid canonical payload signature that legacy
// CPubKey::Verify accepts by construction and VerifyStrict must reject.
// Payload sigs are RAW DER - no trailing sighash-type byte.

#include <arith_uint256.h>
#include <uint256.h>

#include <vector>

// secp256k1 group order n.
inline arith_uint256 A5CurveOrder()
{
    return UintToArith256(uint256S(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"));
}

/** (A) High-S flip: replace s with n - s and re-encode minimally. The result
 * is a byte-distinct, still-minimal DER encoding whose S is high - legacy
 * Verify normalizes it back and accepts; CheckLowS refuses. */
inline std::vector<unsigned char> A5HighSFlip(const std::vector<unsigned char>& sig)
{
    // 0x30 total 0x02 lenR R... 0x02 lenS S...
    const unsigned int lenR = sig[3];
    const unsigned int lenS = sig[5 + lenR];
    arith_uint256 s = 0;
    for (unsigned int i = 0; i < lenS; i++)
        s = (s << 8) | sig[6 + lenR + i];
    arith_uint256 sFlip = A5CurveOrder() - s;

    // Minimal big-endian serialization of n - s (strip leading zeros, then
    // re-pad one 0x00 if the top bit is set).
    std::vector<unsigned char> vchS(32);
    const uint256 u = ArithToUint256(sFlip);
    for (int i = 0; i < 32; i++)
        vchS[i] = u.begin()[31 - i]; // uint256 stores little-endian; we want big-endian
    size_t nLead = 0;
    while (nLead < 31 && vchS[nLead] == 0x00) nLead++;
    std::vector<unsigned char> vchMin(vchS.begin() + nLead, vchS.end());
    if (vchMin[0] & 0x80) vchMin.insert(vchMin.begin(), 0x00);

    std::vector<unsigned char> out;
    out.push_back(0x30);
    out.push_back((unsigned char)(4 + lenR + vchMin.size()));
    out.push_back(0x02);
    out.push_back((unsigned char)lenR);
    out.insert(out.end(), sig.begin() + 4, sig.begin() + 4 + lenR);
    out.push_back(0x02);
    out.push_back((unsigned char)vchMin.size());
    out.insert(out.end(), vchMin.begin(), vchMin.end());
    return out;
}

/** (B) DER padding: prepend a non-minimal 0x00 to the R integer and bump the
 * two length bytes. parse_der_lax accepts it, so legacy Verify accepts; the
 * encoding is non-minimal DER, so CheckStrictDER refuses. A canonical payload
 * sig is at most 71 bytes, so the padded form still fits the 72-byte bound -
 * the reject is the minimality rule itself, not the size gate. */
inline std::vector<unsigned char> A5DerPad(const std::vector<unsigned char>& sig)
{
    std::vector<unsigned char> out = sig;
    out[1] += 1;             // total length
    out[3] += 1;             // R length
    out.insert(out.begin() + 4, 0x00);
    return out;
}

#endif // BITCOIN_TEST_STRICTSIG_UTIL_H

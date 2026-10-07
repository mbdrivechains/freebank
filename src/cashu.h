// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FREEBANK_CASHU_H
#define FREEBANK_CASHU_H

// Checks of Cashu ecash tokens (blind-signed bearer tokens of a house's mint), for the token holders' claim at a
// failed house (gateway docs/freebank/TOKEN_CLAIM_DESIGN.md). Only verification: the node never signs tokens.
//   NUT-00: Y = hash_to_curve(secret); the mint's signature on a token is C = k*Y.
//   NUT-12: a DLEQ proof (e, s), plus the holder's blinding factor r, shows that C was made with the same k as the
//           mint's public key K = k*G, without the mint. https://github.com/cashubtc/nuts (00.md, 12.md)
// Points are SEC1 public keys (33 or 65 bytes); scalars are 32 bytes big-endian.

#include <pubkey.h>
#include <uint256.h>

#include <array>
#include <vector>

typedef std::array<unsigned char, 32> CashuScalar;

/** NUT-00 hash_to_curve: Y = PublicKey(0x02 || SHA256(SHA256("Secp256k1_HashToCurve_Cashu_" || msg) || counter)),
 *  counter a little-endian uint32 from 0 up to the first valid point. False only if no point is found in 2^16 tries
 *  (probability about 2^-65536). */
bool CashuHashToCurve(const std::vector<unsigned char>& msg, CPubKey& Y);

/** NUT-12 hash_e: SHA256 of the concatenated lowercase hex of each point's uncompressed (65-byte) encoding. False if
 *  a point does not parse. */
bool CashuHashE(const std::vector<CPubKey>& points, CashuScalar& e);

/** NUT-12, the minting user's check: R1 = s*G - e*A, R2 = s*B_ - e*C_, and e == hash_e(R1, R2, A, C_). */
bool CashuVerifyDLEQ(const CPubKey& A, const CPubKey& B_, const CPubKey& C_, const CashuScalar& e, const CashuScalar& s);

/** NUT-12, a third party's check of a token: Y = hash_to_curve(secret), C_ = C + r*A, B_ = Y + r*G, then the DLEQ
 *  check. secret is the token's secret string as bytes (its UTF-8 encoding, as the mint hashes it). */
bool CashuVerifyProof(const CPubKey& A, const std::vector<unsigned char>& secret, const CPubKey& C,
                      const CashuScalar& e, const CashuScalar& s, const CashuScalar& r);

/** out = a - b (points). The token claim's signing key: P = B_ - Y, whose private key is the blinding factor r. */
bool CashuPointSub(const CPubKey& a, const CPubKey& b, CPubKey& out);

/** A holder's token, back to what the mint signed: B_ = Y + r*G and C_ = C + r*A. */
bool CashuReblind(const CPubKey& A, const CPubKey& Y, const CPubKey& C, const CashuScalar& r, CPubKey& B_, CPubKey& C_);

#endif // FREEBANK_CASHU_H

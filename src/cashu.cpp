// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cashu.h>

#include <crypto/sha256.h>
#include <utilstrencodings.h>

#include <secp256k1.h>

#include <string.h>

namespace {

// One context for the whole process: sign (for s*G) + verify (for tweak_mul). Built on first use; secp256k1 contexts
// are read-only after creation, so sharing it between threads is safe.
const secp256k1_context* Ctx()
{
    static const secp256k1_context* ctx = [] {
        secp256k1_context* c = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        return c;
    }();
    return ctx;
}

bool Parse(const CPubKey& pk, secp256k1_pubkey& out)
{
    return pk.IsValid() && secp256k1_ec_pubkey_parse(Ctx(), &out, pk.begin(), pk.size());
}

// out = k*P. Fails for k = 0 or k >= n.
bool Mul(const secp256k1_pubkey& P, const CashuScalar& k, secp256k1_pubkey& out)
{
    out = P;
    return secp256k1_ec_pubkey_tweak_mul(Ctx(), &out, k.data());
}

// out = k*G. Fails for k = 0 or k >= n.
bool MulG(const CashuScalar& k, secp256k1_pubkey& out)
{
    return secp256k1_ec_pubkey_create(Ctx(), &out, k.data());
}

// out = a + b. Fails if the sum is the point at infinity.
bool Add(const secp256k1_pubkey& a, const secp256k1_pubkey& b, secp256k1_pubkey& out)
{
    const secp256k1_pubkey* v[2] = {&a, &b};
    return secp256k1_ec_pubkey_combine(Ctx(), &out, v, 2);
}

// out = a - b.
bool Sub(const secp256k1_pubkey& a, const secp256k1_pubkey& b, secp256k1_pubkey& out)
{
    secp256k1_pubkey nb = b;
    return secp256k1_ec_pubkey_negate(Ctx(), &nb) && Add(a, nb, out);
}

bool HashE(const std::vector<secp256k1_pubkey>& points, CashuScalar& e)
{
    std::string hex;
    for (const secp256k1_pubkey& p : points) {
        unsigned char buf[65];
        size_t len = sizeof(buf);
        if (!secp256k1_ec_pubkey_serialize(Ctx(), buf, &len, &p, SECP256K1_EC_UNCOMPRESSED) || len != 65)
            return false;
        hex += HexStr(buf, buf + len);
    }
    CSHA256().Write((const unsigned char*)hex.data(), hex.size()).Finalize(e.data());
    return true;
}

bool VerifyDLEQ(const secp256k1_pubkey& A, const secp256k1_pubkey& B_, const secp256k1_pubkey& C_,
                const CashuScalar& e, const CashuScalar& s)
{
    secp256k1_pubkey sG, eA, sB, eC, R1, R2;
    if (!MulG(s, sG) || !Mul(A, e, eA) || !Sub(sG, eA, R1)) return false;
    if (!Mul(B_, s, sB) || !Mul(C_, e, eC) || !Sub(sB, eC, R2)) return false;
    CashuScalar e2;
    if (!HashE({R1, R2, A, C_}, e2)) return false;
    return memcmp(e2.data(), e.data(), e.size()) == 0;
}

} // namespace

bool CashuHashToCurve(const std::vector<unsigned char>& msg, CPubKey& Y)
{
    static const std::string DOMAIN_SEPARATOR = "Secp256k1_HashToCurve_Cashu_";
    unsigned char msgHash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write((const unsigned char*)DOMAIN_SEPARATOR.data(), DOMAIN_SEPARATOR.size())
             .Write(msg.data(), msg.size()).Finalize(msgHash);
    for (uint32_t counter = 0; counter < 65536; counter++) {
        unsigned char ctr[4] = {(unsigned char)(counter & 0xff), (unsigned char)((counter >> 8) & 0xff),
                                (unsigned char)((counter >> 16) & 0xff), (unsigned char)((counter >> 24) & 0xff)};
        unsigned char cand[33];
        cand[0] = 0x02;
        CSHA256().Write(msgHash, sizeof(msgHash)).Write(ctr, sizeof(ctr)).Finalize(cand + 1);
        secp256k1_pubkey p;
        if (secp256k1_ec_pubkey_parse(Ctx(), &p, cand, sizeof(cand))) {
            Y = CPubKey(cand, cand + sizeof(cand));
            return true;
        }
    }
    return false;
}

bool CashuHashE(const std::vector<CPubKey>& points, CashuScalar& e)
{
    std::vector<secp256k1_pubkey> v(points.size());
    for (size_t i = 0; i < points.size(); i++)
        if (!Parse(points[i], v[i])) return false;
    return HashE(v, e);
}

bool CashuVerifyDLEQ(const CPubKey& A, const CPubKey& B_, const CPubKey& C_, const CashuScalar& e, const CashuScalar& s)
{
    secp256k1_pubkey a, b, c;
    return Parse(A, a) && Parse(B_, b) && Parse(C_, c) && VerifyDLEQ(a, b, c, e, s);
}

bool CashuVerifyProof(const CPubKey& A, const std::vector<unsigned char>& secret, const CPubKey& C,
                      const CashuScalar& e, const CashuScalar& s, const CashuScalar& r)
{
    CPubKey Ypk;
    secp256k1_pubkey a, c, y, rA, rG, B_, C_;
    if (!CashuHashToCurve(secret, Ypk) || !Parse(Ypk, y)) return false;
    if (!Parse(A, a) || !Parse(C, c)) return false;
    if (!Mul(a, r, rA) || !Add(c, rA, C_)) return false;    // C_ = C + r*A
    if (!MulG(r, rG) || !Add(y, rG, B_)) return false;      // B_ = Y + r*G
    return VerifyDLEQ(a, B_, C_, e, s);
}

bool CashuPointSub(const CPubKey& a, const CPubKey& b, CPubKey& out)
{
    secp256k1_pubkey pa, pb, d;
    if (!Parse(a, pa) || !Parse(b, pb) || !Sub(pa, pb, d)) return false;
    unsigned char buf[33];
    size_t len = sizeof(buf);
    secp256k1_ec_pubkey_serialize(Ctx(), buf, &len, &d, SECP256K1_EC_COMPRESSED);
    out = CPubKey(buf, buf + len);
    return true;
}

bool CashuReblind(const CPubKey& A, const CPubKey& Y, const CPubKey& C, const CashuScalar& r, CPubKey& B_, CPubKey& C_)
{
    secp256k1_pubkey a, y, c, rG, rA, b, cc;
    if (!Parse(A, a) || !Parse(Y, y) || !Parse(C, c)) return false;
    if (!MulG(r, rG) || !Add(y, rG, b)) return false;
    if (!Mul(a, r, rA) || !Add(c, rA, cc)) return false;
    unsigned char buf[33];
    size_t len = sizeof(buf);
    secp256k1_ec_pubkey_serialize(Ctx(), buf, &len, &b, SECP256K1_EC_COMPRESSED);
    B_ = CPubKey(buf, buf + len);
    len = sizeof(buf);
    secp256k1_ec_pubkey_serialize(Ctx(), buf, &len, &cc, SECP256K1_EC_COMPRESSED);
    C_ = CPubKey(buf, buf + len);
    return true;
}

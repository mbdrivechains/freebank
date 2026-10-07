// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <token.h>

#include <crypto/sha256.h>
#include <hash.h>

#include <string.h>

bool CTokenKeyset::KeyFor(uint64_t nAmount, CPubKey& key) const
{
    if (nAmount == 0 || (nAmount & (nAmount - 1)) != 0)
        return false;
    uint8_t nExp = 0;
    while ((1ULL << nExp) != nAmount)
        nExp++;
    for (const TokenKey& k : vKey) {
        if (k.nExp == nExp) {
            key = CPubKey(k.vchPubKey.begin(), k.vchPubKey.end());
            return true;
        }
    }
    return false;
}

uint64_t TokenKeysetID(const std::vector<TokenKey>& vKey)
{
    // NUT-02 (v1 ids): sort the keys by amount (the payload is already strictly ascending), concatenate the compressed
    // keys, SHA256, keep the first 7 bytes behind a 0x00 version byte.
    CSHA256 h;
    for (const TokenKey& k : vKey)
        h.Write(k.vchPubKey.data(), k.vchPubKey.size());
    unsigned char out[CSHA256::OUTPUT_SIZE];
    h.Finalize(out);
    uint64_t id = 0;
    for (int i = 0; i < 7; i++)
        id = (id << 8) | out[i];
    return id;   // the top byte is the version, 0x00
}

uint256 TokenYID(const CPubKey& Y)
{
    uint256 y;
    if (Y.size() == CPubKey::COMPRESSED_PUBLIC_KEY_SIZE)
        memcpy(y.begin(), Y.begin() + 1, 32);
    return y;
}

CPubKey TokenYPoint(const uint256& y)
{
    unsigned char buf[33];
    buf[0] = 0x02;
    memcpy(buf + 1, y.begin(), 32);
    return CPubKey(buf, buf + sizeof(buf));
}

uint256 TokenKeysetSigHash(const NoteTokenKeyset& ks, const uint256& hashPrevouts)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankToken/keyset");
    ss << ks.nHouseID;
    ss << ks.vchPostingPubKey;
    ss << ks.vKey;
    ss << hashPrevouts;   // tx-unique: the approvals can't be replayed
    return ss.GetHash();
}

uint256 TokenPostSigHash(const NoteTokenPost& post, const uint256& hashPrevouts)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankToken/post");
    ss << post.nHouseID;
    ss << post.nKeysetID;
    ss << post.vIssued;
    ss << post.vSpent;
    ss << hashPrevouts;
    return ss.GetHash();
}

uint256 TokenClaimSigHash(uint32_t nHouseID, const uint256& y, const std::vector<unsigned char>& vchPayoutScript,
                          uint16_t nFeeBps, const std::vector<unsigned char>& vchRelayerScript)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBankToken/claim");
    ss << nHouseID;
    ss << y;
    ss << vchPayoutScript;
    ss << nFeeBps;
    ss << vchRelayerScript;
    return ss.GetHash();
}

bool IsTokenConditionSecret(const std::vector<unsigned char>& vchSecret)
{
    // NUT-10: a well-known secret is the JSON array ["kind", {...}]. Leading whitespace is legal JSON.
    for (unsigned char c : vchSecret) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            continue;
        return c == '[';
    }
    return false;
}

uint64_t TokenClaimUnits(uint64_t nAmount, uint64_t nBase, uint64_t nClaimed)
{
    if (nClaimed <= nBase)
        return nAmount;
    return (uint64_t)(((unsigned __int128)nAmount * nBase) / nClaimed);
}

CAmount TokenRelayerFee(const CAmount& amountEntitlement, uint16_t nFeeBps)
{
    if (amountEntitlement <= 0 || nFeeBps == 0)
        return 0;
    return (CAmount)(((__int128)amountEntitlement * nFeeBps) / TOKEN_FEE_BPS_MAX);
}

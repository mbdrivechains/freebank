// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNITS_H
#define BITCOIN_UNITS_H

// The units DB (blocks/Units/), gram-notes release (docs-local/GOLD_USD_SCOPE.md, step 1): the chain state that is
// neither a coin nor a house record - issued tokens, the oracle's streams and history, token pools, the per-house
// indexes. One generic undo replaces the per-op priors the older DBs bind into their payloads (which can't serve
// several swaps against one pool in a block, or chain-wide totals): each block writes the before-image of every key it
// touched, keyed by its hash, in the same batch as the new values and the best-block marker.
//  - ConnectBlock reads and writes through a CUnitsView over the DB and hands it to WriteBlock at the end. A
//    template check (fJustCheck) and the mempool use a view and drop it.
//  - DisconnectBlock (real disconnects only) undoes the block if the marker is at it.
//  - The marker follows the House/Bill/Pool DBs' crash rule: at a descendant of the block being connected means its
//    effects are already here (the coins DB lagged), and the block's units sections are skipped, not re-applied.

#include <clientversion.h>
#include <dbwrapper.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <boost/optional.hpp>

#include <map>
#include <utility>
#include <vector>

/** A units-DB key: a prefix byte, then fixed-width big-endian fields, so leveldb's byte order is the fields' order
 *  (range scans by house, by height). Stored raw, with no length; inside another record write its bytes (`v`). */
class UnitsKey
{
public:
    std::vector<unsigned char> v;

    UnitsKey() {}
    explicit UnitsKey(unsigned char chPrefix) : v(1, chPrefix) {}

    UnitsKey& U8(uint8_t x) { v.push_back(x); return *this; }
    UnitsKey& U32(uint32_t x) { for (int i = 3; i >= 0; i--) v.push_back((x >> (8 * i)) & 0xff); return *this; }
    UnitsKey& U64(uint64_t x) { for (int i = 7; i >= 0; i--) v.push_back((x >> (8 * i)) & 0xff); return *this; }
    UnitsKey& Hash(const uint256& h) { v.insert(v.end(), h.begin(), h.end()); return *this; }
    /** Variable-length bytes: only as the last field, or the order breaks. */
    UnitsKey& Bytes(const std::vector<unsigned char>& b) { v.insert(v.end(), b.begin(), b.end()); return *this; }

    bool HasPrefix(const UnitsKey& prefix) const
    {
        return prefix.v.size() <= v.size() && std::equal(prefix.v.begin(), prefix.v.end(), v.begin());
    }
    bool operator<(const UnitsKey& o) const { return v < o.v; }
    bool operator==(const UnitsKey& o) const { return v == o.v; }
    bool operator!=(const UnitsKey& o) const { return v != o.v; }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        if (!v.empty())
            s.write((const char*)v.data(), v.size());
    }
    /** The DB hands a key over as a stream holding exactly its bytes. */
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        v.resize(s.size());
        if (!v.empty())
            s.read((char*)v.data(), v.size());
    }
};

typedef std::vector<unsigned char> UnitsValue;   // a serialized record
typedef boost::optional<UnitsValue> UnitsSlot;   // none = no such key

/** Key prefixes. The DB is new in the gram-notes release; give every record kind its own byte. */
static const unsigned char UNITS_BEST_BLOCK = 'Z';
static const unsigned char UNITS_DB_VERSION = 'v';      // -> uint32 the layout version (review 11-04)
/** The units DB's layout version. 2 = v1.1.0 (the demanded-notes index, burns' cumulative units). A DB with blocks in
 *  it and another (or no) version was written by an earlier build: the node asks for -reindex. */
static const uint32_t UNITS_DB_VERSION_CURRENT = 2;
static const unsigned char UNITS_BLOCK_UNDO = 'u';
static const unsigned char UNITS_TEST = '~';     // unit tests only
static const unsigned char UNITS_ISSUED_TOKEN = 'T';    // + token id -> CIssuedToken (issued.h)
static const unsigned char UNITS_ISSUED_FROZEN = 'F';   // + outpoint -> uint64 frozen units, set by FREEZE / UNFREEZE
static const unsigned char UNITS_ISSUED_BURN = 'R';     // + token id + sequence -> CIssuedBurn

static const unsigned char UNITS_VAULT = 'V';          // + house + kind + partner + token -> uint64 units (a gold vault)
static const unsigned char UNITS_VAULT_TOTAL = 'A';    // + token -> uint64 units of the token in every house's vaults
static const unsigned char UNITS_TOKEN_POOL = 'L';     // + token id -> CTokenPool (issued.h)
static const unsigned char UNITS_POOL_SAMPLE = 'Y';    // + token id + height -> CPoolSample
static const unsigned char UNITS_ORACLE_OBS = 'P';     // + stream + subject + submitter -> COracleObsRec (pricefeed.h)
static const unsigned char UNITS_ORACLE_FIX = 'X';     // + stream + subject + height -> CPriceFix
static const unsigned char UNITS_ORACLE_DAY = 'D';     // + day (height / 144) -> uint64 median sats per gram that day
static const unsigned char UNITS_VAULT_FROZEN = 'G';   // + house + token -> CVaultFrozen (an issuer's freeze on vault gold)
static const unsigned char UNITS_QUEUE = 'Q';           // + house + demand height -> uint64 units of queued demands (R3-12)
static const unsigned char UNITS_DEMANDED = 'q';        // + house + demand tag -> uint64 units of demanded notes (3c)
static const unsigned char UNITS_EXIT = 'E';           // -> CExitState (the exit's step; one record)
static const unsigned char UNITS_NOPRICE = 'N';        // + start height -> uint32 end height: a run of blocks with no payout price
static const unsigned char UNITS_NOPRICE_LAST = 'n';   // -> uint32 start of the latest no-price run
static const unsigned char UNITS_BACKING_ADDRESS = 'b';  // + backing address -> token id (one token per address)

inline UnitsKey IssuedTokenKey(const uint256& tokenID) { return UnitsKey(UNITS_ISSUED_TOKEN).Hash(tokenID); }
inline UnitsKey IssuedFrozenKey(const uint256& txid, uint32_t n) { return UnitsKey(UNITS_ISSUED_FROZEN).Hash(txid).U32(n); }
inline UnitsKey IssuedBurnKey(const uint256& tokenID, uint64_t nSeq) { return UnitsKey(UNITS_ISSUED_BURN).Hash(tokenID).U64(nSeq); }
inline UnitsKey VaultKey(uint32_t nHouseID, uint8_t nKind, uint32_t nPartner, const uint256& tokenID)
{
    return UnitsKey(UNITS_VAULT).U32(nHouseID).U8(nKind).U32(nPartner).Hash(tokenID);
}
inline UnitsKey VaultTotalKey(const uint256& tokenID) { return UnitsKey(UNITS_VAULT_TOTAL).Hash(tokenID); }
inline UnitsKey VaultFrozenKey(uint32_t nHouseID, const uint256& tokenID) { return UnitsKey(UNITS_VAULT_FROZEN).U32(nHouseID).Hash(tokenID); }
inline UnitsKey QueueKey(uint32_t nHouseID, uint32_t nDemandHeight) { return UnitsKey(UNITS_QUEUE).U32(nHouseID).U32(nDemandHeight); }
/** D-2026-11-04-1 (3c): every demanded note's units by house and full demand tag (the tag fixes how its interest runs),
 *  so a house's equity counts the interest its demands have accrued. */
inline UnitsKey DemandedKey(uint32_t nHouseID, uint32_t nDemandTag) { return UnitsKey(UNITS_DEMANDED).U32(nHouseID).U32(nDemandTag); }
inline UnitsKey TokenPoolKey(const uint256& tokenID) { return UnitsKey(UNITS_TOKEN_POOL).Hash(tokenID); }
inline UnitsKey PoolSampleKey(const uint256& tokenID, uint32_t nHeight) { return UnitsKey(UNITS_POOL_SAMPLE).Hash(tokenID).U32(nHeight); }

/** One block's undo: the value every key it touched had before it. */
struct CUnitsBlockUndo
{
    std::vector<std::pair<UnitsKey, UnitsSlot>> vBefore;

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, vBefore.size());
        for (const std::pair<UnitsKey, UnitsSlot>& p : vBefore) {
            ::Serialize(s, p.first.v);
            const uint8_t fPresent = p.second ? 1 : 0;
            ::Serialize(s, fPresent);
            if (fPresent)
                ::Serialize(s, *p.second);
        }
    }
    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint64_t n = ReadCompactSize(s);
        vBefore.clear();
        for (uint64_t i = 0; i < n; i++) {
            UnitsKey key;
            ::Unserialize(s, key.v);
            uint8_t fPresent;
            ::Unserialize(s, fPresent);
            if (fPresent > 1)
                throw std::ios_base::failure("CUnitsBlockUndo: bad presence flag");
            UnitsSlot slot;
            if (fPresent) {
                UnitsValue value;
                ::Unserialize(s, value);
                slot = value;
            }
            vBefore.emplace_back(std::move(key), std::move(slot));
        }
    }
};

/** Access to the units database (blocks/Units/). */
class CUnitsDB : public CDBWrapper
{
public:
    CUnitsDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool ReadValue(const UnitsKey& key, UnitsValue& value) const;
    bool GetBestBlock(uint256& hashBlock) const;
    /** At startup: a DB with no blocks yet gets the current version; one with blocks must carry it. */
    bool CheckOrWriteVersion(std::string& strError);

    /** One block's effects in one atomic batch: the new value of every key in mapChange (none erases it), the block's
     *  undo record (mapBefore: each key's value before the block) and the marker = hashBlock. A block that changed
     *  nothing writes no undo record; its absence reads as "nothing to undo". */
    bool WriteBlock(const std::map<UnitsKey, UnitsSlot>& mapChange, const std::map<UnitsKey, UnitsSlot>& mapBefore,
                    const uint256& hashBlock);

    /** Undo one block in one atomic batch: restore its before-images, erase its record, marker = hashPrev. */
    bool UndoBlock(const uint256& hashBlock, const uint256& hashPrev);

    /** Up to nMax stored (key, value) pairs with this prefix, from start (inclusive; empty = from the prefix), in key
     *  order. */
    std::vector<std::pair<UnitsKey, UnitsValue>> Scan(const UnitsKey& prefix, const UnitsKey& start, size_t nMax) const;
};

/** A block's (or a check's) window on the units state: reads fall through to the DB, writes stay here until Write.
 *  The first write of a key records its before-image for the undo. pdb may be null: an empty state (unit tests). */
class CUnitsView
{
public:
    explicit CUnitsView(const CUnitsDB* pdbIn) : pdb(pdbIn) {}

    bool GetRaw(const UnitsKey& key, UnitsValue& value) const;
    bool Have(const UnitsKey& key) const { UnitsValue value; return GetRaw(key, value); }
    void PutRaw(const UnitsKey& key, const UnitsValue& value);
    void Erase(const UnitsKey& key);

    template <typename T>
    bool Get(const UnitsKey& key, T& obj) const
    {
        UnitsValue value;
        if (!GetRaw(key, value))
            return false;
        try {
            CDataStream ss(value, SER_DISK, CLIENT_VERSION);
            ss >> obj;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }
    template <typename T>
    void Put(const UnitsKey& key, const T& obj)
    {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << obj;
        PutRaw(key, UnitsValue(ss.begin(), ss.end()));
    }

    /** As CUnitsDB::Scan, over the DB with this view's writes applied. */
    std::vector<std::pair<UnitsKey, UnitsValue>> Scan(const UnitsKey& prefix, const UnitsKey& start, size_t nMax) const;

    /** The keys this view changed (a key written back to its old value is left out) with their new and old values. */
    void GetChanges(std::map<UnitsKey, UnitsSlot>& mapChange, std::map<UnitsKey, UnitsSlot>& mapBefore) const;
    bool IsEmpty() const { return mapChange.empty(); }

private:
    const CUnitsDB* pdb;
    std::map<UnitsKey, UnitsSlot> mapChange;   // current value of every key written
    std::map<UnitsKey, UnitsSlot> mapBefore;   // its value before the first write

    UnitsSlot ReadDB(const UnitsKey& key) const;
    void Set(const UnitsKey& key, const UnitsSlot& slot);
};

#endif // BITCOIN_UNITS_H

// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_DBWRAPPER_H
#define BITCOIN_DBWRAPPER_H

#include <clientversion.h>
#include <fs.h>
#include <serialize.h>
#include <streams.h>
#include <util.h>
#include <uint256.h>
#include <utilstrencodings.h>
#include <version.h>

#include <leveldb/db.h>
#include <leveldb/write_batch.h>

#include <cassert>
#include <map>
#include <string>
#include <utility>

static const size_t DBWRAPPER_PREALLOC_KEY_SIZE = 64;
static const size_t DBWRAPPER_PREALLOC_VALUE_SIZE = 1024;

class dbwrapper_error : public std::runtime_error
{
public:
    explicit dbwrapper_error(const std::string& msg) : std::runtime_error(msg) {}
};

class CDBWrapper;

/** These should be considered an implementation detail of the specific database.
 */
namespace dbwrapper_private {

/** Handle database error by throwing dbwrapper_error exception.
 */
void HandleError(const leveldb::Status& status);

/** Work around circular dependency, as well as for testing in dbwrapper_tests.
 * Database obfuscation should be considered an implementation detail of the
 * specific database.
 */
const std::vector<unsigned char>& GetObfuscateKey(const CDBWrapper &w);

};

/** Batch of changes queued to be written to a CDBWrapper */
class CDBBatch
{
    friend class CDBWrapper;

private:
    const CDBWrapper &parent;
    leveldb::WriteBatch batch;

    CDataStream ssKey;
    CDataStream ssValue;

    size_t size_estimate;

public:
    /**
     * @param[in] _parent   CDBWrapper that this batch is to be submitted to
     */
    explicit CDBBatch(const CDBWrapper &_parent) : parent(_parent), ssKey(SER_DISK, CLIENT_VERSION), ssValue(SER_DISK, CLIENT_VERSION), size_estimate(0) { };

    void Clear()
    {
        batch.Clear();
        size_estimate = 0;
    }

    template <typename K, typename V>
    void Write(const K& key, const V& value)
    {
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());

        ssValue.reserve(DBWRAPPER_PREALLOC_VALUE_SIZE);
        ssValue << value;
        ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));
        leveldb::Slice slValue(ssValue.data(), ssValue.size());

        batch.Put(slKey, slValue);
        // LevelDB serializes writes as:
        // - byte: header
        // - varint: key length (1 byte up to 127B, 2 bytes up to 16383B, ...)
        // - byte[]: key
        // - varint: value length
        // - byte[]: value
        // The formula below assumes the key and value are both less than 16k.
        size_estimate += 3 + (slKey.size() > 127) + slKey.size() + (slValue.size() > 127) + slValue.size();
        ssKey.clear();
        ssValue.clear();
    }

    template <typename K>
    void Erase(const K& key)
    {
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());

        batch.Delete(slKey);
        // LevelDB serializes erases as:
        // - byte: header
        // - varint: key length
        // - byte[]: key
        // The formula below assumes the key is less than 16kB.
        size_estimate += 2 + (slKey.size() > 127) + slKey.size();
        ssKey.clear();
    }

    /** UR-ext-10: a write whose key and value are already serialized (SER_DISK, CLIENT_VERSION), as
     *  StagedDBWrapper keeps them. The value is obfuscated here exactly as Write() does. */
    void WriteSerialized(const std::string& strKey, const std::string& strValue)
    {
        ssValue.write(strValue.data(), strValue.size());
        ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));
        leveldb::Slice slKey(strKey.data(), strKey.size());
        leveldb::Slice slValue(ssValue.data(), ssValue.size());
        batch.Put(slKey, slValue);
        size_estimate += 3 + (slKey.size() > 127) + slKey.size() + (slValue.size() > 127) + slValue.size();
        ssValue.clear();
    }

    /** UR-ext-10: an erase whose key is already serialized. */
    void EraseSerialized(const std::string& strKey)
    {
        leveldb::Slice slKey(strKey.data(), strKey.size());
        batch.Delete(slKey);
        size_estimate += 2 + (slKey.size() > 127) + slKey.size();
    }

    size_t SizeEstimate() const { return size_estimate; }
};

class CDBIterator
{
private:
    const CDBWrapper &parent;
    leveldb::Iterator *piter;

public:

    /**
     * @param[in] _parent          Parent CDBWrapper instance.
     * @param[in] _piter           The original leveldb iterator.
     */
    CDBIterator(const CDBWrapper &_parent, leveldb::Iterator *_piter) :
        parent(_parent), piter(_piter) { };
    ~CDBIterator();

    bool Valid() const;

    void SeekToFirst();

    template<typename K> void Seek(const K& key) {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());
        piter->Seek(slKey);
    }

    void Next();

    template<typename K> bool GetKey(K& key) {
        leveldb::Slice slKey = piter->key();
        try {
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
            ssKey >> key;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template<typename V> bool GetValue(V& value) {
        leveldb::Slice slValue = piter->value();
        try {
            CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template<typename V> bool GetSidechainValue(V& value) {
        leveldb::Slice slValue = piter->value();
        try {
            CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    unsigned int GetValueSize() {
        return piter->value().size();
    }

    /** FB-6 (regtest getsidedbhashes): the key's raw bytes and the value's de-obfuscated bytes, as every node agrees on
     *  them (the obfuscation key differs per node). */
    void GetRawKeyValue(std::string& strKey, std::string& strValue) {
        leveldb::Slice slKey = piter->key(), slValue = piter->value();
        strKey.assign(slKey.data(), slKey.size());
        CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
        ssValue.Xor(dbwrapper_private::GetObfuscateKey(parent));
        strValue.assign(ssValue.begin(), ssValue.end());
    }

};

class CDBWrapper
{
    friend const std::vector<unsigned char>& dbwrapper_private::GetObfuscateKey(const CDBWrapper &w);
private:
    //! custom environment this database is using (may be nullptr in case of default environment)
    leveldb::Env* penv;

    //! database options used
    leveldb::Options options;

    //! options used when reading from the database
    leveldb::ReadOptions readoptions;

    //! options used when iterating over values of the database
    leveldb::ReadOptions iteroptions;

    //! options used when writing to the database
    leveldb::WriteOptions writeoptions;

    //! options used when sync writing to the database
    leveldb::WriteOptions syncoptions;

    //! the database itself
    leveldb::DB* pdb;

    //! a key used for optional XOR-obfuscation of the database
    std::vector<unsigned char> obfuscate_key;

    //! the key under which the obfuscation key is stored
    static const std::string OBFUSCATE_KEY_KEY;

    //! the length of the obfuscate key in number of bytes
    static const unsigned int OBFUSCATE_KEY_NUM_BYTES;

    std::vector<unsigned char> CreateObfuscateKey() const;

public:
    /** FB-6 (regtest getsidedbhashes): SHA256 over every (key, value) record in key order - the key raw, the value
     *  de-obfuscated - leaving out the obfuscation key's own record; nCount gets the number of records hashed. Two nodes
     *  holding the same state get the same hash. Reads LevelDB only (never a stage's overlay). */
    uint256 HashAllRecords(size_t& nCount);

    /**
     * @param[in] path        Location in the filesystem where leveldb data will be stored.
     * @param[in] nCacheSize  Configures various leveldb cache settings.
     * @param[in] fMemory     If true, use leveldb's memory environment.
     * @param[in] fWipe       If true, remove all existing data.
     * @param[in] obfuscate   If true, store data obfuscated via simple XOR. If false, XOR
     *                        with a zero'd byte array.
     */
    CDBWrapper(const fs::path& path, size_t nCacheSize, bool fMemory = false, bool fWipe = false, bool obfuscate = false);
    ~CDBWrapper();

    template <typename K, typename V>
    bool Read(const K& key, V& value) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        try {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue.Xor(obfuscate_key);
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template <typename K, typename V>
    bool ReadSidechain(const K& key, V& value) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(&ssKey[0], ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        try {
            CDataStream ssValue(strValue.data(), strValue.data() + strValue.size(), SER_DISK, CLIENT_VERSION);
            ssValue.Xor(obfuscate_key);
            ssValue >> value;
        } catch (const std::exception&) {
            return false;
        }
        return true;
    }

    template <typename K, typename V>
    bool Write(const K& key, const V& value, bool fSync = false)
    {
        CDBBatch batch(*this);
        batch.Write(key, value);
        return WriteBatch(batch, fSync);
    }

    template <typename K>
    bool Exists(const K& key) const
    {
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey << key;
        leveldb::Slice slKey(ssKey.data(), ssKey.size());

        std::string strValue;
        leveldb::Status status = pdb->Get(readoptions, slKey, &strValue);
        if (!status.ok()) {
            if (status.IsNotFound())
                return false;
            LogPrintf("LevelDB read failure: %s\n", status.ToString());
            dbwrapper_private::HandleError(status);
        }
        return true;
    }

    template <typename K>
    bool Erase(const K& key, bool fSync = false)
    {
        CDBBatch batch(*this);
        batch.Erase(key);
        return WriteBatch(batch, fSync);
    }

    bool WriteBatch(CDBBatch& batch, bool fSync = false);

    // not available for LevelDB; provide for compatibility with BDB
    bool Flush()
    {
        return true;
    }

    bool Sync()
    {
        CDBBatch batch(*this);
        return WriteBatch(batch, true);
    }

    CDBIterator *NewIterator()
    {
        return new CDBIterator(*this, pdb->NewIterator(iteroptions));
    }

    /**
     * Return true if the database managed by this class contains no entries.
     */
    bool IsEmpty();

    template<typename K>
    size_t EstimateSize(const K& key_begin, const K& key_end) const
    {
        CDataStream ssKey1(SER_DISK, CLIENT_VERSION), ssKey2(SER_DISK, CLIENT_VERSION);
        ssKey1.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey2.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey1 << key_begin;
        ssKey2 << key_end;
        leveldb::Slice slKey1(ssKey1.data(), ssKey1.size());
        leveldb::Slice slKey2(ssKey2.data(), ssKey2.size());
        uint64_t size = 0;
        leveldb::Range range(slKey1, slKey2);
        pdb->GetApproximateSizes(&range, 1, &size);
        return size;
    }

    /**
     * Compact a certain range of keys in the database.
     */
    template<typename K>
    void CompactRange(const K& key_begin, const K& key_end) const
    {
        CDataStream ssKey1(SER_DISK, CLIENT_VERSION), ssKey2(SER_DISK, CLIENT_VERSION);
        ssKey1.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey2.reserve(DBWRAPPER_PREALLOC_KEY_SIZE);
        ssKey1 << key_begin;
        ssKey2 << key_end;
        leveldb::Slice slKey1(ssKey1.data(), ssKey1.size());
        leveldb::Slice slKey2(ssKey2.data(), ssKey2.size());
        pdb->CompactRange(&slKey1, &slKey2);
    }

};

/** UR-ext-10 (switch-on): a database whose writes can be STAGED and committed in one atomic batch with a marker.
 *  While a stage is open, SWrite/SErase go to an in-memory overlay (last write per key wins) and SRead/SExists read
 *  the overlay first, so a multi-step undo sees its own writes; CommitStage then writes every staged change plus the
 *  marker in a single LevelDB batch, and AbortStage drops them. A crash can no longer land between a record write and
 *  its marker step (the BillDB R-3 treatment, for HouseDB and PoolDB). Iterators (cursors) do NOT see the overlay:
 *  nothing that runs inside a stage may list records. */
class StagedDBWrapper : public CDBWrapper
{
public:
    using CDBWrapper::CDBWrapper;

    void BeginStage() { AssertStageLock(); fStaged = true; mapStage.clear(); }
    void AbortStage() { if (fStaged) AssertStageLock(); fStaged = false; mapStage.clear(); }
    bool Staged() const { return fStaged; }

    /** Write every staged change and (keyMarker, valueMarker) in one synced batch, then close the stage. */
    template <typename K, typename V>
    bool CommitStage(const K& keyMarker, const V& valueMarker)
    {
        CDBBatch batch(*this);
        for (const auto& kv : mapStage) {
            if (kv.second.first)
                batch.WriteSerialized(kv.first, kv.second.second);
            else
                batch.EraseSerialized(kv.first);
        }
        batch.Write(keyMarker, valueMarker);
        const bool fOk = WriteBatch(batch, true);
        AbortStage();
        return fOk;
    }

    /** Close the stage, committing its changes with no marker (a datadir that never had one keeps none). */
    bool CommitStageNoMarker()
    {
        CDBBatch batch(*this);
        for (const auto& kv : mapStage) {
            if (kv.second.first)
                batch.WriteSerialized(kv.first, kv.second.second);
            else
                batch.EraseSerialized(kv.first);
        }
        const bool fOk = WriteBatch(batch, true);
        AbortStage();
        return fOk;
    }

protected:
    /** The overlay has no lock of its own: the lock that serialises the undo against every reader (cs_main for
     *  HouseDB and PoolDB, txdb.cpp) must be held whenever a stage is open (security, UR-ext-10 hardening 2). */
    virtual void AssertStageLock() const {}

    /** A cursor reads LevelDB only, never the overlay: nothing may list records while a stage is open, or it would read
     *  the state before the undo's own writes (security, UR-ext-10 hardening 1). */
    void AssertNoStageForCursor() const { assert(!fStaged); }

    template <typename K>
    static std::string StageKey(const K& key)
    {
        CDataStream ss(SER_DISK, CLIENT_VERSION);
        ss << key;
        return std::string(ss.begin(), ss.end());
    }

    template <typename K, typename V>
    bool SRead(const K& key, V& value) const
    {
        if (fStaged) {
            AssertStageLock();
            const auto it = mapStage.find(StageKey(key));
            if (it != mapStage.end()) {
                if (!it->second.first)
                    return false;
                try {
                    CDataStream ss(it->second.second.data(), it->second.second.data() + it->second.second.size(),
                                   SER_DISK, CLIENT_VERSION);
                    ss >> value;
                } catch (const std::exception&) {
                    return false;
                }
                return true;
            }
        }
        return Read(key, value);
    }

    template <typename K, typename V>
    bool SWrite(const K& key, const V& value, bool fSync = false)
    {
        if (fStaged) {
            AssertStageLock();
            CDataStream ss(SER_DISK, CLIENT_VERSION);
            ss << value;
            mapStage[StageKey(key)] = std::make_pair(true, std::string(ss.begin(), ss.end()));
            return true;
        }
        return Write(key, value, fSync);
    }

    template <typename K>
    bool SErase(const K& key, bool fSync = false)
    {
        if (fStaged) {
            AssertStageLock();
            mapStage[StageKey(key)] = std::make_pair(false, std::string());
            return true;
        }
        return Erase(key, fSync);
    }

    template <typename K>
    bool SExists(const K& key) const
    {
        if (fStaged) {
            AssertStageLock();
            const auto it = mapStage.find(StageKey(key));
            if (it != mapStage.end())
                return it->second.first;
        }
        return Exists(key);
    }

private:
    bool fStaged = false;
    std::map<std::string, std::pair<bool, std::string>> mapStage;   // serialized key -> (present, serialized value)
};

#endif // BITCOIN_DBWRAPPER_H

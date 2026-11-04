// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <units.h>

#include <util.h>

#include <boost/thread.hpp>

#include <memory>

CUnitsDB::CUnitsDB(size_t nCacheSize, bool fMemory, bool fWipe)
    : CDBWrapper(GetDataDir() / "blocks" / "Units", nCacheSize, fMemory, fWipe) { }

bool CUnitsDB::CheckOrWriteVersion(std::string& strError)
{
    uint256 hashBest;
    uint32_t nVersion = 0;
    const bool fVersion = Read(UnitsKey(UNITS_DB_VERSION), nVersion);
    if (!GetBestBlock(hashBest) || hashBest.IsNull()) {
        if (fVersion && nVersion == UNITS_DB_VERSION_CURRENT)
            return true;
        if (!Write(UnitsKey(UNITS_DB_VERSION), UNITS_DB_VERSION_CURRENT, true)) {
            strError = "Could not write the units database's version";
            return false;
        }
        return true;
    }
    if (fVersion && nVersion == UNITS_DB_VERSION_CURRENT)
        return true;
    strError = strprintf("The units database (blocks/Units) was written by an earlier build (layout %u, this build %u): "
                         "restart with -reindex", fVersion ? nVersion : 0, UNITS_DB_VERSION_CURRENT);
    return false;
}

bool CUnitsDB::ReadValue(const UnitsKey& key, UnitsValue& value) const
{
    return Read(key, value);
}

bool CUnitsDB::GetBestBlock(uint256& hashBlock) const
{
    return Read(UnitsKey(UNITS_BEST_BLOCK), hashBlock);
}

bool CUnitsDB::WriteBlock(const std::map<UnitsKey, UnitsSlot>& mapChange, const std::map<UnitsKey, UnitsSlot>& mapBefore,
                          const uint256& hashBlock)
{
    CDBBatch batch(*this);
    CUnitsBlockUndo undo;
    for (const std::pair<const UnitsKey, UnitsSlot>& p : mapChange) {
        // The undo record and the marker live in this DB too: a block's state may never write over them.
        if (p.first.v.empty() || p.first.v[0] == UNITS_BEST_BLOCK || p.first.v[0] == UNITS_BLOCK_UNDO)
            return error("%s: block %s writes a reserved units key", __func__, hashBlock.ToString());
        if (p.second)
            batch.Write(p.first, *p.second);
        else
            batch.Erase(p.first);
        std::map<UnitsKey, UnitsSlot>::const_iterator it = mapBefore.find(p.first);
        if (it == mapBefore.end())
            return error("%s: block %s: no before-image for a changed key", __func__, hashBlock.ToString());
        undo.vBefore.emplace_back(p.first, it->second);
    }
    if (!undo.vBefore.empty())
        batch.Write(UnitsKey(UNITS_BLOCK_UNDO).Hash(hashBlock), undo);
    batch.Write(UnitsKey(UNITS_BEST_BLOCK), hashBlock);
    return WriteBatch(batch, true);
}

bool CUnitsDB::UndoBlock(const uint256& hashBlock, const uint256& hashPrev)
{
    const UnitsKey keyUndo = UnitsKey(UNITS_BLOCK_UNDO).Hash(hashBlock);
    CUnitsBlockUndo undo;
    const bool fHaveUndo = Read(keyUndo, undo);
    if (!fHaveUndo && Exists(keyUndo))
        return error("%s: block %s: unreadable undo record", __func__, hashBlock.ToString());

    CDBBatch batch(*this);
    for (const std::pair<UnitsKey, UnitsSlot>& p : undo.vBefore) {
        if (p.second)
            batch.Write(p.first, *p.second);
        else
            batch.Erase(p.first);
    }
    if (fHaveUndo)
        batch.Erase(keyUndo);
    batch.Write(UnitsKey(UNITS_BEST_BLOCK), hashPrev);
    return WriteBatch(batch, true);
}

std::vector<std::pair<UnitsKey, UnitsValue>> CUnitsDB::Scan(const UnitsKey& prefix, const UnitsKey& start, size_t nMax) const
{
    std::vector<std::pair<UnitsKey, UnitsValue>> vOut;
    std::unique_ptr<CDBIterator> pcursor(const_cast<CUnitsDB*>(this)->NewIterator());
    pcursor->Seek(start.v.empty() ? prefix : start);
    while (pcursor->Valid() && vOut.size() < nMax) {
        boost::this_thread::interruption_point();
        UnitsKey key;
        if (!pcursor->GetKey(key) || !key.HasPrefix(prefix))
            break;
        UnitsValue value;
        if (pcursor->GetValue(value))
            vOut.emplace_back(std::move(key), std::move(value));
        pcursor->Next();
    }
    return vOut;
}

UnitsSlot CUnitsView::ReadDB(const UnitsKey& key) const
{
    UnitsValue value;
    if (pdb && pdb->ReadValue(key, value))
        return value;
    return boost::none;
}

bool CUnitsView::GetRaw(const UnitsKey& key, UnitsValue& value) const
{
    std::map<UnitsKey, UnitsSlot>::const_iterator it = mapChange.find(key);
    if (it != mapChange.end()) {
        if (!it->second)
            return false;
        value = *it->second;
        return true;
    }
    const UnitsSlot slot = ReadDB(key);
    if (!slot)
        return false;
    value = *slot;
    return true;
}

void CUnitsView::Set(const UnitsKey& key, const UnitsSlot& slot)
{
    if (!mapBefore.count(key))
        mapBefore[key] = ReadDB(key);
    mapChange[key] = slot;
}

void CUnitsView::PutRaw(const UnitsKey& key, const UnitsValue& value)
{
    Set(key, UnitsSlot(value));
}

void CUnitsView::Erase(const UnitsKey& key)
{
    Set(key, boost::none);
}

std::vector<std::pair<UnitsKey, UnitsValue>> CUnitsView::Scan(const UnitsKey& prefix, const UnitsKey& start, size_t nMax) const
{
    const UnitsKey& from = start.v.empty() ? prefix : start;
    std::vector<std::pair<UnitsKey, UnitsValue>> vOut;
    std::map<UnitsKey, UnitsSlot>::const_iterator itChange = mapChange.lower_bound(from);

    // Walk the DB and this view's writes together, in key order; a key this view wrote is read from the view.
    std::unique_ptr<CDBIterator> pcursor;
    if (pdb) {
        pcursor.reset(const_cast<CUnitsDB*>(pdb)->NewIterator());
        pcursor->Seek(from);
    }
    while (vOut.size() < nMax) {
        boost::this_thread::interruption_point();
        UnitsKey keyDB;
        bool fDB = pcursor && pcursor->Valid() && pcursor->GetKey(keyDB) && keyDB.HasPrefix(prefix);
        const bool fChange = itChange != mapChange.end() && itChange->first.HasPrefix(prefix);
        if (!fDB && !fChange)
            break;
        if (fChange && (!fDB || !(keyDB < itChange->first))) {
            if (fDB && keyDB == itChange->first)
                pcursor->Next();                  // the view's write replaces the stored value
            if (itChange->second)
                vOut.emplace_back(itChange->first, *itChange->second);
            ++itChange;
            continue;
        }
        UnitsValue value;
        if (pcursor->GetValue(value))
            vOut.emplace_back(std::move(keyDB), std::move(value));
        pcursor->Next();
    }
    return vOut;
}

void CUnitsView::GetChanges(std::map<UnitsKey, UnitsSlot>& mapChangeOut, std::map<UnitsKey, UnitsSlot>& mapBeforeOut) const
{
    mapChangeOut.clear();
    mapBeforeOut.clear();
    for (const std::pair<const UnitsKey, UnitsSlot>& p : mapChange) {
        const UnitsSlot& before = mapBefore.at(p.first);
        if (before == p.second)
            continue;
        mapChangeOut.insert(p);
        mapBeforeOut.emplace(p.first, before);
    }
}

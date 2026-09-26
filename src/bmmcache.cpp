#include <bmmcache.h>

#include <primitives/block.h>
#include <util.h>

// The main block cache (vMainBlockHash, mapMainBlock) has its own leaf mutex:
// nothing else is locked while it is held.
#define LOCK_MAIN_CACHE std::lock_guard<std::mutex> lockMainCache(csMainBlockCache)

BMMCache::BMMCache()
{

}

bool BMMCache::StoreBMMBlock(const CBlock& block)
{
    if (!block.vtx.size())
        return false;

    uint256 hashMerkleRoot = block.hashMerkleRoot;

    // Already have block stored
    if (mapBMMBlocks.find(hashMerkleRoot) != mapBMMBlocks.end())
        return false;

    mapBMMBlocks[hashMerkleRoot] = block;

    return true;
}

bool BMMCache::GetBMMBlock(const uint256& hashMerkleRoot, CBlock& block)
{
    if (mapBMMBlocks.find(hashMerkleRoot) == mapBMMBlocks.end())
        return false;

    block = mapBMMBlocks[hashMerkleRoot];

    return true;
}

std::vector<CBlock> BMMCache::GetBMMBlockCache() const
{
    std::vector<CBlock> vBlock;
    for (const auto& b : mapBMMBlocks) {
        vBlock.push_back(b.second);
    }
    return vBlock;
}

std::vector<uint256> BMMCache::GetBroadcastedWithdrawalBundleCache() const
{
    std::vector<uint256> vHash;
    for (const auto& u : setWithdrawalBundleBroadcasted) {
        vHash.push_back(u);
    }
    return vHash;
}

std::vector<uint256> BMMCache::GetMainBlockHashCache() const
{
    LOCK_MAIN_CACHE;
    return vMainBlockHash;
}

std::vector<uint256> BMMCache::GetRecentMainBlockHashes() const
{
    // Return up to three of the most recent mainchain block hashes
    LOCK_MAIN_CACHE;
    std::vector<uint256> vHash;
    std::vector<uint256>::const_reverse_iterator rit = vMainBlockHash.rbegin();
    for (; rit != vMainBlockHash.rend(); rit++) {
        vHash.push_back(*rit);
        if (vHash.size() == 3)
            break;
    }
    std::reverse(vHash.begin(), vHash.end());
    return vHash;
}

std::vector<uint256> BMMCache::GetLastMainBlockHashes(size_t n) const
{
    LOCK_MAIN_CACHE;
    size_t nStart = vMainBlockHash.size() > n ? vMainBlockHash.size() - n : 0;
    return std::vector<uint256>(vMainBlockHash.begin() + nStart, vMainBlockHash.end());
}

uint256 BMMCache::GetMainChildBlockHash(const uint256& hashBlock) const
{
    LOCK_MAIN_CACHE;
    return GetMainChildBlockHashLocked(hashBlock);
}

uint256 BMMCache::GetMainChildBlockHashLocked(const uint256& hashBlock) const
{
    std::map<uint256, MainBlockIndex>::const_iterator it = mapMainBlock.find(hashBlock);
    if (it == mapMainBlock.end())
        return uint256();

    size_t nChild = it->second.index + 1;
    if (nChild >= vMainBlockHash.size())
        return uint256();

    return vMainBlockHash[nChild];
}

void BMMCache::ClearBMMBlocks()
{
    mapBMMBlocks.clear();
}

void BMMCache::StoreBroadcastedWithdrawalBundle(const uint256& hashWithdrawalBundle)
{
    setWithdrawalBundleBroadcasted.insert(hashWithdrawalBundle);
}

void BMMCache::StorePrevBlockBMMCreated(const uint256& hashPrevBlock)
{
    setPrevBlockBMMCreated.insert(hashPrevBlock);
}

bool BMMCache::HaveBroadcastedWithdrawalBundle(const uint256& hashWithdrawalBundle) const
{
    if (hashWithdrawalBundle.IsNull())
        return false;

    if (setWithdrawalBundleBroadcasted.count(hashWithdrawalBundle))
        return true;

    return false;
}

bool BMMCache::HaveVerifiedBMM(const uint256& hashBlock) const
{
    if (hashBlock.IsNull())
        return false;

    return (setBMMVerified.count(hashBlock));
}

void BMMCache::CacheVerifiedBMM(const uint256& hashBlock)
{
    if (hashBlock.IsNull())
        return;

    setBMMVerified.insert(hashBlock);
}

bool BMMCache::HaveVerifiedDeposit(const uint256& txid) const
{
    if (txid.IsNull())
        return false;

    return (setDepositVerified.count(txid));
}

void BMMCache::CacheVerifiedDeposit(const uint256& txid)
{
    if (txid.IsNull())
        return;

    setDepositVerified.insert(txid);
}

std::vector<uint256> BMMCache::GetVerifiedBMMCache() const
{
    std::vector<uint256> vHash;
    for (const auto& u : setBMMVerified) {
        vHash.push_back(u);
    }
    return vHash;
}

std::vector<uint256> BMMCache::GetVerifiedDepositCache() const
{
    std::vector<uint256> vHash;
    for (const auto& u : setDepositVerified) {
        vHash.push_back(u);
    }
    return vHash;
}

void BMMCache::CacheMainBlockHash(const uint256& hash)
{
    LOCK_MAIN_CACHE;
    CacheMainBlockHashLocked(hash);
}

void BMMCache::CacheMainBlockHashLocked(const uint256& hash)
{
    // Don't re-cache the genesis block
    if (vMainBlockHash.size() == 1 && hash == vMainBlockHash.front())
        return;

    // Add to ordered vector of main block hashes
    vMainBlockHash.push_back(hash);

    // Add to index of hashes
    MainBlockIndex index;
    index.hash = hash;
    index.index = vMainBlockHash.size() - 1;

    mapMainBlock[hash] = index;
}

bool BMMCache::UpdateMainBlockCache(std::deque<uint256>& deqHashNew, bool& fReorg, std::vector<uint256>& vOrphan)
{
    LOCK_MAIN_CACHE;
    if (deqHashNew.empty()) {
        LogPrintf("%s: Error - called with empty list of new block hashes!\n", __func__);
        return false;
    }

    // If the main block cache doesn't have the genesis block yet, add it first
    if (vMainBlockHash.empty())
        CacheMainBlockHashLocked(deqHashNew.front());

    // Figure out the block in our cache that we will append the new blocks to
    MainBlockIndex index;
    if (mapMainBlock.count(deqHashNew.front())) {
        index = mapMainBlock[deqHashNew.front()];
    } else {
        LogPrintf("%s: Error - New blocks do not connect to cached chain!\n", __func__);
        return false;
    }

    // If there were any blocks in our cache after the block we will be building
    // on, remove them, add them to vOrphan as they were disconnected, set
    // fReorg true.
    if (index.index != vMainBlockHash.size() - 1) {
        LogPrintf("%s: Mainchain reorg detected!\n", __func__);
        fReorg = true;
    }

    for (size_t i = vMainBlockHash.size() - 1; i > index.index; i--) {
        vOrphan.push_back(vMainBlockHash[i]);
        vMainBlockHash.pop_back();
    }

    // Remove disconnected blocks from index map
    for (const uint256& u : vOrphan)
        mapMainBlock.erase(u);

    // It's possible that the first block in the list of new blocks (which
    // connects to our cached chain by a prevblock) was already cached.
    // The first block that connected by prevblock to one of our cached blocks
    // could either be a new different block or a block we already know
    // depending on how the fork / reorg happened.
    //
    // Check if we already know the first block in the deque and remove it if
    // we do.
    if (mapMainBlock.count(deqHashNew.front()))
        deqHashNew.pop_front();

    // Append new blocks
    for (const uint256& u : deqHashNew)
        CacheMainBlockHashLocked(u);

    LogPrintf("%s: Updated cached mainchain tip to: %s.\n", __func__, vMainBlockHash.back().ToString());

    return true;
}

uint256 BMMCache::GetLastMainBlockHash() const
{
    LOCK_MAIN_CACHE;
    if (vMainBlockHash.empty())
        return uint256();

    return vMainBlockHash.back();
}

uint256 BMMCache::GetMainPrevBlockHash(const uint256& hashBlock) const
{
    LOCK_MAIN_CACHE;
    if (vMainBlockHash.size() < 2)
        return uint256();

    if (!mapMainBlock.count(hashBlock))
        return uint256();

    const MainBlockIndex index = mapMainBlock.at(hashBlock);

    size_t indexPrev = index.index;
    if (indexPrev == 0)
        return uint256();

    indexPrev -= 1;
    if (indexPrev >= vMainBlockHash.size())
        return uint256();

    return vMainBlockHash[indexPrev];
}

int BMMCache::GetCachedBlockCount() const
{
    LOCK_MAIN_CACHE;
    return vMainBlockHash.size();
}

int BMMCache::GetMainchainBlockHeight(const uint256& hash) const
{
    LOCK_MAIN_CACHE;
    if (!mapMainBlock.count(hash))
        return -1;

    const MainBlockIndex index = mapMainBlock.at(hash);

    return index.index - 1;
}

bool BMMCache::HaveMainBlock(const uint256& hash) const
{
    LOCK_MAIN_CACHE;
    return mapMainBlock.count(hash);
}

bool BMMCache::HaveBMMRequestForPrevBlock(const uint256& hashPrevBlock) const
{
    return setPrevBlockBMMCreated.count(hashPrevBlock);
}

void BMMCache::AddCheckedMainBlock(const uint256& hashBlock)
{
    setMainBlockChecked.insert(hashBlock);
}

bool BMMCache::MainBlockChecked(const uint256& hashBlock) const
{
    return setMainBlockChecked.count(hashBlock);
}

void BMMCache::ResetMainBlockCache()
{
    LOCK_MAIN_CACHE;
    vMainBlockHash.clear();
    mapMainBlock.clear();
}

void BMMCache::ReplaceMainBlockCache(const std::deque<uint256>& deqHash)
{
    // Build the replacement outside the lock, then swap it in: a reader sees
    // the old cache or the new one, never an empty or half-built one.
    std::vector<uint256> vHash;
    std::map<uint256, MainBlockIndex> mapIndex;
    vHash.reserve(deqHash.size());
    for (const uint256& u : deqHash) {
        if (mapIndex.count(u))
            continue;
        MainBlockIndex index;
        index.hash = u;
        index.index = vHash.size();
        vHash.push_back(u);
        mapIndex[u] = index;
    }

    LOCK_MAIN_CACHE;
    vMainBlockHash.swap(vHash);
    mapMainBlock.swap(mapIndex);
}

bool BMMCache::GetMainBlockHashesFrom(int nHeight, size_t n, std::vector<uint256>& vHash) const
{
    LOCK_MAIN_CACHE;
    vHash.clear();
    if (nHeight < 0 || (size_t)nHeight + n > vMainBlockHash.size())
        return false;
    vHash.assign(vMainBlockHash.begin() + nHeight, vMainBlockHash.begin() + nHeight + n);
    return true;
}

uint256 BMMCache::GetMainBlockThroughT(const uint256& hashMain, const uint256& hashPrevMain) const
{
    LOCK_MAIN_CACHE;
    std::map<uint256, MainBlockIndex>::const_iterator it = mapMainBlock.find(hashMain);
    if (it != mapMainBlock.end() && it->second.index > 0 && vMainBlockHash[it->second.index - 1] == hashPrevMain)
        return hashMain;
    return GetMainChildBlockHashLocked(hashPrevMain);
}

void BMMCache::CacheWithdrawalID(const uint256& wtid)
{
    setWITHDRAWALIDCache.insert(wtid);
}

std::set<uint256> BMMCache::GetCachedWithdrawalID()
{
    return setWITHDRAWALIDCache;
}

bool BMMCache::IsMyWT(const uint256& wtid)
{
    return setWITHDRAWALIDCache.count(wtid);
}

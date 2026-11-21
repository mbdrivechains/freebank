#include <bmmcache.h>

#include <primitives/block.h>
#include <chainparams.h>
#include <hash.h>
#include <util.h>

// The main block cache (vMainBlockHash, mapMainBlock) has its own leaf mutex:
// nothing else is locked while it is held.
#define LOCK_MAIN_CACHE std::lock_guard<std::mutex> lockMainCache(csMainBlockCache)
// UR5-5: the bid state and the small sets beside it (see csBid in bmmcache.h), also a leaf mutex.
#define LOCK_BID std::lock_guard<std::mutex> lockBid(csBid)

BMMCache::BMMCache()
{

}

uint256 BMMCommitment(const CBlockHeader& header)
{
    // S5X-2 (switch-on, from genesis): the network (its genesis hash, as UR-ext-13 names it in payload signatures) and
    // every header field the L1 block doesn't fix. nTime and hashMainchainBlock are left out: the bid's L1 block E
    // sets both (CheckBlockBMMTime pins nTime to E).
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("FreeBank BMM commitment") << Params().GenesisBlock().GetHash() << header.nVersion
       << header.hashPrevBlock << header.hashMerkleRoot << header.hashWithdrawalBundle;
    return ss.GetHash();
}

bool BMMCache::StoreBMMBlock(const CBlock& block)
{
    LOCK_BID;
    if (!block.vtx.size())
        return false;

    const uint256 hashCommitment = BMMCommitment(block);   // S5X-2: keyed by what the bid carries

    // Already have block stored
    if (mapBMMBlocks.find(hashCommitment) != mapBMMBlocks.end())
        return false;

    mapBMMBlocks[hashCommitment] = block;

    return true;
}

bool BMMCache::GetBMMBlock(const uint256& hashCommitment, CBlock& block)
{
    LOCK_BID;
    if (mapBMMBlocks.find(hashCommitment) == mapBMMBlocks.end())
        return false;

    block = mapBMMBlocks[hashCommitment];

    return true;
}

std::vector<CBlock> BMMCache::GetBMMBlockCache() const
{
    LOCK_BID;
    std::vector<CBlock> vBlock;
    for (const auto& b : mapBMMBlocks) {
        vBlock.push_back(b.second);
    }
    return vBlock;
}

std::vector<uint256> BMMCache::GetBroadcastedWithdrawalBundleCache() const
{
    LOCK_BID;
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
    LOCK_BID;
    mapBMMBlocks.clear();
    hashResendPrev.SetNull();
    hashResendRoot.SetNull();
    nResendRefusals = 0;
}

void BMMCache::MarkBidResend(const uint256& hashPrevBlock, const uint256& hashMerkleRoot)
{
    LOCK_BID;
    if (hashPrevBlock != hashResendPrev || hashMerkleRoot != hashResendRoot) {
        hashResendPrev = hashPrevBlock;
        hashResendRoot = hashMerkleRoot;
        nResendRefusals = 0;
    }
    nResendRefusals++;
}

bool BMMCache::GetBidResend(const uint256& hashPrevBlock, uint256& hashMerkleRoot) const
{
    LOCK_BID;
    // The first refusal plus MAX_BID_RESENDS resends
    if (hashResendRoot.IsNull() || hashPrevBlock != hashResendPrev || nResendRefusals > MAX_BID_RESENDS)
        return false;
    hashMerkleRoot = hashResendRoot;
    return true;
}

void BMMCache::ClearBidResend()
{
    LOCK_BID;
    hashResendPrev.SetNull();
    hashResendRoot.SetNull();
    nResendRefusals = 0;
}

void BMMCache::StoreBroadcastedWithdrawalBundle(const uint256& hashWithdrawalBundle)
{
    LOCK_BID;
    setWithdrawalBundleBroadcasted.insert(hashWithdrawalBundle);
}

void BMMCache::ForgetBroadcastedWithdrawalBundle(const uint256& hashWithdrawalBundle)
{
    LOCK_BID;
    setWithdrawalBundleBroadcasted.erase(hashWithdrawalBundle);
}

void BMMCache::StorePrevBlockBMMCreated(const uint256& hashPrevBlock)
{
    LOCK_BID;
    setPrevBlockBMMCreated.insert(hashPrevBlock);
}

bool BMMCache::HaveBroadcastedWithdrawalBundle(const uint256& hashWithdrawalBundle) const
{
    LOCK_BID;
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

    std::lock_guard<std::mutex> lock(csVerified);
    return (setBMMVerified.count(hashBlock));
}

static const size_t MAX_MAIN_BLOCK_TIMES = 100000;

bool BMMCache::GetMainBlockTime(const uint256& hashMainBlock, uint32_t& nTime) const
{
    std::lock_guard<std::mutex> lock(csVerified);
    const auto it = mapMainBlockTime.find(hashMainBlock);
    if (it == mapMainBlockTime.end())
        return false;
    nTime = it->second;
    return true;
}

void BMMCache::CacheMainBlockTime(const uint256& hashMainBlock, uint32_t nTime)
{
    if (hashMainBlock.IsNull())
        return;

    std::lock_guard<std::mutex> lock(csVerified);
    if (mapMainBlockTime.size() >= MAX_MAIN_BLOCK_TIMES)
        mapMainBlockTime.clear();
    mapMainBlockTime[hashMainBlock] = nTime;
}

void BMMCache::CacheMainBlockCommitment(const uint256& hashMainBlock, bool fCommitted, const uint256& hashCommitment)
{
    if (hashMainBlock.IsNull())
        return;
    std::lock_guard<std::mutex> lock(csVerified);
    if (mapMainBlockCommitment.size() >= MAX_MAIN_BLOCK_TIMES)
        mapMainBlockCommitment.clear();
    mapMainBlockCommitment[hashMainBlock] = std::make_pair(fCommitted, fCommitted ? hashCommitment : uint256());
}

bool BMMCache::GetMainBlockCommitmentAnswer(const uint256& hashMainBlock, const uint256& hashBMM, bool& fYes) const
{
    std::lock_guard<std::mutex> lock(csVerified);
    const auto it = mapMainBlockCommitment.find(hashMainBlock);
    if (it == mapMainBlockCommitment.end())
        return false;
    fYes = it->second.first && it->second.second == hashBMM;
    return true;
}

bool BMMCache::HaveBmmPair(const uint256& hashMainBlock, const uint256& hashBMM) const
{
    std::lock_guard<std::mutex> lock(csVerified);
    return setBmmPair.count(std::make_pair(hashMainBlock, hashBMM)) > 0;
}

void BMMCache::CacheBmmPair(const uint256& hashMainBlock, const uint256& hashBMM)
{
    std::lock_guard<std::mutex> lock(csVerified);
    if (setBmmPair.size() >= MAX_MAIN_BLOCK_TIMES)
        setBmmPair.clear();
    setBmmPair.insert(std::make_pair(hashMainBlock, hashBMM));
}

void BMMCache::CacheVerifiedBMM(const uint256& hashBlock)
{
    if (hashBlock.IsNull())
        return;

    std::lock_guard<std::mutex> lock(csVerified);
    setBMMVerified.insert(hashBlock);
}

bool BMMCache::HaveVerifiedDeposit(const uint256& txid) const
{
    if (txid.IsNull())
        return false;

    std::lock_guard<std::mutex> lock(csVerified);
    return (setDepositVerified.count(txid));
}

void BMMCache::CacheVerifiedDeposit(const uint256& txid)
{
    if (txid.IsNull())
        return;

    std::lock_guard<std::mutex> lock(csVerified);
    setDepositVerified.insert(txid);
}

std::vector<uint256> BMMCache::GetVerifiedBMMCache() const
{
    std::lock_guard<std::mutex> lock(csVerified);
    std::vector<uint256> vHash;
    for (const auto& u : setBMMVerified) {
        vHash.push_back(u);
    }
    return vHash;
}

std::vector<uint256> BMMCache::GetVerifiedDepositCache() const
{
    std::lock_guard<std::mutex> lock(csVerified);
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
    // v0.2.25: a null hash holds the place of an L1 block below the pin that
    // was never fetched (the list stays indexed by L1 height). It is not
    // indexed, so no lookup ever finds it.
    if (hash.IsNull()) {
        vMainBlockHash.push_back(hash);
        return;
    }

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

bool BMMCache::GetMainBlockPositions(const uint256& hashA, const uint256& hashB, size_t& nA, size_t& nB) const
{
    LOCK_MAIN_CACHE;
    auto itA = mapMainBlock.find(hashA);
    auto itB = mapMainBlock.find(hashB);
    if (itA == mapMainBlock.end() || itB == mapMainBlock.end())
        return false;
    nA = itA->second.index;
    nB = itB->second.index;
    return true;
}

bool BMMCache::HaveMainBlock(const uint256& hash) const
{
    LOCK_MAIN_CACHE;
    return mapMainBlock.count(hash);
}

bool BMMCache::HaveBMMRequestForPrevBlock(const uint256& hashPrevBlock) const
{
    LOCK_BID;
    return setPrevBlockBMMCreated.count(hashPrevBlock);
}

void BMMCache::AddCheckedMainBlock(const uint256& hashBlock)
{
    LOCK_BID;
    setMainBlockChecked.insert(hashBlock);
}

bool BMMCache::MainBlockChecked(const uint256& hashBlock) const
{
    LOCK_BID;
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
        if (u.IsNull()) {   // v0.2.25: a placeholder below the pin (CacheMainBlockHashLocked)
            vHash.push_back(u);
            continue;
        }
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
    LOCK_BID;
    setWITHDRAWALIDCache.insert(wtid);
}

std::set<uint256> BMMCache::GetCachedWithdrawalID()
{
    LOCK_BID;
    return setWITHDRAWALIDCache;
}

bool BMMCache::IsMyWT(const uint256& wtid)
{
    LOCK_BID;
    return setWITHDRAWALIDCache.count(wtid);
}

// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <assert.h>
#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.hashWithdrawalBundle.SetNull(); // This could be some useful hash
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 */
static CBlock CreateGenesisBlock(uint32_t nTime, int32_t nVersion, const CAmount& genesisReward)
{
    // Note: For sidechains the timestamp should be:
    // "mainchainBlockHeight:mainchainBlockHash"
    const char* pszTimestamp = "nnnnnn:0xnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nVersion, genesisReward);
}

void CChainParams::UpdateChainDormant(bool fDormant)
{
    consensus.fChainDormant = fDormant;
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

// v0.2.18: the interest schedule must start at height 0 and be strictly
// increasing by height - NoteDeferralInterest sums its segments, so an unsorted
// or overlapping entry would double-count interest.
static bool DeferScheduleIsValid(const std::vector<Consensus::DeferInterestStep>& v)
{
    if (v.empty() || v[0].nHeight != 0)
        return false;
    for (size_t i = 1; i < v.size(); i++)
        if (v[i].nHeight <= v[i - 1].nHeight)
            return false;
    return true;
}

/**
 * FreeBank beta: the eCash betanet era (slot 130 since 2026-09). Until v0.2.19
 * this was the "main" network; its identity is unchanged (magic, genesis,
 * ports, the root data directory), and it is still what a node runs with no
 * flag, so a beta node upgrades with nothing to change.
 */
class CBetaParams : public CChainParams {
public:
    CBetaParams() {
        strNetworkID = "beta";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Height = 0;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;

        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.nSettleCadence = 144; // ~1 day of settlement exclusivity per house pair
        consensus.nDemandWindow = 1008;  // B3: ~1 week at 10-min — comfortably over honest downtime
        // v0.2.18 suspension (operator sign-off 2026-10-02): 10%/yr from block 0 on
        // queued and lapsed-B3 demands ("needs to discourage"); a later release may
        // APPEND a step at a future height, never edit a past one.
        consensus.vDeferInterestSchedule = {{0, 1000}};
        assert(DeferScheduleIsValid(consensus.vDeferInterestSchedule));
        consensus.nDeferSilenceWindow = 4032;  // ~4 weeks after 2 missed cadences
        consensus.nTokenClaimWindow = 4032;    // the token claim window: ~4 weeks from insolvency
        consensus.nOracleQuorumMin = 3;
        consensus.nOracleBrakePpmPerBlock = 347;  // ~5%/day / 144 blocks
        consensus.nOracleBrakeElapsedCap = 144;   // censor-charge bounded to one day's fall
        consensus.nOracleUnbondDelay = 2016;      // provisional; decorative while inert
        consensus.nOracleOpWindow = 6;            // ~1h at 144 blk/day: a price older than the
                                                  // row-1 hourly cadence promise can never enter a
                                                  // fix; 6 << the 144 brake cap; 2.1% of G3's ~2d
        // Withdrawal poison-row guard from genesis (operator sign-off 2026-09-24, H = 0).
        // Until v0.2.19 these params served BOTH the eCash beta and eCash mainnet, so one H
        // covered both; mainnet (CMainParams below) inherits it.
        // 0 is safe on beta only while no block of its FreeBank chain holds a withdrawal
        // object: only such a block can break the rule. Check that directly at the swap,
        // with v0.2.12 stopped so it cannot connect a block in between: no output in blocks
        // 1..tip has a scriptPubKey starting 6aacdcf66f57 (the withdrawal object header).
        // gettxoutsetinfo total_amount 0 (measured at height 10) is only a proxy: it leaves
        // out OP_RETURN outputs, and every withdrawal burn is one. And an upgraded node
        // re-connects only its last few blocks at startup, so a deeper violating block
        // would show up only as a fork on a fresh v0.2.13 sync.
        // Mainnet has the rule from its first block, so it never needs a flag day.
        consensus.nWithdrawalGuardHeight = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // By default assume that the signatures in ancestors of this block are valid.
        // v0.2.25: beta block 992, reached by a fresh sync from the seed with
        // v0.2.24 (every signature checked) on 2026-10-09 and the explorer's
        // hash at 992 on 2026-10-10 (docs-local/sync-speed-2026-10-10). Was the
        // genesis block: nothing skipped. Set again at each release.
        consensus.defaultAssumeValid = uint256S("0xa939cbd9118b7f5d0ffccaa3a3a7d3f447349e09a892a518c14df7ddb0eaef7b");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        // LOCKED (S-5, v0.1.0 M1 package, 2026-07-11)
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0x4b;
        pchMessageStart[2] = 0x18;
        pchMessageStart[3] = 0x45;
        nDefaultPort = 8455;
        nPruneAfterHeight = 100000;

        // The main network pairs with a CUSF-enforcer mainchain (L2L Signet /
        // eCash era): withdrawal bundles use the enforcer's BlindedM6 layout.
        // LOCKED (S-5, v0.1.0)
        fCUSFBundleFormat = true;

        genesis = CreateGenesisBlock(1668667160, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x359d17fc7cc60653fb72bbec271efab88af16ba9f15a55b060fe632c7de5e978"));
        assert(genesis.hashMerkleRoot == uint256S("0x8eb1364f43885edf1322b2d32095e57abb03c32a61a80ac25c8db3de58e16b8a"));

        vSeeds.clear();
        // Public DNS seed (added 2026-09-01, first FreeBank blocks live on eCash alpha). A dedicated (seed.ecxfreebank.com — freebank.com DNS is delegated+wildcarded)
        // subdomain resolving to the seed node, so the seed IP is repointable via DNS without a recompile.
        // Fresh nodes discover peers here on nDefaultPort (8455) with zero config.
        vSeeds.emplace_back("seed.ecxfreebank.com");

        // LOCKED (S-5, v0.1.0 M1 package, 2026-07-11).
        // Sidechain addresses: PUBKEY 75 / SCRIPT 125 (X... addresses).
        // MAINCHAIN_PUBKEY_ADDRESS is 111 because the v0.1.0-era mainchain is
        // L2L Signet, whose addresses carry the Bitcoin testnet prefix - a
        // prefix-0 setting would reject every real signet withdrawal
        // destination. Revisit only if the mainchain moves to a network with
        // different address prefixes.
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,75);
        base58Prefixes[MAINCHAIN_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[MAINCHAIN_REGTEST_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        // CONSENSUS-FROZEN: SCRIPT_ADDRESS and bech32_hrp are part of the L1 withdrawal
        // carrier encoding (mainchainaddress.h); changing them splits the chain.
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // LOCKED (S-5, v0.1.0 M1 package, 2026-07-11)
        bech32_hrp = "fbk";

        // A public network (eCash beta) exists, so ship the live seed as a hardcoded
        // fixed-seed fallback alongside the DNS seed above (pnSeed6_main = seed.ecxfreebank.com,
        // 163.47.9.132:8455, the seed droplet's reserved IP; v0.2.12 shipped its primary IP
        // 68.183.235.153). v0.1.0 cleared this because upstream pnSeed6_main pointed at dead
        // LayerTwo Labs nodes.
        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                { 0, uint256S("0x359d17fc7cc60653fb72bbec271efab88af16ba9f15a55b060fe632c7de5e978")},
            }
        };

        // TODO update these once your sidechain has been active for a while
        chainTxData = ChainTxData{
            // Data as of block 000000000000000000d97e53664d17967bd4ee50b23abb92e54a34eb222d15ae (height 478913).
            0, // * UNIX timestamp of last known number of transactions
            0, // * total number of transactions between genesis and that timestamp
               //   (the tx=... number in the SetBestChain debug.log lines)
            0  // * estimated number of transactions per second after that timestamp
        };
    }
};

/**
 * FreeBank mainnet, on eCash mainnet (opens 2026-10-31). Beta's rules from
 * block 0, its own identity: magic, genesis and data directory ("mainnet"),
 * the same ports and seed name (beta stops when mainnet starts, so the two
 * never need to run side by side). Ships DORMANT (genesis M1, option A).
 * No flag selects it in a beta build: the mainnet release runs it as its one
 * public network.
 */
class CMainParams : public CBetaParams {
public:
    CMainParams() {
        strNetworkID = "main";

        // v0.2.19: dormant until a later release switches it on
        consensus.fChainDormant = true;

        // Its own network: a mainnet node never talks to a beta node
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0x4b;
        pchMessageStart[2] = 0xec;
        pchMessageStart[3] = 0x58;

        genesis = CreateGenesisBlock("FreeBank mainnet genesis: eCash slot 130, 2026-10-04",
                                     CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG,
                                     1791072000, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        // LOCKED (v0.2.19, the release the mainnet M1 names)
        assert(consensus.hashGenesisBlock == uint256S("0x6e5a41bcc2793325e79d952de3766989f70181294e32f19b10d4968b74d919fc"));
        assert(genesis.hashMerkleRoot == uint256S("0xd0a6ddf613dfbf632067bed8386ee4f2afbb0d142a32ad413b283b53f5e3011e"));
        consensus.defaultAssumeValid = consensus.hashGenesisBlock;
        checkpointData = {
            {
                { 0, consensus.hashGenesisBlock },
            }
        };
        chainTxData = ChainTxData{0, 0, 0};
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Height = 0; // always enforce P2SH BIP16 on regtest
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for bitassetss
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.nSettleCadence = 12; // fast settle windows for tests + demo-rhythm chains
        consensus.nDemandWindow = 12;  // B3: gate-testable; ~8.4h on the 30s demo signet
        consensus.vDeferInterestSchedule = {{0, 1000}};  // same as main (10%/yr from block 0)
        assert(DeferScheduleIsValid(consensus.vDeferInterestSchedule));
        consensus.nDeferSilenceWindow = 40;    // gate-testable silence clock (main: 4032)
        consensus.nTokenClaimWindow = 20;      // gate-testable claim window (main: 4032)
        consensus.nOracleQuorumMin = 3;
        consensus.nOracleBrakePpmPerBlock = 100000; // 10%/block: brake behavior testable in few blocks
        consensus.nOracleBrakeElapsedCap = 12;
        consensus.nOracleUnbondDelay = 16;
        consensus.nOracleOpWindow = 3;            // mechanical floor 2 + 1 margin; small enough
                                                  // that the gate proves expiry in 3 blocks
        consensus.nWithdrawalGuardHeight = 0;     // poison-row guard active from genesis on regtest
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // v0.2.25: none on regtest, every script checked (was a hash inherited
        // from BitAssets, harmless while nothing skipped; a gate sets -assumevalid)
        consensus.defaultAssumeValid = uint256();

        // LOCKED (S-5, v0.1.0 M1 package, 2026-07-11)
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0x4b;
        pchMessageStart[2] = 0x18;
        pchMessageStart[3] = 0x47;
        nDefaultPort = 18456;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1691102346, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("0x7e666f858e27e4d079ac93ac2cbee743a6cd96ec021bcafe0eb63768734a67b3"));
        assert(genesis.hashMerkleRoot == uint256S("0x8eb1364f43885edf1322b2d32095e57abb03c32a61a80ac25c8db3de58e16b8a"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
            }
        };

        // Doesn't need to be updated
        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        // LOCKED (S-5, v0.1.0 M1 package, 2026-07-11)
        // PUBKEY_ADDRESS 75 / SCRIPT_ADDRESS 125 match the BTX mainchain for
        // Phase 1 deposit testing; provisional for the eCash era.
        base58Prefixes[MAINCHAIN_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[MAINCHAIN_REGTEST_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,75);
        // CONSENSUS-FROZEN (carrier encoding, mainchainaddress.h)
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // LOCKED (S-5, v0.1.0 M1 package, 2026-07-11)
        bech32_hrp = "fbkrt";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::BETA)
        return std::unique_ptr<CChainParams>(new CBetaParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

void UpdateChainDormantForTest(bool fDormant)
{
    globalChainParams->UpdateChainDormant(fDormant);
}

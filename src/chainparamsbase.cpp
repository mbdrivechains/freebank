// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparamsbase.h>

#include <tinyformat.h>
#include <util.h>

#include <assert.h>

const std::string CBaseChainParams::MAIN = "main";
const std::string CBaseChainParams::BETA = "beta";
const std::string CBaseChainParams::REGTEST = "regtest";

void AppendParamsHelpMessages(std::string& strUsage, bool debugHelp)
{
    strUsage += HelpMessageGroup(_("Chain selection options:"));
    if (debugHelp) {
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
                                   "This is intended for regression testing tools and app development.");
    }
}

static std::unique_ptr<CBaseChainParams> globalChainBaseParams;

const CBaseChainParams& BaseParams()
{
    assert(globalChainBaseParams);
    return *globalChainBaseParams;
}

std::unique_ptr<CBaseChainParams> CreateBaseChainParams(const std::string& chain)
{
    // LOCKED (S-5, v0.1.0 M1 package, 2026-07-11): RPC 8454 for the FreeBank
    // network. v0.2.19: mainnet and beta share it (they never run side by side)
    // but not the data directory: beta keeps the directory itself, as before;
    // mainnet lives in "mainnet".
    if (chain == CBaseChainParams::MAIN)
        return MakeUnique<CBaseChainParams>("mainnet", 8454);
    else if (chain == CBaseChainParams::BETA)
        return MakeUnique<CBaseChainParams>("", 8454);
    else if (chain == CBaseChainParams::REGTEST)
        return MakeUnique<CBaseChainParams>("regtest", 18457);
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectBaseParams(const std::string& chain)
{
    globalChainBaseParams = CreateBaseChainParams(chain);
}

std::string ChainNameFromCommandLine()
{
    // One public network per build (Michael, 2026-10-04): this build runs beta,
    // with no flag, as every release before it. FreeBank mainnet is in the code
    // (dormant) but no flag selects it: the mainnet release runs it the same way.
    bool fRegTest = gArgs.GetBoolArg("-regtest", false);

    if (fRegTest)
        return CBaseChainParams::REGTEST;

    return CBaseChainParams::BETA;
}

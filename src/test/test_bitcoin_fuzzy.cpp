// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <consensus/merkle.h>
#include <primitives/block.h>
#include <script/script.h>
#include <addrman.h>
#include <chain.h>
#include <coins.h>
#include <compressor.h>
#include <net.h>
#include <protocol.h>
#include <streams.h>
#include <undo.h>
#include <version.h>
#include <pubkey.h>
#include <blockencodings.h>

#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <crypto/common.h>
#include <primitives/transaction.h>

#include <bill.h>
#include <deposit.h>
#include <house.h>
#include <issued.h>
#include <note.h>
#include <pool.h>
#include <settle.h>
#include <token.h>

#include <chainparams.h>
#include <chainparamsbase.h>
#include <l1client.h>
#include <mainchainaddress.h>
#include <sidechain.h>
#include <univalue.h>
#include <util.h>
#include <utilstrencodings.h>

#include <stdint.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <vector>

enum TEST_ID {
    CBLOCK_DESERIALIZE=0,
    CTRANSACTION_DESERIALIZE,
    CBLOCKLOCATOR_DESERIALIZE,
    CBLOCKMERKLEROOT,
    CADDRMAN_DESERIALIZE,
    CBLOCKHEADER_DESERIALIZE,
    CBANENTRY_DESERIALIZE,
    CTXUNDO_DESERIALIZE,
    CBLOCKUNDO_DESERIALIZE,
    CCOINS_DESERIALIZE,
    CNETADDR_DESERIALIZE,
    CSERVICE_DESERIALIZE,
    CMESSAGEHEADER_DESERIALIZE,
    CADDRESS_DESERIALIZE,
    CINV_DESERIALIZE,
    CBLOOMFILTER_DESERIALIZE,
    CDISKBLOCKINDEX_DESERIALIZE,
    CTXOUTCOMPRESSOR_DESERIALIZE,
    BLOCKTRANSACTIONS_DESERIALIZE,
    BLOCKTRANSACTIONSREQUEST_DESERIALIZE,
    // FreeBank (C5). Appended, never inserted: a test id is the first four bytes
    // of every corpus file, so renumbering an existing id silently repoints the
    // whole accumulated corpus at the wrong target.
    FREEBANK_BILL_TX_CHECK,
    FREEBANK_HOUSE_TX_CHECK,
    FREEBANK_NOTE_TX_CHECK,
    FREEBANK_DEPOSIT_TX_CHECK,
    FREEBANK_POOL_TX_CHECK,
    FREEBANK_SETTLE_TX_CHECK,
    FREEBANK_ORACLE_TX_CHECK,
    // testing (FB-6 layer 3, 2026-11-11): the v18 issued-token family, and one round-trip target per payload family.
    FREEBANK_TOKEN_TX_CHECK,
    FREEBANK_HOUSE_PAYLOAD_ROUNDTRIP,
    FREEBANK_NOTE_PAYLOAD_ROUNDTRIP,
    FREEBANK_BILL_PAYLOAD_ROUNDTRIP,
    FREEBANK_DEPOSIT_PAYLOAD_ROUNDTRIP,
    FREEBANK_POOL_PAYLOAD_ROUNDTRIP,
    FREEBANK_SETTLE_PAYLOAD_ROUNDTRIP,
    FREEBANK_ISSUED_PAYLOAD_ROUNDTRIP,
    // testing (L1 inputs, 2026-11-13; security's addition to the FB-6 fuzz plan): what the node reads from the L1 and
    // the enforcer. Untrusted: a parser answers false ("can't read"), never throws, never reads a bad field as "no".
    FREEBANK_L1_ENFORCER_JSON,
    FREEBANK_L1_JSONRPC_DEPOSITS,
    FREEBANK_L1_RAW_TX,
    FREEBANK_MAINCHAIN_ADDRESS,
    // testing (NX-32, 2026-11-13): the BitAssets create transaction (v10), the one CheckTransaction family no target
    // reached (members, tokens and NET are covered by 27-34)
    FREEBANK_BITASSET_TX_CHECK,
    TEST_ID_END
};

/** Run the context-free FreeBank checks over an arbitrary transaction body.
 *
 * ECC: these checkers verify payload signatures, and CPubKey routes every one
 * through the global secp256k1_context_verify, which is a NULL POINTER until an
 * ECCVerifyHandle exists (pubkey.cpp:14) - so a signature-bearing input would
 * fault inside secp256k1 on a harness defect indistinguishable from a consensus
 * crash. This file's initialize() already builds that handle, and BOTH drivers
 * call it (main() directly, libFuzzer via LLVMFuzzerInitialize), so there is
 * nothing to add here - but any future driver that bypasses initialize() loses
 * the guarantee silently.
 *
 * CheckTransaction (consensus/tx_verify.cpp:166) is the single door every
 * FreeBank family comes through - it dispatches to CheckBill/House/Note/Deposit/
 * Pool/Settle/OracleTransactionShape purely on tx.nVersion - and it is what an
 * unauthenticated peer reaches before paying any cost. So this is the whole
 * attacker-reachable context-free surface behind one entry point.
 *
 * The version is FORCED rather than taken from the input. nVersion is a magic
 * gate: random bytes land on 11..17 about once in 2^29 mutations, so a target
 * that let the fuzzer choose would spend its entire budget re-testing the stock
 * Core paths and report coverage it never had. One test id per family also keeps
 * the corpus separable, so a crash tells you which consensus object owns it.
 *
 * THE VERSION IS PATCHED INTO THE STREAM, NOT ASSIGNED AFTERWARDS, and that
 * distinction is the whole target. UnserializeTransaction reads the op byte and
 * the payload blob ONLY inside `if (tx.nVersion == TRANSACTION_*_VERSION)`
 * (primitives/transaction.h:261-294), so a transaction deserialized under some
 * other version and then relabelled arrives with nBillOp == 0 and an EMPTY
 * payload. The checker would then run - and stay green forever - against a
 * payload the fuzzer never controlled, exercising nothing but the "payload
 * missing" rejection while reporting coverage of the decoder. Overwriting the
 * leading four bytes puts the fuzzer's own bytes into the op and the payload,
 * which is the surface we are actually trying to attack. */
static int freebank_check_tx(CDataStream& ds, int32_t nForcedVersion)
{
    std::vector<unsigned char> body(ds.begin(), ds.end());
    if (body.size() < sizeof(uint32_t)) return 0;
    WriteLE32(body.data(), static_cast<uint32_t>(nForcedVersion));

    CDataStream ds2(body, SER_NETWORK, ds.GetVersion());
    CMutableTransaction mtx;
    try {
        ds2 >> mtx;
    } catch (const std::ios_base::failure& e) {
        return 0;
    }

    const CTransaction tx(mtx);
    CValidationState state;
    const bool ok = CheckTransaction(tx, state);
    static const bool fStats = getenv("FB_FUZZ_STATS") != nullptr;   // testing (FB-6): the driver counts accepts
    if (fStats) fputs(ok ? "FB_FUZZ_ACCEPTED\n" : "FB_FUZZ_REJECTED\n", stderr);

    // A rejection MUST carry its reason. Several FreeBank checkers reject by
    // propagating a bare `return false` out of a helper that was handed `state`
    // (note.cpp CheckNoteOutputs, deposit.cpp CheckDepositReceiptOutputs,
    // pool.cpp), so a helper with one un-flagged failure path would reject a
    // peer's transaction while leaving the state valid - no reject reason, no
    // DoS score, and a caller that reads IsInvalid() to decide what to do
    // concludes nothing was wrong. That asymmetry is invisible to a no-crash
    // fuzzer, which is exactly why it is asserted here rather than assumed.
    assert(ok || state.IsInvalid());
    return 0;
}


/** testing (FB-6 layer 3, 2026-11-11): a payload has exactly one encoding.
 *
 * Every FreeBank payload is a byte blob inside the transaction, so it is part of the txid, while its signatures cover
 * the DECODED fields. If a decoder accepts bytes it would not write itself (a bool read from 0x02, a non-minimal
 * length, padding a field ignores), a relayer can rewrite those bytes under the same signatures: the same effects, a
 * new txid, and any unconfirmed child orphaned - the UR1-6 class, found there by reading. Here it is searched for:
 * whatever decodes must re-encode to the identical bytes. A crash or throw out of the decoder fails the target too
 * (the decoders are meant to turn every failure into `false`).
 *
 * Input after the stream version: one byte that picks the payload type (mod the family's count), then the payload. */
template <typename T, typename D>
static void freebank_roundtrip_as(const std::vector<unsigned char>& vch, D decode)
{
    T x;
    if (!decode(vch, x)) return;
    static const bool fStats = getenv("FB_FUZZ_STATS") != nullptr;   // the driver counts decodes (coverage)
    if (fStats) fputs("FB_FUZZ_DECODED\n", stderr);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << x;
    const std::vector<unsigned char> re(ss.begin(), ss.end());
    assert(re == vch);
}

#define FB_RT(T, DEC) [](const std::vector<unsigned char>& v) { \
        freebank_roundtrip_as<T>(v, [](const std::vector<unsigned char>& w, T& t) { return DEC<T>(w, t); }); }

static int freebank_payload_roundtrip(CDataStream& ds, const std::vector<void (*)(const std::vector<unsigned char>&)>& vTypes)
{
    std::vector<unsigned char> rest(ds.begin(), ds.end());
    if (rest.empty() || vTypes.empty()) return 0;
    const size_t nType = rest[0] % vTypes.size();
    rest.erase(rest.begin());
    vTypes[nType](rest);
    return 0;
}

static const std::vector<void (*)(const std::vector<unsigned char>&)>& HousePayloadTypes()
{
    static const std::vector<void (*)(const std::vector<unsigned char>&)> v{
        FB_RT(HouseRegister, DecodeHousePayload), FB_RT(HouseTopup, DecodeHousePayload),
        FB_RT(HouseAdmit, DecodeHousePayload), FB_RT(HouseExit, DecodeHousePayload),
        FB_RT(HouseWinddown, DecodeHousePayload), FB_RT(HouseReclaim, DecodeHousePayload),
        FB_RT(HouseAttest, DecodeHousePayload), FB_RT(HouseDefer, DecodeHousePayload),
        FB_RT(HouseRenew, DecodeHousePayload), FB_RT(HouseRelease, DecodeHousePayload),
        FB_RT(HouseRegisterMO, DecodeHousePayload), FB_RT(HouseMemberOp, DecodeHousePayload),
        FB_RT(HouseRate, DecodeHousePayload), FB_RT(HouseCharter, DecodeHousePayload),
        FB_RT(HouseClose, DecodeHousePayload)};
    return v;
}
static const std::vector<void (*)(const std::vector<unsigned char>&)>& NotePayloadTypes()
{
    static const std::vector<void (*)(const std::vector<unsigned char>&)> v{
        FB_RT(NoteMint, DecodeNotePayload), FB_RT(NoteTransfer, DecodeNotePayload),
        FB_RT(NoteRedeem, DecodeNotePayload), FB_RT(NoteClaim, DecodeNotePayload),
        FB_RT(NoteDemand, DecodeNotePayload), FB_RT(NoteProtest, DecodeNotePayload),
        FB_RT(NoteLock, DecodeNotePayload), FB_RT(NoteUnlock, DecodeNotePayload),
        FB_RT(NoteTokenKeyset, DecodeNotePayload), FB_RT(NoteTokenPost, DecodeNotePayload),
        FB_RT(NoteTokenClaim, DecodeNotePayload), FB_RT(NoteTokenCollect, DecodeNotePayload),
        FB_RT(NoteSwap, DecodeNotePayload), FB_RT(NoteSwapDone, DecodeNotePayload),
        FB_RT(NoteSwapPay, DecodeNotePayload), FB_RT(NoteSwapProtest, DecodeNotePayload),
        FB_RT(NoteSwapExpire, DecodeNotePayload), FB_RT(NoteSwapClaim, DecodeNotePayload)};
    return v;
}
static const std::vector<void (*)(const std::vector<unsigned char>&)>& BillPayloadTypes()
{
    static const std::vector<void (*)(const std::vector<unsigned char>&)> v{
        FB_RT(BillIssue, DecodeBillPayload), FB_RT(BillEndorse, DecodeBillPayload),
        FB_RT(BillRetire, DecodeBillPayload), FB_RT(BillClaim, DecodeBillPayload),
        FB_RT(BillDiscount, DecodeBillPayload), FB_RT(BillRecourse, DecodeBillPayload),
        FB_RT(BillHRetire, DecodeBillPayload), FB_RT(BillHRetireNotes, DecodeBillPayload),
        FB_RT(BillHClaimEscrow, DecodeBillPayload), FB_RT(BillHClaim, DecodeBillPayload)};
    return v;
}
static const std::vector<void (*)(const std::vector<unsigned char>&)>& DepositPayloadTypes()
{
    static const std::vector<void (*)(const std::vector<unsigned char>&)> v{
        FB_RT(DepositOriginate, DecodeDepositPayload), FB_RT(DepositTransfer, DecodeDepositPayload),
        FB_RT(DepositWithdraw, DecodeDepositPayload), FB_RT(DepositClaim, DecodeDepositPayload),
        FB_RT(DepositDemand, DecodeDepositPayload), FB_RT(DepositProtest, DecodeDepositPayload),
        FB_RT(DepositDischarge, DecodeDepositPayload)};
    return v;
}
static const std::vector<void (*)(const std::vector<unsigned char>&)>& PoolPayloadTypes()
{
    static const std::vector<void (*)(const std::vector<unsigned char>&)> v{
        FB_RT(PoolCreate, DecodePoolPayload), FB_RT(PoolAddLiq, DecodePoolPayload),
        FB_RT(PoolRemoveLiq, DecodePoolPayload), FB_RT(PoolSwap, DecodePoolPayload),
        FB_RT(PoolRetire, DecodePoolPayload)};
    return v;
}
static const std::vector<void (*)(const std::vector<unsigned char>&)>& SettlePayloadTypes()
{
    static const std::vector<void (*)(const std::vector<unsigned char>&)> v{
        FB_RT(SettleExchange, DecodeSettlePayload), FB_RT(SettleNet, DecodeSettlePayload)};
    return v;
}
static const std::vector<void (*)(const std::vector<unsigned char>&)>& IssuedPayloadTypes()
{
    static const std::vector<void (*)(const std::vector<unsigned char>&)> v{
        FB_RT(IssuedCreate, DecodeIssuedPayload), FB_RT(IssuedMint, DecodeIssuedPayload),
        FB_RT(IssuedBurn, DecodeIssuedPayload), FB_RT(IssuedFreeze, DecodeIssuedPayload),
        FB_RT(IssuedPoolCreate, DecodeIssuedPayload), FB_RT(IssuedPoolAdd, DecodeIssuedPayload),
        FB_RT(IssuedPoolRemove, DecodeIssuedPayload), FB_RT(IssuedPoolSwap, DecodeIssuedPayload)};
    return v;
}


/** testing (L1 inputs, 2026-11-13): the node's readers of L1 and enforcer answers.
 *
 * Each reader returns bool: false is "can't read this" (the caller treats it as UNKNOWN and retries). So the rules
 * checked here, beyond no crash under ASan/UBSan:
 *  - nothing throws out of a reader (a throw skips the caller's UNKNOWN handling; on a scheduler or validation thread
 *    it ends the node). FB_FUZZ_ALLOW_THROW=1 counts throws instead, to keep searching past a known one;
 *  - a present but unreadable BMM commitment is "can't tell" (false), never "none" (l1client.cpp ReadCommitmentField,
 *    layer-B review BMM L2: a "none" marks the side block invalid for good);
 *  - ParsePegEvents and BuildJsonRpcDepositEvents never hand over half an answer, and every deposit value they hand
 *    over is in MoneyRange (ParsePegEvents's own check on valueSats; the JSON-RPC reader feeds the same records);
 *  - what the wallet stores for a mainchain address (EncodeMainchainCarrier) decodes, under the withdrawal guard's and
 *    the bundle's decoder (MainchainPayoutScriptAnyFamily, peg map 5), to the very script the user gave.
 * A failed rule prints FB_ORACLE_FAIL and aborts, so libFuzzer keeps the input. */
static bool FbStats() { static const bool f = getenv("FB_FUZZ_STATS") != nullptr; return f; }
static bool FbAllowThrow() { static const bool f = getenv("FB_FUZZ_ALLOW_THROW") != nullptr; return f; }

static void FbOracleFail(const std::string& what)
{
    fprintf(stderr, "FB_ORACLE_FAIL: %s\n", what.c_str());
    abort();
}

/** Run one reader; an exception out of it fails the target (or is counted, under FB_FUZZ_ALLOW_THROW). False if it threw. */
template <typename F>
static bool FbNoThrow(const char* name, F f)
{
    try {
        f();
        return true;
    } catch (const std::exception& e) {
        if (FbAllowThrow()) {
            if (FbStats()) fprintf(stderr, "FB_FUZZ_THREW %s\n", name);
            return false;
        }
        FbOracleFail(std::string(name) + " threw: " + e.what());
    }
    return false;
}

static bool FbIsZeroCommitmentHex(const UniValue& field)
{
    const UniValue& hex = find_value(field, "hex");
    return hex.isStr() && hex.get_str().size() == 64 && IsHex(hex.get_str()) &&
           Uint256FromConsensusHex(hex.get_str()).IsNull();
}

/** Input after the stream version: one selector byte (which reader), then the reply's JSON text. */
static int freebank_l1_enforcer_json(CDataStream& ds)
{
    const std::vector<unsigned char> v(ds.begin(), ds.end());
    if (v.empty()) return 0;
    const unsigned nSel = v[0] % 10;
    UniValue r;
    if (!r.read(std::string(v.begin() + 1, v.end()))) return 0;
    if (FbStats()) fputs("FB_FUZZ_DECODED\n", stderr);

    switch (nSel) {
    case 0: {
        L1BlockHeader h;
        FbNoThrow("ParseEnforcerChainTip", [&] { ParseEnforcerChainTip(r, h); });
        break;
    }
    case 1: {
        std::vector<L1BlockHeader> vh;
        FbNoThrow("ParseEnforcerHeaderInfos", [&] { ParseEnforcerHeaderInfos(r, vh); });
        break;
    }
    case 2: {
        bool fFound = false, fHave = false, ok = false;
        uint256 h;
        if (!FbNoThrow("ParseEnforcerBmmCommitment", [&] { ok = ParseEnforcerBmmCommitment(r, fFound, fHave, h); })) break;
        if (ok && fHave && (!fFound || h.IsNull()))
            FbOracleFail("ParseEnforcerBmmCommitment: a commitment without a block, or a null one");
        if (ok && fFound && !fHave) {
            const UniValue& f = find_value(find_value(r, "commitment"), "commitment");
            if (!f.isNull() && !FbIsZeroCommitmentHex(f))
                FbOracleFail("ParseEnforcerBmmCommitment read a present, unreadable commitment as 'none'");
        }
        break;
    }
    case 3: {
        std::vector<std::pair<bool, uint256>> vc;
        bool ok = false;
        if (!FbNoThrow("ParseEnforcerBmmCommitments", [&] { ok = ParseEnforcerBmmCommitments(r, vc); })) break;
        if (!ok) break;
        if (vc.empty()) FbOracleFail("ParseEnforcerBmmCommitments: true with no entry for the block itself");
        for (const auto& c : vc)
            if (c.first == c.second.IsNull()) FbOracleFail("ParseEnforcerBmmCommitments: fHave disagrees with the hash");
        // the block's own field: present and unreadable must be false, as in the single read
        const UniValue& f = find_value(find_value(r, "commitment"), "commitment");
        if (!vc[0].first && !f.isNull() && !FbIsZeroCommitmentHex(f))
            FbOracleFail("ParseEnforcerBmmCommitments read a present, unreadable commitment as 'none'");
        // an ancestor read as "none" must be absent or zero too (the loop stops at the first unreadable one)
        const UniValue& anc = find_value(find_value(r, "commitment"), "ancestorCommitments");
        for (size_t i = 1; i < vc.size(); i++) {
            if (vc[i].first) continue;
            const UniValue& af = find_value(anc[i - 1], "commitment");
            if (!af.isNull() && !FbIsZeroCommitmentHex(af))
                FbOracleFail("ParseEnforcerBmmCommitments read a present, unreadable ancestor commitment as 'none'");
        }
        break;
    }
    case 4: {
        std::vector<uint256> vt;
        FbNoThrow("ParseEnforcerBlockDepositTxids", [&] { ParseEnforcerBlockDepositTxids(r, vt); });
        break;
    }
    case 5: {
        uint256 txid;
        uint32_t n = 0;
        FbNoThrow("ParseEnforcerCtip", [&] { ParseEnforcerCtip(r, txid, n); });
        break;
    }
    case 6: {
        std::vector<L1WithdrawalEvent> ve;
        bool ok = false;
        if (!FbNoThrow("ParseEnforcerWithdrawalEvents", [&] { ok = ParseEnforcerWithdrawalEvents(r, ve); })) break;
        if (!ok) break;
        std::vector<uint256> vPending;
        FbNoThrow("PendingM6idsFromEvents", [&] { vPending = PendingM6idsFromEvents(ve); });
        const std::set<uint256> setPending(vPending.begin(), vPending.end());
        if (setPending.size() != vPending.size()) FbOracleFail("PendingM6idsFromEvents: an m6id pending twice");
        std::vector<uint256> vHash;
        for (const L1WithdrawalEvent& e : ve) vHash.push_back(e.m6id);
        FbNoThrow("L1StillTracksWithdrawalBundle", [&] { L1StillTracksWithdrawalBundle(ve, vHash); });
        break;
    }
    case 7: {
        L1PegEvents ev;
        bool ok = false;
        if (!FbNoThrow("ParsePegEvents", [&] { ok = ParsePegEvents(r, ev); })) break;
        if (!ok && (!ev.vDeposit.empty() || !ev.vWithdrawal.empty()))
            FbOracleFail("ParsePegEvents: false but handed over part of the reply");
        for (const L1DepositEvent& d : ev.vDeposit)
            if (!MoneyRange(d.nValue)) FbOracleFail("ParsePegEvents: a deposit value outside MoneyRange");
        for (const L1WithdrawalEvent& w : ev.vWithdrawal)
            if (w.status != 'S' && w.status != 'F' && w.status != 'U') FbOracleFail("ParsePegEvents: an unknown status");
        break;
    }
    case 8: {
        EnforcerSettings st;
        bool ok = false;
        if (!FbNoThrow("ParseEnforcerChainInfo", [&] { ok = ParseEnforcerChainInfo(r, st); })) break;
        if (ok) FbNoThrow("CompareEnforcerSettings", [&] { CompareEnforcerSettings(v.size() > 1 ? v[1] * 4032 : 0, st); });
        break;
    }
    case 9: {
        FbNoThrow("ChainNameFromEnforcerChainInfo", [&] { ChainNameFromEnforcerChainInfo(r); });
        break;
    }
    }
    return 0;
}

/** Input after the stream version: one byte (bit 7 set: no start height; else the start height), then the JSON array
 *  BitcoinX's listsidechaindepositsbyblock would answer. Heights come from the block hash, so the fuzzer steers them;
 *  a hash whose low word is a multiple of 97 is "height unknown". */
static int freebank_l1_jsonrpc_deposits(CDataStream& ds)
{
    const std::vector<unsigned char> v(ds.begin(), ds.end());
    if (v.empty()) return 0;
    const int nStart = (v[0] & 0x80) ? -1 : (v[0] & 0x7f);
    UniValue r;
    if (!r.read(std::string(v.begin() + 1, v.end()))) return 0;
    if (FbStats()) fputs("FB_FUZZ_DECODED\n", stderr);
    const std::function<bool(const uint256&, int&)> fnHeight = [](const uint256& h, int& n) {
        const uint64_t w = h.GetUint64(0);
        if (w % 97 == 0 && w != 0) return false;
        n = (int)(w % 300) - 2;
        return true;
    };
    std::vector<L1DepositEvent> vOut;
    bool ok = false;
    if (!FbNoThrow("BuildJsonRpcDepositEvents", [&] { ok = BuildJsonRpcDepositEvents(r, fnHeight, nStart, vOut); })) return 0;
    if (!ok && !vOut.empty()) FbOracleFail("BuildJsonRpcDepositEvents: false but handed over part of the answer");
    for (const L1DepositEvent& d : vOut)
        if (!MoneyRange(d.nValue))
            FbOracleFail("BuildJsonRpcDepositEvents: a deposit value outside MoneyRange (ParsePegEvents refuses one)");
    return 0;
}

/** Input after the stream version: one selector byte, then a REST raw-tx body (text) or a raw L1 block. */
static int freebank_l1_raw_tx(CDataStream& ds)
{
    const std::vector<unsigned char> v(ds.begin(), ds.end());
    if (v.empty()) return 0;
    const std::vector<unsigned char> body(v.begin() + 1, v.end());
    CMutableTransaction tx;
    if (v[0] & 1) {
        FbNoThrow("ClassifyRawTxBody", [&] { ClassifyRawTxBody(std::string(body.begin(), body.end()), tx); });
    } else {
        // a null txid matches nothing, so every transaction in the block is read
        int nTx = -1;
        L1TxFetch res = L1TxFetch::OK;
        if (!FbNoThrow("FindL1TxInBlock", [&] { res = FindL1TxInBlock(body, uint256(), tx, nTx); })) return 0;
        if (res == L1TxFetch::OK) FbOracleFail("FindL1TxInBlock: found a transaction with a null txid");
    }
    return 0;
}

/** Input after the stream version: one byte (bit 0: regtest, else main), then an address as a user would type it, or
 *  as stored in a withdrawal row. */
static int freebank_mainchain_address(CDataStream& ds)
{
    const std::vector<unsigned char> v(ds.begin(), ds.end());
    if (v.empty()) return 0;
    const bool fRegtest = v[0] & 1;
    gArgs.ForceSetArg("-regtest", fRegtest ? "1" : "0");
    SelectParams(fRegtest ? CBaseChainParams::REGTEST : CBaseChainParams::MAIN);
    const std::string str(v.begin() + 1, v.end());

    // What the row guard and the bundle read from a stored destination
    CScript spkStored;
    FbNoThrow("MainchainPayoutScriptAnyFamily", [&] { spkStored = MainchainPayoutScriptAnyFamily(str); });
    FbNoThrow("MainchainDisplayAddress", [&] { MainchainDisplayAddress(str); });

    // What the wallet stores for an address the user typed: it must pay exactly that script
    CScript spk;
    std::string strError;
    bool ok = false;
    if (!FbNoThrow("ParseMainchainAddress", [&] { ok = ParseMainchainAddress(str, spk, strError); })) return 0;
    for (const CScript& s : {spk, spkStored}) {
        if (s.empty()) continue;
        std::string strCarrier;
        if (!FbNoThrow("EncodeMainchainCarrier", [&] { strCarrier = EncodeMainchainCarrier(s); })) continue;
        if (strCarrier.empty()) continue;
        if (FbStats()) fputs("FB_FUZZ_ACCEPTED\n", stderr);
        CScript spkBack;
        FbNoThrow("MainchainPayoutScriptAnyFamily", [&] { spkBack = MainchainPayoutScriptAnyFamily(strCarrier); });
        if (spkBack != s)
            FbOracleFail("the withdrawal guard/bundle decoder reads the wallet's carrier as a different script");
        if (MainchainPayoutScript(strCarrier) != s)
            FbOracleFail("MainchainPayoutScript reads the wallet's carrier as a different script");
    }

    // The consensus deposit-address grammar (GetDepositPayoutOutput, sidechain.cpp): one spelling only, exactly what
    // GenerateDepositAddress makes ("s130_" + address + "_" + 6 hex of its SHA256)
    std::string strDepAddr;
    bool fDep = false;
    if (FbNoThrow("ParseFullDepositAddress", [&] { fDep = ParseFullDepositAddress(str, strDepAddr); }) && fDep) {
        if (FbStats()) fputs("FB_FUZZ_DECODED\n", stderr);
        if (GenerateDepositAddress(strDepAddr) != str)
            FbOracleFail("ParseFullDepositAddress accepted a spelling GenerateDepositAddress does not make");
    }
    return 0;
}

bool read_stdin(std::vector<uint8_t> &data) {
    uint8_t buffer[1024];
    ssize_t length=0;
    while((length = read(STDIN_FILENO, buffer, 1024)) > 0) {
        data.insert(data.end(), buffer, buffer+length);

        if (data.size() > (1<<20)) return false;
    }
    return length==0;
}

int test_one_input(std::vector<uint8_t> buffer) {
    if (buffer.size() < sizeof(uint32_t)) return 0;

    uint32_t test_id = 0xffffffff;
    memcpy(&test_id, buffer.data(), sizeof(uint32_t));
    buffer.erase(buffer.begin(), buffer.begin() + sizeof(uint32_t));

    if (test_id >= TEST_ID_END) return 0;

    CDataStream ds(buffer, SER_NETWORK, INIT_PROTO_VERSION);
    try {
        int nVersion;
        ds >> nVersion;
        ds.SetVersion(nVersion);
    } catch (const std::ios_base::failure& e) {
        return 0;
    }

    switch(test_id) {
        case CBLOCK_DESERIALIZE:
        {
            try
            {
                CBlock block;
                ds >> block;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CTRANSACTION_DESERIALIZE:
        {
            try
            {
                CTransaction tx(deserialize, ds);
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKLOCATOR_DESERIALIZE:
        {
            try
            {
                CBlockLocator bl;
                ds >> bl;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKMERKLEROOT:
        {
            try
            {
                CBlock block;
                ds >> block;
                bool mutated;
                BlockMerkleRoot(block, &mutated);
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CADDRMAN_DESERIALIZE:
        {
            try
            {
                CAddrMan am;
                ds >> am;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKHEADER_DESERIALIZE:
        {
            try
            {
                CBlockHeader bh;
                ds >> bh;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBANENTRY_DESERIALIZE:
        {
            try
            {
                CBanEntry be;
                ds >> be;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CTXUNDO_DESERIALIZE:
        {
            try
            {
                CTxUndo tu;
                ds >> tu;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOCKUNDO_DESERIALIZE:
        {
            try
            {
                CBlockUndo bu;
                ds >> bu;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CCOINS_DESERIALIZE:
        {
            try
            {
                Coin coin;
                ds >> coin;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CNETADDR_DESERIALIZE:
        {
            try
            {
                CNetAddr na;
                ds >> na;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CSERVICE_DESERIALIZE:
        {
            try
            {
                CService s;
                ds >> s;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CMESSAGEHEADER_DESERIALIZE:
        {
            CMessageHeader::MessageStartChars pchMessageStart = {0x00, 0x00, 0x00, 0x00};
            try
            {
                CMessageHeader mh(pchMessageStart);
                ds >> mh;
                if (!mh.IsValid(pchMessageStart)) {return 0;}
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CADDRESS_DESERIALIZE:
        {
            try
            {
                CAddress a;
                ds >> a;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CINV_DESERIALIZE:
        {
            try
            {
                CInv i;
                ds >> i;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CBLOOMFILTER_DESERIALIZE:
        {
            try
            {
                CBloomFilter bf;
                ds >> bf;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CDISKBLOCKINDEX_DESERIALIZE:
        {
            try
            {
                CDiskBlockIndex dbi;
                ds >> dbi;
            } catch (const std::ios_base::failure& e) {return 0;}
            break;
        }
        case CTXOUTCOMPRESSOR_DESERIALIZE:
        {
            CTxOut to;
            CTxOutCompressor toc(to);
            try
            {
                ds >> toc;
            } catch (const std::ios_base::failure& e) {return 0;}

            break;
        }
        case BLOCKTRANSACTIONS_DESERIALIZE:
        {
            try
            {
                BlockTransactions bt;
                ds >> bt;
            } catch (const std::ios_base::failure& e) {return 0;}

            break;
        }
        case BLOCKTRANSACTIONSREQUEST_DESERIALIZE:
        {
            try
            {
                BlockTransactionsRequest btr;
                ds >> btr;
            } catch (const std::ios_base::failure& e) {return 0;}

            break;
        }
        case FREEBANK_BILL_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_BILL_VERSION);
        case FREEBANK_HOUSE_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_HOUSE_VERSION);
        case FREEBANK_NOTE_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_NOTE_VERSION);
        case FREEBANK_DEPOSIT_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_DEPOSIT_VERSION);
        case FREEBANK_POOL_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_POOL_VERSION);
        case FREEBANK_SETTLE_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_SETTLE_VERSION);
        case FREEBANK_ORACLE_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_ORACLE_VERSION);
        case FREEBANK_TOKEN_TX_CHECK:
            return freebank_check_tx(ds, TRANSACTION_TOKEN_VERSION);
        case FREEBANK_HOUSE_PAYLOAD_ROUNDTRIP:   return freebank_payload_roundtrip(ds, HousePayloadTypes());
        case FREEBANK_NOTE_PAYLOAD_ROUNDTRIP:    return freebank_payload_roundtrip(ds, NotePayloadTypes());
        case FREEBANK_BILL_PAYLOAD_ROUNDTRIP:    return freebank_payload_roundtrip(ds, BillPayloadTypes());
        case FREEBANK_DEPOSIT_PAYLOAD_ROUNDTRIP: return freebank_payload_roundtrip(ds, DepositPayloadTypes());
        case FREEBANK_POOL_PAYLOAD_ROUNDTRIP:    return freebank_payload_roundtrip(ds, PoolPayloadTypes());
        case FREEBANK_SETTLE_PAYLOAD_ROUNDTRIP:  return freebank_payload_roundtrip(ds, SettlePayloadTypes());
        case FREEBANK_ISSUED_PAYLOAD_ROUNDTRIP:  return freebank_payload_roundtrip(ds, IssuedPayloadTypes());
        case FREEBANK_L1_ENFORCER_JSON:          return freebank_l1_enforcer_json(ds);
        case FREEBANK_L1_JSONRPC_DEPOSITS:       return freebank_l1_jsonrpc_deposits(ds);
        case FREEBANK_L1_RAW_TX:                 return freebank_l1_raw_tx(ds);
        case FREEBANK_MAINCHAIN_ADDRESS:         return freebank_mainchain_address(ds);
        case FREEBANK_BITASSET_TX_CHECK:         return freebank_check_tx(ds, TRANSACTION_BITASSET_CREATE_VERSION);
        default:
            return 0;
    }
    return 0;
}

static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;
void initialize() {
    globalVerifyHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
    // testing (L1 inputs): the address and L1 readers consult Params(); the address target re-selects per input
    SelectParams(CBaseChainParams::MAIN);
}

// This function is used by libFuzzer
// testing (L1 inputs): FB_FUZZ_ID=<n> pins one target, so libFuzzer mutates only that target's input (the id and the
// stream version are put in front of each input); unset, the first eight bytes pick them as before.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const char* pszId = getenv("FB_FUZZ_ID");
    if (pszId) {
        std::vector<uint8_t> buf(8);
        const uint32_t nId = (uint32_t)atoi(pszId);
        const int32_t nVer = PROTOCOL_VERSION;
        memcpy(buf.data(), &nId, 4);
        memcpy(buf.data() + 4, &nVer, 4);
        buf.insert(buf.end(), data, data + size);
        test_one_input(buf);
        return 0;
    }
    test_one_input(std::vector<uint8_t>(data, data + size));
    return 0;
}

// This function is used by libFuzzer
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    initialize();
    return 0;
}

// Disabled under WIN32 due to clash with Cygwin's WinMain.
#ifndef WIN32
// Declare main(...) "weak" to allow for libFuzzer linking. libFuzzer provides
// the main(...) function.
__attribute__((weak))
#endif
int main(int argc, char **argv)
{
    initialize();
#ifdef __AFL_INIT
    // Enable AFL deferred forkserver mode. Requires compilation using
    // afl-clang-fast++. See fuzzing.md for details.
    __AFL_INIT();
#endif

#ifdef __AFL_LOOP
    // Enable AFL persistent mode. Requires compilation using afl-clang-fast++.
    // See fuzzing.md for details.
    int ret = 0;
    while (__AFL_LOOP(1000)) {
        std::vector<uint8_t> buffer;
        if (!read_stdin(buffer)) {
            continue;
        }
        ret = test_one_input(buffer);
    }
    return ret;
#else
    std::vector<uint8_t> buffer;
    if (!read_stdin(buffer)) {
        return 0;
    }
    return test_one_input(buffer);
#endif
}

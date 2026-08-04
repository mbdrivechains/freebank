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

#include <stdint.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
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
        default:
            return 0;
    }
    return 0;
}

static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;
void initialize() {
    globalVerifyHandle = std::unique_ptr<ECCVerifyHandle>(new ECCVerifyHandle());
}

// This function is used by libFuzzer
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
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

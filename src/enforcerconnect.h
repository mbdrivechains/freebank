// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ENFORCERCONNECT_H
#define BITCOIN_ENFORCERCONNECT_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

/**
 * v0.2.17: the Connect-protocol client for the CUSF bip300301_enforcer
 * (-enforcertransport=connect, the default). It replaces one grpcurl process
 * per query with a persistent HTTP/1.1 connection.
 *
 * The enforcer (connectrpc 0.9) serves gRPC and the Connect protocol on the same
 * port. A Connect unary call is a plain HTTP/1.1 POST of proto3 JSON:
 *
 *   POST /cusf.mainchain.v1.ValidatorService/GetChainTip HTTP/1.1
 *   Content-Type: application/json
 *   Connect-Protocol-Version: 1
 *
 * The reply is the response message as proto3 JSON (HTTP 200: camelCase keys,
 * 64-bit integers as strings, bytes as base64, default values left out), the
 * same JSON grpcurl prints, so the existing parsers read it unchanged. An error
 * is a non-200 status with {"code": "not_found", "message": "..."}. The request
 * JSON is the same text the grpcurl transport sends: the enforcer's JSON codec
 * (buffa) accepts both the proto field names (block_hash) and the camelCase ones.
 *
 * Every outcome is reported in grpcurl's exit-status convention, so the failure
 * classifiers in l1client.h (ClassifyGrpcurlFailure, GrpcurlBMMRequestNotSent)
 * serve both transports unchanged:
 *   0               success; strOutput = the reply JSON
 *   64 + gRPC code  the enforcer answered an error; strOutput is grpcurl's error
 *                   text, "ERROR:\n  Code: NotFound\n  Message: <message>\n"
 *   1               client side: the dial failed (strOutput starts "Failed to dial
 *                   target host", as grpcurl's does; the request was never sent),
 *                   or the call timed out or broke after the request went out (it
 *                   may have reached the enforcer)
 *
 * Only unary calls: none of FreeBank's enforcer calls is server-streaming.
 */
namespace enforcerconnect {

/** Per-call budget of the existing call sites: grpcurl's -max-time 15. */
static const int DEFAULT_CALL_TIMEOUT = 15;
/** The longest budget a call may ask for (consensus calls). */
static const int MAX_CALL_TIMEOUT = 60;
/** A reply larger than this fails the call (grpcurl's default was 4 MiB). */
static const size_t MAX_REPLY_SIZE = 64 << 20;
/** Tries to open a connection before a call gives up: waits of 250, 500, 1000 ms in between. */
static const int DIAL_TRIES = 4;
/** Idle keep-alive connections kept per client. */
static const size_t MAX_IDLE = 4;

/** Split host:port. The host may be [v6]; an http:// prefix is dropped. False on no port. Pure. */
bool SplitHostPort(const std::string& strAddr, std::string& strHost, std::string& strPort);

/** The HTTP/1.1 request text of one Connect unary call. nTimeoutMs > 0 adds
 *  Connect-Timeout-Ms, so the enforcer can stop work the client gave up on. Pure. */
std::string BuildRequest(const std::string& strAddr, const std::string& strService, const std::string& strMethod,
                         const std::string& strBody, int64_t nTimeoutMs);

/** gRPC status code of a Connect error code ("not_found" -> 5); 2 (Unknown) if unrecognised. Pure. */
int GrpcCodeFromConnectName(const std::string& strCode);

/** grpcurl's name of a gRPC status code (5 -> "NotFound"). Pure. */
std::string GrpcCodeName(int nCode);

/** The gRPC code the Connect spec gives an HTTP status whose body carries no Connect error
 *  (404 -> Unimplemented, as for a service the enforcer does not register). Pure. */
int GrpcCodeFromHttpStatus(int nHttpStatus);

/** One complete HTTP reply -> grpcurl-convention status and output (see above). Pure. */
int ReplyToStatus(int nHttpStatus, const std::string& strContentEncoding, const std::string& strBody, std::string& strOutput);

/** Incremental HTTP/1.1 response parser: Content-Length, chunked, or close-delimited bodies. */
class HttpReplyParser
{
public:
    enum State { INCOMPLETE, DONE, BAD };

    /** Append received bytes; DONE once a whole reply is in. */
    State Feed(const char* pch, size_t n);
    /** The peer closed the connection: DONE for a close-delimited body, else BAD. */
    State Finish();

    int nStatus = 0;
    std::string strBody;
    std::string strContentEncoding;
    bool fKeepAlive = false;      //!< the connection may carry another request
    std::string strError;         //!< why BAD
    size_t nReceived = 0;         //!< bytes fed so far

private:
    State Parse();
    State Bad(const std::string& strWhy);

    std::string buf;
    bool fHeaders = false;
    bool fChunked = false;
    bool fCloseDelimited = false;
    int64_t nContentLength = -1;
    State state = INCOMPLETE;
};

/**
 * The client. Thread-safe: each call takes an idle connection (or opens one),
 * uses it alone, and puts it back if the reply allows keep-alive.
 */
class Client
{
public:
    ~Client();

    /**
     * One unary call. nTimeoutSecs (clamped to 1..MAX_CALL_TIMEOUT) bounds the
     * whole call, dial retries included. fRetrySafe: the call has no side effect
     * a repeat could double, so it may run on a reused connection and be resent
     * once on a fresh one if the reused one turns out dead before any reply byte.
     * A call that is not retry-safe always opens its own connection and is never
     * resent once written. Returns the grpcurl-convention status (see above).
     */
    int Call(const std::string& strAddr, const std::string& strService, const std::string& strMethod,
             const std::string& strRequest, int nTimeoutSecs, bool fRetrySafe, std::string& strOutput);

    /** Close every idle connection. */
    void CloseIdle();

    /** Connections opened so far (unit tests check reuse with it). */
    uint64_t Dials() const { return nDials.load(); }

private:
    int TakeIdle(const std::string& strAddr);
    void PutIdle(const std::string& strAddr, int fd);
    int Dial(const std::string& strHost, const std::string& strPort, int64_t nDeadlineMs, std::string& strError);

    std::mutex mutexIdle;
    std::vector<std::pair<std::string, int>> vIdle;
    std::atomic<uint64_t> nDials{0};
};

} // namespace enforcerconnect

#endif // BITCOIN_ENFORCERCONNECT_H

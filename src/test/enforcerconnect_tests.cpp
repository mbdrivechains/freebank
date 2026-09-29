// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// v0.2.17: the Connect-protocol enforcer client (enforcerconnect.h) - request
// text, reply parsing, error mapping, and the socket client against an
// in-process fake enforcer (connection reuse, a stale keep-alive connection, a
// refused dial with its backoff, a timeout), then the real EnforcerL1Client
// driven through the fake over -enforcertransport=connect.

#include <enforcerconnect.h>
#include <l1client.h>

#include <test/test_bitcoin.h>
#include <uint256.h>
#include <util.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <boost/test/unit_test.hpp>

using namespace enforcerconnect;

namespace {

/** An HTTP/1.1 server on 127.0.0.1 (a thread per connection) that answers Connect
 *  unary calls through a handler. Knobs (atomics) let a test misbehave on purpose. */
class FakeEnforcer
{
public:
    typedef std::function<std::pair<int, std::string>(const std::string& strPath, const std::string& strBody)> Handler;

    explicit FakeEnforcer(Handler handlerIn, int nPortIn = 0) : handler(std::move(handlerIn))
    {
        fdListen = socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(fdListen, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sa.sin_port = htons(nPortIn);
        BOOST_REQUIRE(bind(fdListen, (struct sockaddr*)&sa, sizeof(sa)) == 0);
        BOOST_REQUIRE(listen(fdListen, 8) == 0);
        socklen_t len = sizeof(sa);
        getsockname(fdListen, (struct sockaddr*)&sa, &len);
        nPort = ntohs(sa.sin_port);
        thread = std::thread([this] { Run(); });
    }
    ~FakeEnforcer()
    {
        fStop = true;
        thread.join();
        for (std::thread& t : vConn)
            t.join();
        close(fdListen);
    }

    std::string Addr() const { return "127.0.0.1:" + std::to_string(nPort); }

    std::atomic<int> nAccepted{0};
    std::atomic<int> nRequests{0};
    std::atomic<bool> fCloseAfterReply{false}; //!< close each connection after one reply, with no Connection: close
    std::atomic<int> nDropNext{0};             //!< read the next N requests, then close without a reply
    std::atomic<bool> fChunked{false};         //!< chunked replies
    std::atomic<int> nStallMs{0};              //!< wait this long before replying

    std::string LastRequest()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return strLastRequest;
    }

private:
    void Run()
    {
        while (!fStop) {
            struct pollfd pfd = {fdListen, POLLIN, 0};
            if (poll(&pfd, 1, 50) <= 0)
                continue;
            int fd = accept(fdListen, nullptr, nullptr);
            if (fd < 0)
                continue;
            nAccepted++;
            vConn.emplace_back([this, fd] {
                Serve(fd);
                close(fd);
            });
        }
    }

    /** Read one request (headers + Content-Length body). False on EOF / stop. */
    bool ReadRequest(int fd, std::string& buf, std::string& strHead, std::string& strBody)
    {
        for (;;) {
            size_t nEnd = buf.find("\r\n\r\n");
            if (nEnd != std::string::npos) {
                strHead = buf.substr(0, nEnd);
                size_t nCl = strHead.find("Content-Length: ");
                size_t nLen = nCl == std::string::npos ? 0 : (size_t)atoi(strHead.c_str() + nCl + 16);
                if (buf.size() >= nEnd + 4 + nLen) {
                    strBody = buf.substr(nEnd + 4, nLen);
                    buf.erase(0, nEnd + 4 + nLen);
                    return true;
                }
            }
            struct pollfd pfd = {fd, POLLIN, 0};
            int r = poll(&pfd, 1, 50);
            if (fStop)
                return false;
            if (r <= 0)
                continue;
            char tmp[4096];
            ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
            if (n <= 0)
                return false;
            buf.append(tmp, n);
        }
    }

    void Serve(int fd)
    {
        std::string buf;
        for (;;) {
            std::string strHead, strBody;
            if (!ReadRequest(fd, buf, strHead, strBody))
                return;
            nRequests++;
            {
                std::lock_guard<std::mutex> lock(mutex);
                strLastRequest = strHead + "\r\n\r\n" + strBody;
            }
            if (nDropNext.fetch_sub(1) > 0)
                return;
            nDropNext.fetch_add(1);
            if (nStallMs > 0) {
                int64_t nUntil = GetTimeMillis() + nStallMs;
                while (!fStop && GetTimeMillis() < nUntil)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            size_t nSp = strHead.find(' ');
            std::string strPath = strHead.substr(nSp + 1, strHead.find(' ', nSp + 1) - nSp - 1);
            std::pair<int, std::string> reply = handler(strPath, strBody);
            std::string strOut = "HTTP/1.1 " + std::to_string(reply.first) + " X\r\nContent-Type: application/json\r\n";
            if (fChunked) {
                strOut += "Transfer-Encoding: chunked\r\n\r\n";
                const std::string& b = reply.second;
                for (size_t i = 0; i < b.size(); i += 7) {
                    std::string c = b.substr(i, 7);
                    char hex[16];
                    snprintf(hex, sizeof(hex), "%zx", c.size());
                    strOut += std::string(hex) + "\r\n" + c + "\r\n";
                }
                strOut += "0\r\n\r\n";
            } else {
                strOut += "Content-Length: " + std::to_string(reply.second.size()) + "\r\n\r\n" + reply.second;
            }
            send(fd, strOut.data(), strOut.size(), MSG_NOSIGNAL);
            if (fCloseAfterReply)
                return;
        }
    }

    Handler handler;
    int fdListen = -1;
    int nPort = 0;
    std::atomic<bool> fStop{false};
    std::thread thread;
    std::vector<std::thread> vConn;
    std::mutex mutex;
    std::string strLastRequest;
};

/** A port nothing listens on (bound, then closed). */
int DeadPort()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd, (struct sockaddr*)&sa, sizeof(sa));
    socklen_t len = sizeof(sa);
    getsockname(fd, (struct sockaddr*)&sa, &len);
    close(fd);
    return ntohs(sa.sin_port);
}

const std::string TIP_JSON = "{\"blockHeaderInfo\": {\"blockHash\": {\"hex\": "
    "\"00000000000000000000000000000000000000000000000000000000000000ff\"}, \"height\": 100}}";

} // namespace

BOOST_FIXTURE_TEST_SUITE(enforcerconnect_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(enforcerconnect_split_host_port)
{
    std::string h, p;
    BOOST_CHECK(SplitHostPort("127.0.0.1:50051", h, p));
    BOOST_CHECK_EQUAL(h, "127.0.0.1");
    BOOST_CHECK_EQUAL(p, "50051");
    BOOST_CHECK(SplitHostPort("localhost:50051", h, p));
    BOOST_CHECK_EQUAL(h, "localhost");
    BOOST_CHECK(SplitHostPort("http://127.0.0.1:50051/", h, p));
    BOOST_CHECK_EQUAL(h, "127.0.0.1");
    BOOST_CHECK_EQUAL(p, "50051");
    BOOST_CHECK(SplitHostPort("[::1]:50051", h, p));
    BOOST_CHECK_EQUAL(h, "::1");
    BOOST_CHECK_EQUAL(p, "50051");
    BOOST_CHECK(!SplitHostPort("127.0.0.1", h, p));
    BOOST_CHECK(!SplitHostPort("127.0.0.1:", h, p));
    BOOST_CHECK(!SplitHostPort(":50051", h, p));
    BOOST_CHECK(!SplitHostPort("127.0.0.1:0", h, p));
    BOOST_CHECK(!SplitHostPort("127.0.0.1:65536", h, p));
    BOOST_CHECK(!SplitHostPort("127.0.0.1:5x", h, p));
    BOOST_CHECK(!SplitHostPort("::1:50051", h, p));
    BOOST_CHECK(!SplitHostPort("[::1]50051", h, p));
}

BOOST_AUTO_TEST_CASE(enforcerconnect_build_request)
{
    const std::string strBody = "{\"block_hash\": {\"hex\": \"ab\"}, \"max_ancestors\": 999}";
    const std::string strReq = BuildRequest("127.0.0.1:50051", "cusf.mainchain.v1.ValidatorService", "GetBlockHeaderInfo", strBody, 15000);
    BOOST_CHECK_EQUAL(strReq,
        "POST /cusf.mainchain.v1.ValidatorService/GetBlockHeaderInfo HTTP/1.1\r\n"
        "Host: 127.0.0.1:50051\r\n"
        "User-Agent: freebankd\r\n"
        "Content-Type: application/json\r\n"
        "Connect-Protocol-Version: 1\r\n"
        "Connect-Timeout-Ms: 15000\r\n"
        "Content-Length: " + std::to_string(strBody.size()) + "\r\n"
        "\r\n" + strBody);
    // No timeout header without a budget; the Host keeps IPv6 brackets, loses a scheme
    const std::string strReq2 = BuildRequest("http://[::1]:50051", "s", "m", "{}", 0);
    BOOST_CHECK(strReq2.find("Connect-Timeout-Ms") == std::string::npos);
    BOOST_CHECK(strReq2.find("Host: [::1]:50051\r\n") != std::string::npos);
    BOOST_CHECK_EQUAL(strReq2.find("POST /s/m HTTP/1.1\r\n"), 0U);
}

BOOST_AUTO_TEST_CASE(enforcerconnect_codes)
{
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("canceled"), 1);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("invalid_argument"), 3);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("deadline_exceeded"), 4);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("not_found"), 5);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("failed_precondition"), 9);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("unimplemented"), 12);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("unavailable"), 14);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("unauthenticated"), 16);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("bogus"), 2);
    BOOST_CHECK_EQUAL(GrpcCodeFromConnectName("ok"), 2);
    BOOST_CHECK_EQUAL(GrpcCodeName(5), "NotFound");
    BOOST_CHECK_EQUAL(GrpcCodeName(12), "Unimplemented");
    BOOST_CHECK_EQUAL(GrpcCodeName(99), "Code(99)");
    BOOST_CHECK_EQUAL(GrpcCodeFromHttpStatus(404), 12);
    BOOST_CHECK_EQUAL(GrpcCodeFromHttpStatus(503), 14);
    BOOST_CHECK_EQUAL(GrpcCodeFromHttpStatus(400), 13);
    BOOST_CHECK_EQUAL(GrpcCodeFromHttpStatus(500), 2);
}

BOOST_AUTO_TEST_CASE(enforcerconnect_reply_to_status)
{
    std::string out;
    // Success: the body is passed through untouched (the parsers read it)
    BOOST_CHECK_EQUAL(ReplyToStatus(200, "", TIP_JSON, out), 0);
    BOOST_CHECK_EQUAL(out, TIP_JSON);
    BOOST_CHECK_EQUAL(ReplyToStatus(200, "identity", "{}", out), 0);

    // A Connect error: 64 + gRPC code, grpcurl's error text
    BOOST_CHECK_EQUAL(ReplyToStatus(404, "", "{\"code\":\"not_found\",\"message\":\"block not found\"}", out), 69);
    BOOST_CHECK_EQUAL(out, "ERROR:\n  Code: NotFound\n  Message: block not found\n");
    BOOST_CHECK_EQUAL(ReplyToStatus(400, "", "{\"code\":\"invalid_argument\",\"message\":\"invalid prev_bytes\",\"details\":[]}", out), 67);
    BOOST_CHECK_EQUAL(ReplyToStatus(500, "", "{\"code\":\"unknown\",\"message\":\"error creating BMM request: failed to build BMM tx: Insufficient funds\"}", out), 66);
    BOOST_CHECK(out.find("failed to build BMM tx") != std::string::npos);
    BOOST_CHECK_EQUAL(ReplyToStatus(501, "", "{\"code\":\"unimplemented\"}", out), 76);
    BOOST_CHECK_EQUAL(out, "ERROR:\n  Code: Unimplemented\n  Message: \n");

    // No Connect error body: the HTTP status decides (404 = a service or method the enforcer lacks)
    BOOST_CHECK_EQUAL(ReplyToStatus(404, "", "", out), 76);
    BOOST_CHECK(out.find("Message: HTTP 404") != std::string::npos);
    BOOST_CHECK_EQUAL(ReplyToStatus(503, "", "<html>busy</html>", out), 78);
    BOOST_CHECK(out.find("HTTP 503: <html>busy</html>") != std::string::npos);
    BOOST_CHECK_EQUAL(ReplyToStatus(500, "", "not json", out), 66);

    // A compressed reply was never asked for
    BOOST_CHECK_EQUAL(ReplyToStatus(200, "gzip", "x", out), 1);

    // The classifiers read Connect outcomes the way they read grpcurl's
    BOOST_CHECK(ClassifyGrpcurlFailure(ReplyToStatus(404, "", "", out), out) == GrpcurlFailure::UNIMPLEMENTED);
    BOOST_CHECK(ClassifyGrpcurlFailure(ReplyToStatus(503, "", "", out), out) == GrpcurlFailure::OTHER);
    BOOST_CHECK(GrpcurlBMMRequestNotSent(ReplyToStatus(400, "", "{\"code\":\"invalid_argument\",\"message\":\"x\"}", out), out));
    BOOST_CHECK(GrpcurlBMMRequestNotSent(ReplyToStatus(400, "", "{\"code\":\"failed_precondition\",\"message\":\"x\"}", out), out));
    int n = ReplyToStatus(500, "", "{\"code\":\"unknown\",\"message\":\"failed to sign BMM tx: x\"}", out);
    BOOST_CHECK(GrpcurlBMMRequestNotSent(n, out));
    n = ReplyToStatus(500, "", "{\"code\":\"unknown\",\"message\":\"failed to broadcast BMM request tx via RPC: x\"}", out);
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(n, out));
    n = ReplyToStatus(504, "", "{\"code\":\"deadline_exceeded\",\"message\":\"x\"}", out);
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(n, out));
}

BOOST_AUTO_TEST_CASE(enforcerconnect_reply_parser)
{
    // Content-Length, split across feeds at every byte
    {
        const std::string r = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-length: 2\r\n\r\n{}";
        HttpReplyParser p;
        HttpReplyParser::State s = HttpReplyParser::INCOMPLETE;
        for (size_t i = 0; i < r.size(); ++i) {
            BOOST_CHECK(s == HttpReplyParser::INCOMPLETE);
            s = p.Feed(r.data() + i, 1);
        }
        BOOST_CHECK(s == HttpReplyParser::DONE);
        BOOST_CHECK_EQUAL(p.nStatus, 200);
        BOOST_CHECK_EQUAL(p.strBody, "{}");
        BOOST_CHECK(p.fKeepAlive);
    }
    // Chunked, with a chunk extension and a trailer
    {
        const std::string r = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\n{\"a\r\n4\r\n\": 1\r\n1\r\n}\r\n0\r\nGrpc-Status: 0\r\n\r\n";
        HttpReplyParser p;
        BOOST_CHECK(p.Feed(r.data(), r.size() - 3) == HttpReplyParser::INCOMPLETE);
        BOOST_CHECK(p.Feed(r.data() + r.size() - 3, 3) == HttpReplyParser::DONE);
        BOOST_CHECK_EQUAL(p.strBody, "{\"a\": 1}");
        BOOST_CHECK(p.fKeepAlive);
    }
    // Close-delimited (no length): complete only when the peer closes; never reused
    {
        const std::string r = "HTTP/1.1 200 OK\r\n\r\n{\"x\":1}";
        HttpReplyParser p;
        BOOST_CHECK(p.Feed(r.data(), r.size()) == HttpReplyParser::INCOMPLETE);
        BOOST_CHECK(p.Finish() == HttpReplyParser::DONE);
        BOOST_CHECK_EQUAL(p.strBody, "{\"x\":1}");
        BOOST_CHECK(!p.fKeepAlive);
    }
    // Connection: close and HTTP/1.0 are not reused
    {
        const std::string r = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        HttpReplyParser p;
        BOOST_CHECK(p.Feed(r.data(), r.size()) == HttpReplyParser::DONE);
        BOOST_CHECK(!p.fKeepAlive);
        const std::string r10 = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        HttpReplyParser p10;
        BOOST_CHECK(p10.Feed(r10.data(), r10.size()) == HttpReplyParser::DONE);
        BOOST_CHECK(!p10.fKeepAlive);
    }
    // An interim 100 Continue is skipped
    {
        const std::string r = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nabc";
        HttpReplyParser p;
        BOOST_CHECK(p.Feed(r.data(), r.size()) == HttpReplyParser::DONE);
        BOOST_CHECK_EQUAL(p.nStatus, 404);
        BOOST_CHECK_EQUAL(p.strBody, "abc");
    }
    // Content-Encoding is reported, lowercased
    {
        const std::string r = "HTTP/1.1 200 OK\r\nContent-Encoding: GZIP\r\nContent-Length: 0\r\n\r\n";
        HttpReplyParser p;
        BOOST_CHECK(p.Feed(r.data(), r.size()) == HttpReplyParser::DONE);
        BOOST_CHECK_EQUAL(p.strContentEncoding, "gzip");
    }
    // Malformed
    {
        HttpReplyParser p;
        const std::string r = "SSH-2.0-OpenSSH\r\n\r\n";
        BOOST_CHECK(p.Feed(r.data(), r.size()) == HttpReplyParser::BAD);
        HttpReplyParser p2;
        const std::string r2 = "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n";
        BOOST_CHECK(p2.Feed(r2.data(), r2.size()) == HttpReplyParser::BAD);
        HttpReplyParser p3;
        const std::string r3 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
        BOOST_CHECK(p3.Feed(r3.data(), r3.size()) == HttpReplyParser::BAD);
        HttpReplyParser p4;
        const std::string r4 = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
        BOOST_CHECK(p4.Feed(r4.data(), r4.size()) == HttpReplyParser::INCOMPLETE);
        BOOST_CHECK(p4.Finish() == HttpReplyParser::BAD); // closed mid-body
    }
}

BOOST_AUTO_TEST_CASE(enforcerconnect_client_against_fake)
{
    FakeEnforcer fake([](const std::string& strPath, const std::string& strBody) -> std::pair<int, std::string> {
        if (strPath == "/cusf.mainchain.v1.ValidatorService/GetChainTip")
            return {200, TIP_JSON};
        if (strPath == "/cusf.mainchain.v1.ValidatorService/GetBlockHeaderInfo")
            return {404, "{\"code\":\"not_found\",\"message\":\"block not found: " + std::to_string(strBody.size()) + " bytes\"}"};
        return {404, ""};
    });
    Client client;
    std::string out;

    // Two calls share one keep-alive connection
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 5, true, out), 0);
    BOOST_CHECK_EQUAL(out, TIP_JSON);
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 5, true, out), 0);
    BOOST_CHECK_EQUAL(client.Dials(), 1U);
    BOOST_CHECK_EQUAL(fake.nAccepted.load(), 1);
    const std::string strReq = fake.LastRequest();
    BOOST_CHECK_EQUAL(strReq.find("POST /cusf.mainchain.v1.ValidatorService/GetChainTip HTTP/1.1\r\n"), 0U);
    BOOST_CHECK(strReq.find("Content-Type: application/json\r\n") != std::string::npos);
    BOOST_CHECK(strReq.find("Connect-Protocol-Version: 1\r\n") != std::string::npos);
    BOOST_CHECK(strReq.find("Connect-Timeout-Ms: ") != std::string::npos);
    BOOST_CHECK(strReq.substr(strReq.size() - 4) == "\r\n{}");

    // An enforcer error comes back as 64 + code with the message
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetBlockHeaderInfo", "{\"block_hash\": {}}", 5, true, out), 69);
    BOOST_CHECK(out.find("Code: NotFound") != std::string::npos);
    BOOST_CHECK(out.find("Message: block not found: 18 bytes\n") != std::string::npos);
    // A service the enforcer does not register: a bare 404 = Unimplemented (the D7 fallback's trigger)
    int n = client.Call(fake.Addr(), "cusf.mainchain.v1.BlockProducerService", "ProposeWithdrawalBundle", "{}", 5, true, out);
    BOOST_CHECK_EQUAL(n, 76);
    BOOST_CHECK(ClassifyGrpcurlFailure(n, out) == GrpcurlFailure::UNIMPLEMENTED);
    BOOST_CHECK_EQUAL(client.Dials(), 1U); // error replies keep the connection too

    // Chunked replies
    fake.fChunked = true;
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 5, true, out), 0);
    BOOST_CHECK_EQUAL(out, TIP_JSON);
    fake.fChunked = false;

    // The enforcer closed the idle connection: the next call notices before sending and dials again
    fake.fCloseAfterReply = true;
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 5, true, out), 0);
    const uint64_t nDials = client.Dials();
    std::this_thread::sleep_for(std::chrono::milliseconds(100)); // let the close arrive
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 5, true, out), 0);
    BOOST_CHECK_EQUAL(client.Dials(), nDials + 1);
    fake.fCloseAfterReply = false;

    // A reused connection that dies before any reply byte: a retry-safe call is resent once on a fresh one
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 5, true, out), 0);
    const int nReq = fake.nRequests.load();
    const uint64_t nDials2 = client.Dials();
    fake.nDropNext = 1;
    BOOST_CHECK_EQUAL(client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 5, true, out), 0);
    BOOST_CHECK_EQUAL(out, TIP_JSON);
    BOOST_CHECK_EQUAL(fake.nRequests.load(), nReq + 2);
    BOOST_CHECK_EQUAL(client.Dials(), nDials2 + 1);

    // A call that is not retry-safe (the BMM bid) opens its own connection and is never resent:
    // dropped after the request went out, it fails as "may have been sent"
    const int nReq2 = fake.nRequests.load();
    const uint64_t nDials3 = client.Dials();
    fake.nDropNext = 1;
    n = client.Call(fake.Addr(), "cusf.mainchain.v1.WalletService", "CreateBmmCriticalDataTransaction", "{}", 5, false, out);
    BOOST_CHECK_EQUAL(n, 1);
    BOOST_CHECK(out.find("Connect transport: cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction") == 0);
    BOOST_CHECK_EQUAL(fake.nRequests.load(), nReq2 + 1);
    BOOST_CHECK_EQUAL(client.Dials(), nDials3 + 1);
    BOOST_CHECK(!GrpcurlBMMRequestNotSent(n, out));

    // A timeout: the enforcer takes longer than the budget
    fake.nStallMs = 3000;
    const int64_t nStart = GetTimeMillis();
    n = client.Call(fake.Addr(), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 1, true, out);
    const int64_t nTook = GetTimeMillis() - nStart;
    BOOST_CHECK_EQUAL(n, 1);
    BOOST_CHECK(out.find("timed out waiting for the reply") != std::string::npos);
    BOOST_CHECK(nTook >= 900 && nTook < 2500);
    BOOST_CHECK(fake.LastRequest().find("Connect-Timeout-Ms: 1000\r\n") != std::string::npos ||
                fake.LastRequest().find("Connect-Timeout-Ms: 99") != std::string::npos);
    fake.nStallMs = 0;
}

BOOST_AUTO_TEST_CASE(enforcerconnect_dial_retry_and_give_up)
{
    Client client;
    std::string out;
    const std::string strDead = "127.0.0.1:" + std::to_string(DeadPort());

    // Refused: DIAL_TRIES tries with 250 + 500 + 1000 ms between them, then a grpcurl-style dial failure
    int64_t nStart = GetTimeMillis();
    int n = client.Call(strDead, "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 15, true, out);
    int64_t nTook = GetTimeMillis() - nStart;
    BOOST_CHECK_EQUAL(n, 1);
    BOOST_CHECK_EQUAL(out.find("Failed to dial target host \"" + strDead + "\": connect: "), 0U);
    BOOST_CHECK(nTook >= 1700 && nTook < 5000);
    BOOST_CHECK(ClassifyGrpcurlFailure(n, out) == GrpcurlFailure::OTHER);
    BOOST_CHECK(GrpcurlBMMRequestNotSent(n, out)); // never reached the enforcer
    BOOST_CHECK_EQUAL(client.Dials(), 0U);

    // The retries never run past the call's budget
    nStart = GetTimeMillis();
    client.Call(strDead, "s", "m", "{}", 1, true, out);
    nTook = GetTimeMillis() - nStart;
    BOOST_CHECK(nTook < 1500);

    // A bad address is a dial failure, not a crash
    BOOST_CHECK_EQUAL(client.Call("nonsense", "s", "m", "{}", 1, true, out), 1);
    BOOST_CHECK_EQUAL(out.find("Failed to dial target host \"nonsense\""), 0U);

    // An enforcer that comes up during the backoff is reached (the dials before it were refused)
    const int nLatePort = DeadPort();
    std::unique_ptr<FakeEnforcer> pLate;
    std::thread late([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        pLate.reset(new FakeEnforcer([](const std::string&, const std::string&) -> std::pair<int, std::string> {
            return {200, TIP_JSON};
        }, nLatePort));
    });
    nStart = GetTimeMillis();
    n = client.Call("127.0.0.1:" + std::to_string(nLatePort), "cusf.mainchain.v1.ValidatorService", "GetChainTip", "{}", 15, true, out);
    nTook = GetTimeMillis() - nStart;
    late.join();
    BOOST_CHECK_EQUAL(n, 0);
    BOOST_CHECK_EQUAL(out, TIP_JSON);
    BOOST_CHECK(nTook >= 250);
    BOOST_CHECK_EQUAL(client.Dials(), 1U);
    client.CloseIdle();
    pLate.reset();
}

// The real EnforcerL1Client over -enforcertransport=connect against the fake:
// the same scenarios l1client_bundle_guard_through_enforcer_client runs through
// a fake grpcurl, plus the BMM bid's not-sent classification.
BOOST_AUTO_TEST_CASE(enforcerconnect_through_enforcer_client)
{
    std::mutex mutexPeg;
    std::string strPeg = "{\"blocks\": []}";
    std::string strBmmReply = "{\"txid\": {\"hex\": \"00000000000000000000000000000000000000000000000000000000000000aa\"}}";
    int nBmmStatus = 200;
    FakeEnforcer fake([&](const std::string& strPath, const std::string& strBody) -> std::pair<int, std::string> {
        std::lock_guard<std::mutex> lock(mutexPeg);
        if (strPath == "/cusf.mainchain.v1.ValidatorService/GetChainTip")
            return {200, TIP_JSON};
        if (strPath == "/cusf.mainchain.v1.ValidatorService/GetTwoWayPegData")
            return {200, strPeg};
        if (strPath == "/cusf.mainchain.v1.WalletService/CreateBmmCriticalDataTransaction")
            return {nBmmStatus, strBmmReply};
        return {404, ""};
    });
    gArgs.ForceSetArg("-enforcertransport", "connect");
    gArgs.ForceSetArg("-enforceraddr", fake.Addr());

    L1Client& client = GetEnforcerL1Client();
    const std::string X(64, '1');
    auto blk = [](const std::string& strM6, const std::string& strEvent) {
        return "{\"blockInfo\": {\"events\": [{\"withdrawalBundle\": {\"m6id\": {\"hex\": \"" + strM6 +
               "\"}, \"event\": {\"" + strEvent + "\": {}}}}]}}";
    };
    {
        std::lock_guard<std::mutex> lock(mutexPeg);
        strPeg = "{\"blocks\": [" + blk(X, "submitted") + "]}";
    }
    std::vector<uint256> vHash;
    BOOST_CHECK(client.ListWithdrawalBundleStatus(vHash));
    BOOST_CHECK_EQUAL(vHash.size(), 1U);
    BOOST_CHECK(fake.LastRequest().find("\"end_block_hash\": {\"hex\": \"00000000000000000000000000000000000000000000000000000000000000ff\"}") != std::string::npos);
    {
        std::lock_guard<std::mutex> lock(mutexPeg);
        strPeg = "{\"blocks\": [" + blk(X, "submitted") + "," + blk(X, "succeeded") + "]}";
    }
    vHash.clear();
    BOOST_CHECK(!client.ListWithdrawalBundleStatus(vHash));
    BOOST_CHECK(vHash.empty());

    int nBlocks = 0;
    BOOST_CHECK(client.GetBlockCount(nBlocks));
    BOOST_CHECK_EQUAL(nBlocks, 100);

    // The bid: a txid back; a refusal (InvalidArgument) = not sent; a broadcast error = may have gone out
    bool fNotSent = true;
    uint256 txid = client.SendBMMRequest(uint256S("01"), uint256S("ff"), 101, 1000, fNotSent);
    BOOST_CHECK_EQUAL(txid.GetHex(), std::string(62, '0') + "aa");
    BOOST_CHECK(!fNotSent);
    {
        std::lock_guard<std::mutex> lock(mutexPeg);
        nBmmStatus = 400;
        strBmmReply = "{\"code\":\"invalid_argument\",\"message\":\"invalid prev_bytes\"}";
    }
    txid = client.SendBMMRequest(uint256S("01"), uint256S("ff"), 101, 1000, fNotSent);
    BOOST_CHECK(txid.IsNull());
    BOOST_CHECK(fNotSent);
    {
        std::lock_guard<std::mutex> lock(mutexPeg);
        nBmmStatus = 500;
        strBmmReply = "{\"code\":\"unknown\",\"message\":\"failed to broadcast BMM request tx via RPC: x\"}";
    }
    txid = client.SendBMMRequest(uint256S("01"), uint256S("ff"), 101, 1000, fNotSent);
    BOOST_CHECK(txid.IsNull());
    BOOST_CHECK(!fNotSent);

    // Enforcer unreachable: fail closed (the bundle guard blocks), the bid counts as not sent
    const std::string strDead = "127.0.0.1:" + std::to_string(DeadPort());
    gArgs.ForceSetArg("-enforceraddr", strDead);
    vHash.clear();
    BOOST_CHECK(client.ListWithdrawalBundleStatus(vHash));
    BOOST_CHECK(vHash.empty());
    txid = client.SendBMMRequest(uint256S("01"), uint256S("ff"), 101, 1000, fNotSent);
    BOOST_CHECK(txid.IsNull());
    BOOST_CHECK(fNotSent);

    gArgs.ForceSetArg("-enforceraddr", "127.0.0.1:50051");
    gArgs.ForceSetArg("-enforcertransport", DEFAULT_ENFORCER_TRANSPORT);
}

BOOST_AUTO_TEST_SUITE_END()

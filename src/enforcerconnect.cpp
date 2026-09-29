// Copyright (c) 2026 The FreeBank developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <enforcerconnect.h>

#include <univalue.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace enforcerconnect {

namespace {

int64_t NowMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string Lower(std::string s)
{
    for (char& c : s)
        c = std::tolower(static_cast<unsigned char>(c));
    return s;
}

std::string Trim(const std::string& s)
{
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos)
        return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

/** Wait until fd is ready for events or the deadline passes. 1 ready, 0 timed out, -1 error. */
int WaitFd(int fd, short events, int64_t nDeadlineMs)
{
    for (;;) {
        int64_t nLeft = nDeadlineMs - NowMs();
        if (nLeft <= 0)
            return 0;
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = events;
        pfd.revents = 0;
        int r = poll(&pfd, 1, (int)std::min<int64_t>(nLeft, 1000000));
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return -1;
        if (r == 0)
            continue; // re-check the deadline
        return 1;
    }
}

bool SetNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return false;
    // grpcurl (the fallback transport) runs under popen: do not hand it our sockets
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return true;
}

/** How one request/reply exchange on a connection ended. */
enum class Io {
    DONE,         //!< a whole reply is in
    DEAD_EARLY,   //!< the connection died before any reply byte (a stale keep-alive connection looks like this)
    FAILED,       //!< timed out, broke mid-reply, or the reply was malformed
};

Io Exchange(int fd, const std::string& strReq, int64_t nDeadlineMs, HttpReplyParser& reply, std::string& strError)
{
    size_t nSent = 0;
    while (nSent < strReq.size()) {
        ssize_t n = send(fd, strReq.data() + nSent, strReq.size() - nSent, MSG_NOSIGNAL);
        if (n > 0) {
            nSent += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            int w = WaitFd(fd, POLLOUT, nDeadlineMs);
            if (w == 0) {
                strError = "timed out sending the request";
                return Io::FAILED;
            }
            if (w < 0) {
                strError = std::string("poll: ") + strerror(errno);
                return Io::FAILED;
            }
            continue;
        }
        strError = std::string("send: ") + strerror(errno);
        return Io::DEAD_EARLY;
    }

    char buf[16384];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            HttpReplyParser::State s = reply.Feed(buf, (size_t)n);
            if (s == HttpReplyParser::DONE)
                return Io::DONE;
            if (s == HttpReplyParser::BAD) {
                strError = "bad reply: " + reply.strError;
                return Io::FAILED;
            }
            continue;
        }
        if (n == 0) {
            if (reply.nReceived == 0) {
                strError = "connection closed before any reply";
                return Io::DEAD_EARLY;
            }
            if (reply.Finish() == HttpReplyParser::DONE)
                return Io::DONE;
            strError = "bad reply: " + reply.strError;
            return Io::FAILED;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            int w = WaitFd(fd, POLLIN, nDeadlineMs);
            if (w == 0) {
                strError = "timed out waiting for the reply";
                return Io::FAILED;
            }
            if (w < 0) {
                strError = std::string("poll: ") + strerror(errno);
                return Io::FAILED;
            }
            continue;
        }
        strError = std::string("recv: ") + strerror(errno);
        return reply.nReceived == 0 ? Io::DEAD_EARLY : Io::FAILED;
    }
}

/** An idle keep-alive connection is usable if it has nothing to read: no EOF, no stray bytes. */
bool IdleAlive(int fd)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int r;
    do {
        r = poll(&pfd, 1, 0);
    } while (r < 0 && errno == EINTR);
    return r == 0;
}

} // namespace

bool SplitHostPort(const std::string& strAddrIn, std::string& strHost, std::string& strPort)
{
    std::string strAddr = strAddrIn;
    if (strAddr.compare(0, 7, "http://") == 0)
        strAddr = strAddr.substr(7);
    while (!strAddr.empty() && strAddr.back() == '/')
        strAddr.pop_back();

    size_t colon;
    if (!strAddr.empty() && strAddr[0] == '[') {
        size_t close = strAddr.find(']');
        if (close == std::string::npos || close + 1 >= strAddr.size() || strAddr[close + 1] != ':')
            return false;
        strHost = strAddr.substr(1, close - 1);
        colon = close + 1;
    } else {
        colon = strAddr.rfind(':');
        if (colon == std::string::npos || strAddr.find(':') != colon)
            return false;
        strHost = strAddr.substr(0, colon);
    }
    strPort = strAddr.substr(colon + 1);
    if (strHost.empty() || strPort.empty() || strPort.size() > 5)
        return false;
    for (char c : strPort)
        if (!std::isdigit(static_cast<unsigned char>(c)))
            return false;
    int nPort = atoi(strPort.c_str());
    return nPort > 0 && nPort < 65536;
}

std::string BuildRequest(const std::string& strAddr, const std::string& strService, const std::string& strMethod,
                         const std::string& strBody, int64_t nTimeoutMs)
{
    std::string strHostHeader = strAddr;
    if (strHostHeader.compare(0, 7, "http://") == 0)
        strHostHeader = strHostHeader.substr(7);
    while (!strHostHeader.empty() && strHostHeader.back() == '/')
        strHostHeader.pop_back();

    std::string s = "POST /" + strService + "/" + strMethod + " HTTP/1.1\r\n";
    s += "Host: " + strHostHeader + "\r\n";
    s += "User-Agent: freebankd\r\n";
    s += "Content-Type: application/json\r\n";
    s += "Connect-Protocol-Version: 1\r\n";
    if (nTimeoutMs > 0)
        s += "Connect-Timeout-Ms: " + std::to_string(nTimeoutMs) + "\r\n";
    s += "Content-Length: " + std::to_string(strBody.size()) + "\r\n";
    s += "\r\n";
    s += strBody;
    return s;
}

static const char* const CODE_NAMES[][2] = {
    // Connect name, grpcurl (Go codes.Code) name; index = gRPC code
    {"ok", "OK"},
    {"canceled", "Canceled"},
    {"unknown", "Unknown"},
    {"invalid_argument", "InvalidArgument"},
    {"deadline_exceeded", "DeadlineExceeded"},
    {"not_found", "NotFound"},
    {"already_exists", "AlreadyExists"},
    {"permission_denied", "PermissionDenied"},
    {"resource_exhausted", "ResourceExhausted"},
    {"failed_precondition", "FailedPrecondition"},
    {"aborted", "Aborted"},
    {"out_of_range", "OutOfRange"},
    {"unimplemented", "Unimplemented"},
    {"internal", "Internal"},
    {"unavailable", "Unavailable"},
    {"data_loss", "DataLoss"},
    {"unauthenticated", "Unauthenticated"},
};
static const int NUM_CODES = sizeof(CODE_NAMES) / sizeof(CODE_NAMES[0]);

int GrpcCodeFromConnectName(const std::string& strCode)
{
    for (int i = 1; i < NUM_CODES; ++i)
        if (strCode == CODE_NAMES[i][0])
            return i;
    return 2;
}

std::string GrpcCodeName(int nCode)
{
    if (nCode >= 0 && nCode < NUM_CODES)
        return CODE_NAMES[nCode][1];
    return "Code(" + std::to_string(nCode) + ")";
}

int GrpcCodeFromHttpStatus(int nHttpStatus)
{
    switch (nHttpStatus) {
    case 400: return 13; // Internal
    case 401: return 16; // Unauthenticated
    case 403: return 7;  // PermissionDenied
    case 404: return 12; // Unimplemented
    case 429:
    case 502:
    case 503:
    case 504: return 14; // Unavailable
    default: return 2;   // Unknown
    }
}

int ReplyToStatus(int nHttpStatus, const std::string& strContentEncoding, const std::string& strBody, std::string& strOutput)
{
    if (!strContentEncoding.empty() && strContentEncoding != "identity") {
        strOutput = "Connect transport: the reply is compressed (" + strContentEncoding + "), which was not asked for";
        return 1;
    }
    if (nHttpStatus == 200) {
        strOutput = strBody;
        return 0;
    }

    int nCode = GrpcCodeFromHttpStatus(nHttpStatus);
    std::string strMessage;
    bool fConnectError = false;
    UniValue v;
    if (v.read(strBody) && v.isObject()) {
        const UniValue& code = find_value(v, "code");
        if (code.isStr()) {
            nCode = GrpcCodeFromConnectName(code.get_str());
            fConnectError = true;
        }
        const UniValue& message = find_value(v, "message");
        if (message.isStr())
            strMessage = message.get_str();
    }
    if (!fConnectError) {
        std::string strSnippet = strBody.substr(0, 200);
        std::replace(strSnippet.begin(), strSnippet.end(), '\n', ' ');
        strMessage = "HTTP " + std::to_string(nHttpStatus) + (strSnippet.empty() ? "" : ": " + strSnippet);
    }
    strOutput = "ERROR:\n  Code: " + GrpcCodeName(nCode) + "\n  Message: " + strMessage + "\n";
    return 64 + nCode;
}

//
// HttpReplyParser
//

HttpReplyParser::State HttpReplyParser::Bad(const std::string& strWhy)
{
    strError = strWhy;
    fKeepAlive = false;
    state = BAD;
    return state;
}

HttpReplyParser::State HttpReplyParser::Feed(const char* pch, size_t n)
{
    if (state != INCOMPLETE)
        return state;
    nReceived += n;
    buf.append(pch, n);
    if (buf.size() > MAX_REPLY_SIZE + 65536)
        return Bad("reply larger than " + std::to_string(MAX_REPLY_SIZE) + " bytes");
    return Parse();
}

HttpReplyParser::State HttpReplyParser::Finish()
{
    if (state != INCOMPLETE)
        return state;
    if (fHeaders && fCloseDelimited) {
        strBody.swap(buf);
        fKeepAlive = false;
        state = DONE;
        return state;
    }
    return Bad("connection closed mid-reply");
}

HttpReplyParser::State HttpReplyParser::Parse()
{
    while (!fHeaders) {
        size_t nEnd = buf.find("\r\n\r\n");
        if (nEnd == std::string::npos)
            return buf.size() > 65536 ? Bad("reply headers too large") : INCOMPLETE;
        std::string strHead = buf.substr(0, nEnd);
        buf.erase(0, nEnd + 4);

        size_t nLine = strHead.find("\r\n");
        std::string strStatus = strHead.substr(0, nLine);
        if (strStatus.size() < 12 || strStatus.compare(0, 7, "HTTP/1.") != 0 || strStatus[8] != ' ' ||
                !std::isdigit((unsigned char)strStatus[9]) || !std::isdigit((unsigned char)strStatus[10]) ||
                !std::isdigit((unsigned char)strStatus[11]))
            return Bad("bad status line");
        nStatus = atoi(strStatus.substr(9, 3).c_str());
        const bool fHttp11 = strStatus[7] == '1';

        if (nStatus >= 100 && nStatus < 200)
            continue; // an interim reply (100 Continue): the real one follows

        fKeepAlive = fHttp11;
        nContentLength = -1;
        fChunked = false;
        strContentEncoding.clear();
        while (nLine != std::string::npos) {
            size_t nNext = strHead.find("\r\n", nLine + 2);
            std::string strField = strHead.substr(nLine + 2, nNext == std::string::npos ? std::string::npos : nNext - nLine - 2);
            nLine = nNext;
            size_t nColon = strField.find(':');
            if (nColon == std::string::npos)
                continue;
            std::string strName = Lower(Trim(strField.substr(0, nColon)));
            std::string strValue = Trim(strField.substr(nColon + 1));
            if (strName == "content-length") {
                if (strValue.empty() || strValue.size() > 12 ||
                        strValue.find_first_not_of("0123456789") != std::string::npos)
                    return Bad("bad Content-Length");
                nContentLength = atoll(strValue.c_str());
            } else if (strName == "transfer-encoding") {
                if (Lower(strValue).find("chunked") != std::string::npos)
                    fChunked = true;
            } else if (strName == "connection") {
                std::string strLower = Lower(strValue);
                if (strLower.find("close") != std::string::npos)
                    fKeepAlive = false;
                else if (strLower.find("keep-alive") != std::string::npos)
                    fKeepAlive = true;
            } else if (strName == "content-encoding") {
                strContentEncoding = Lower(strValue);
            }
        }
        if (fChunked)
            nContentLength = -1;
        else if (nContentLength < 0) {
            fCloseDelimited = true;
            fKeepAlive = false;
        }
        if (nContentLength > (int64_t)MAX_REPLY_SIZE)
            return Bad("reply larger than " + std::to_string(MAX_REPLY_SIZE) + " bytes");
        fHeaders = true;
    }

    if (fChunked) {
        for (;;) {
            size_t nEol = buf.find("\r\n");
            if (nEol == std::string::npos)
                return buf.size() > 1024 ? Bad("bad chunk size line") : INCOMPLETE;
            std::string strSize = Trim(buf.substr(0, buf.find_first_of(";\r")));
            if (strSize.empty() || strSize.size() > 8 || strSize.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                return Bad("bad chunk size");
            size_t nChunk = strtoul(strSize.c_str(), nullptr, 16);
            if (nChunk == 0) {
                // last chunk, then optional trailers, then an empty line
                if (buf.size() < nEol + 4)
                    return INCOMPLETE;
                if (buf.compare(nEol + 2, 2, "\r\n") != 0 && buf.find("\r\n\r\n", nEol + 2) == std::string::npos)
                    return INCOMPLETE;
                state = DONE;
                return state;
            }
            if (strBody.size() + nChunk > MAX_REPLY_SIZE)
                return Bad("reply larger than " + std::to_string(MAX_REPLY_SIZE) + " bytes");
            if (buf.size() < nEol + 2 + nChunk + 2)
                return INCOMPLETE;
            if (buf.compare(nEol + 2 + nChunk, 2, "\r\n") != 0)
                return Bad("chunk not followed by CRLF");
            strBody.append(buf, nEol + 2, nChunk);
            buf.erase(0, nEol + 2 + nChunk + 2);
        }
    }

    if (nContentLength >= 0) {
        if (buf.size() < (size_t)nContentLength)
            return INCOMPLETE;
        if (buf.size() > (size_t)nContentLength)
            fKeepAlive = false; // stray bytes after the reply: do not reuse the connection
        strBody = buf.substr(0, (size_t)nContentLength);
        buf.clear();
        state = DONE;
        return state;
    }

    return INCOMPLETE; // close-delimited: Finish() completes it
}

//
// Client
//

Client::~Client()
{
    CloseIdle();
}

void Client::CloseIdle()
{
    std::lock_guard<std::mutex> lock(mutexIdle);
    for (const auto& idle : vIdle)
        close(idle.second);
    vIdle.clear();
}

int Client::TakeIdle(const std::string& strAddr)
{
    std::lock_guard<std::mutex> lock(mutexIdle);
    while (!vIdle.empty()) {
        std::pair<std::string, int> idle = vIdle.back();
        vIdle.pop_back();
        if (idle.first == strAddr && IdleAlive(idle.second))
            return idle.second;
        close(idle.second); // closed by the enforcer, or -enforceraddr changed
    }
    return -1;
}

void Client::PutIdle(const std::string& strAddr, int fd)
{
    std::lock_guard<std::mutex> lock(mutexIdle);
    if (vIdle.size() >= MAX_IDLE) {
        close(fd);
        return;
    }
    vIdle.emplace_back(strAddr, fd);
}

int Client::Dial(const std::string& strHost, const std::string& strPort, int64_t nDeadlineMs, std::string& strError)
{
    for (int nTry = 0; nTry < DIAL_TRIES; ++nTry) {
        if (nTry > 0) {
            // back off 250, 500, 1000 ms; never past the call's deadline
            int64_t nWait = 250LL << (nTry - 1);
            if (NowMs() + nWait >= nDeadlineMs)
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(nWait));
        }

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        struct addrinfo* res = nullptr;
        int rc = getaddrinfo(strHost.c_str(), strPort.c_str(), &hints, &res);
        if (rc != 0 || !res) {
            strError = std::string("resolve: ") + gai_strerror(rc);
            continue;
        }

        int fdOut = -1;
        for (struct addrinfo* ai = res; ai && fdOut < 0; ai = ai->ai_next) {
            int fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (fd < 0) {
                strError = std::string("socket: ") + strerror(errno);
                continue;
            }
            if (!SetNonBlocking(fd)) {
                strError = std::string("fcntl: ") + strerror(errno);
                close(fd);
                continue;
            }
#ifdef SO_NOSIGPIPE
            int one = 1;
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
            int nodelay = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

            int r;
            do {
                r = connect(fd, ai->ai_addr, ai->ai_addrlen);
            } while (r < 0 && errno == EINTR);
            if (r < 0 && errno == EINPROGRESS) {
                int w = WaitFd(fd, POLLOUT, nDeadlineMs);
                if (w <= 0) {
                    strError = w == 0 ? "context deadline exceeded (connect timed out)" : std::string("poll: ") + strerror(errno);
                    close(fd);
                    continue;
                }
                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
                    err = errno;
                r = err ? -1 : 0;
                errno = err;
            }
            if (r < 0) {
                strError = std::string("connect: ") + strerror(errno);
                close(fd);
                continue;
            }
            fdOut = fd;
        }
        freeaddrinfo(res);
        if (fdOut >= 0) {
            nDials++;
            return fdOut;
        }
        if (NowMs() >= nDeadlineMs)
            break;
    }
    return -1;
}

int Client::Call(const std::string& strAddr, const std::string& strService, const std::string& strMethod,
                 const std::string& strRequest, int nTimeoutSecs, bool fRetrySafe, std::string& strOutput)
{
    strOutput.clear();
    nTimeoutSecs = std::max(1, std::min(nTimeoutSecs, MAX_CALL_TIMEOUT));
    const int64_t nDeadlineMs = NowMs() + 1000LL * nTimeoutSecs;
    const std::string strCall = strService + "/" + strMethod;

    std::string strHost, strPort;
    if (!SplitHostPort(strAddr, strHost, strPort)) {
        strOutput = "Failed to dial target host \"" + strAddr + "\": not a host:port address";
        return 1;
    }

    for (int nPass = 0; nPass < 2; ++nPass) {
        int fd = -1;
        bool fReused = false;
        if (fRetrySafe && nPass == 0) {
            fd = TakeIdle(strAddr);
            fReused = fd >= 0;
        }
        if (fd < 0) {
            std::string strError;
            fd = Dial(strHost, strPort, nDeadlineMs, strError);
            if (fd < 0) {
                strOutput = "Failed to dial target host \"" + strAddr + "\": " + strError;
                return 1;
            }
        }

        const std::string strReq = BuildRequest(strAddr, strService, strMethod, strRequest,
                                                std::max<int64_t>(1, nDeadlineMs - NowMs()));
        HttpReplyParser reply;
        std::string strError;
        const Io io = Exchange(fd, strReq, nDeadlineMs, reply, strError);
        if (io == Io::DONE) {
            if (reply.fKeepAlive)
                PutIdle(strAddr, fd);
            else
                close(fd);
            return ReplyToStatus(reply.nStatus, reply.strContentEncoding, reply.strBody, strOutput);
        }
        close(fd);
        // A reused keep-alive connection the enforcer had already closed: send
        // the (retry-safe) call once more on a fresh connection
        if (io == Io::DEAD_EARLY && fReused)
            continue;
        strOutput = "Connect transport: " + strCall + " to " + strAddr + ": " + strError;
        return 1;
    }
    strOutput = "Connect transport: " + strCall + " to " + strAddr + ": no usable connection";
    return 1;
}

} // namespace enforcerconnect

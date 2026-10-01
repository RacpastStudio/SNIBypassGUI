// Copyright © 2026 Racpast. All Rights Reserved.
//
// This file is part of SNIBypassGUI, a proprietary software project.
//
// NOTICE: All information contained herein is, and remains the property of
// Racpast. The intellectual and technical concepts contained herein are
// proprietary to Racpast and are protected by copyright law and international
// treaties. Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained from Racpast.
//
// Unauthorized copying, modification, distribution, or use of this file,
// via any medium, is strictly prohibited.
//
// For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com
//
// See the LICENSE file in the project root for full terms and conditions.

#pragma once
// Winsock plumbing shared by the two DNS servers this program runs.
//
// LocalResolver and DnsProxy both listen on a loopback address, both hand out
// ephemeral sockets to reach real servers, and both have to survive the same
// Windows quirks doing it. Those pieces live here once rather than being
// written twice and drifting apart.
//
// Nothing in this header knows what a DNS message is: it is sockets, deadlines,
// and the two UDP behaviours Windows gets wrong.
#include <winsock2.h>

#include <cstdint>
#include <string>
#include <vector>

#include "dns/cancel.h"

namespace Dns {
namespace SocketUtils {

// How often a loop that is otherwise waiting checks its deadlines, in
// milliseconds. Also the longest a Stop() can take to be noticed.
inline constexpr long kTickMs = 100;

// The largest DNS message that can exist: the TCP length prefix is 16 bits.
inline constexpr size_t kMaxMessage = 65535;

// Close `s`, taking it back from `cancel` first so the token cannot close it a
// second time.
//
// A socket handed to a CancelToken is owned by the token: cancelling closes it
// from whichever thread cancels, while this thread may still be sitting in a
// read on it. Whichever thread gets there first must be the only one to close
// it, because on Windows a closed socket value is immediately reusable and a
// second close can tear down an unrelated socket that has since been given the
// same value.
//
// So cleanup goes through here rather than through CloseSocket whenever a token
// is in play: Release() removes the socket from the token, and only if it was
// still registered — meaning the token never cancelled — is it closed here.
// Passing no token is the ordinary non-cancellable case.
inline void ReleaseAndClose(SOCKET& s, const CancelToken* cancel) {
    if (s == INVALID_SOCKET) return;
    if (cancel == nullptr || cancel->Release(s)) {
        closesocket(s);
    }
    s = INVALID_SOCKET;
}

// A socket handle that closes what it holds, and does nothing else with it.
//
// Constructed and destroyed on one thread — it is a local in a call, not a field
// a loop owns — which is why it needs none of the ordering that makes a raw
// SOCKET awkward to pass around.
//
// The handle can also be handed to a CancelToken, and remembering the token is
// the whole point of doing it here: once registered, the socket has two possible
// closers, and the handle itself is the only place that knows which of them got
// there first. Folding that into the destructor is what makes the rule hold on
// every return path rather than only the ones a caller remembered to write.
class SocketHandle {
public:
    SocketHandle() = default;
    explicit SocketHandle(SOCKET s) : m_socket(s) {}
    ~SocketHandle() { Close(); }

    SocketHandle(const SocketHandle&) = delete;
    SocketHandle& operator=(const SocketHandle&) = delete;

    SocketHandle(SocketHandle&& other) noexcept
        : m_socket(other.m_socket), m_token(other.m_token) {
        other.m_socket = INVALID_SOCKET;
        other.m_token = nullptr;
    }

    SocketHandle& operator=(SocketHandle&& other) noexcept {
        if (this != &other) {
            Close();
            m_socket = other.m_socket;
            m_token = other.m_token;
            other.m_socket = INVALID_SOCKET;
            other.m_token = nullptr;
        }
        return *this;
    }

    operator SOCKET() const { return m_socket; }
    SOCKET Get() const { return m_socket; }
    bool IsValid() const { return m_socket != INVALID_SOCKET; }
    explicit operator bool() const { return IsValid(); }

    // Hand the socket to `cancel`, so that cancelling closes it, and remember
    // that fact so this handle never closes it twice.
    //
    // Returns false if the token was already cancelled — in which case it has
    // closed the socket itself, the handle is left empty, and the caller must
    // not use the socket again. Call this before the first operation that can
    // block on the socket; that is the point of it.
    bool RegisterWith(const CancelToken* cancel) {
        if (cancel == nullptr) return IsValid();
        if (!cancel->Register(m_socket)) {
            // Already cancelled: the token closed it as it was registered, and
            // the handle must forget it rather than close it again later.
            m_socket = INVALID_SOCKET;
            return false;
        }
        m_token = cancel;
        return true;
    }

    void Close() {
        ReleaseAndClose(m_socket, m_token);
        m_token = nullptr;
    }

    // Replace what this holds with `s`, closing whatever it held before through
    // the same release path as the destructor. The token is cleared because a
    // fresh socket was never registered with the old one's token, and carrying
    // that token forward would let a cancel close a socket that was bound after
    // the token's work had already been given up on.
    void reset(SOCKET s) {
        Close();
        m_socket = s;
    }

    SOCKET Release() {
        const SOCKET s = m_socket;
        m_socket = INVALID_SOCKET;
        m_token = nullptr;
        return s;
    }

private:
    SOCKET m_socket = INVALID_SOCKET;
    const CancelToken* m_token = nullptr;
};

// Milliseconds since the system started. Monotonic, and the only clock any
// deadline in this program is measured against.
uint64_t Now();

// Winsock, started once for the process and never stopped.
//
// WSACleanup belongs to a program that is finished with sockets, and this one is
// finished with them only when it exits — at which point the kernel does the same
// work. Tying it to a static destructor instead would run it in an order no
// translation unit here controls, while a worker thread may still hold a socket.
bool EnsureWinsock();

void SetNonBlocking(SOCKET s);

// Stop Windows from failing a later recvfrom with WSAECONNRESET because an
// earlier datagram drew an ICMP port-unreachable. On a socket that talks to
// several servers at once, one dead server would otherwise poison reads for all
// of them.
void DisableUdpConnReset(SOCKET s);

void CloseSocket(SOCKET& s);

// Create, bind and prepare a listener on `address`:`port`.
//
// SO_EXCLUSIVEADDRUSE is what stops another program from later binding the same
// address with SO_REUSEADDR and quietly taking delivery of the queries meant for
// us. The socket comes back non-blocking, so the caller only has to call
// listen() for a stream socket.
//
// Returns INVALID_SOCKET on failure, with the Winsock error left set.
SOCKET BindListener(const wchar_t* address, uint16_t port, int type, int protocol);

// Compare two addresses by family and address bytes, ignoring the port: the port
// is ours to set, and the same server must not be treated as two because two
// adapters list it.
bool SameHost(const sockaddr_storage& a, const sockaddr_storage& b);

// `addr` as text. A host with no port, or `addr`:`port` when `withPort` is set.
//
// Only for logging — the string is not round-trippable and the port is formatted
// from the same sockaddr the address is, so a caller cannot pair one address's
// text with another's port. An address family this does not know yields "?".
std::wstring AddressText(const sockaddr_storage& addr, int addrLen, bool withPort);

}  // namespace SocketUtils
}  // namespace Dns

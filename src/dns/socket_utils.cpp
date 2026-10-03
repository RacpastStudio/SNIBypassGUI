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

#include "dns/socket_utils.h"

// SIO_UDP_CONNRESET, which is a Microsoft extension and so lives beside the
// Microsoft extension functions rather than in the portable socket headers.
#include <mswsock.h>
#include <ws2tcpip.h>

#include <cstring>
#include <string>

namespace Dns {
namespace SocketUtils {

uint64_t Now() {
    return GetTickCount64();
}

bool EnsureWinsock() {
    static const bool ready = [] {
        WSADATA data;
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return ready;
}

void SetNonBlocking(SOCKET s) {
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
}

void DisableUdpConnReset(SOCKET s) {
    BOOL off = FALSE;
    DWORD returned = 0;
    WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &returned, nullptr, nullptr);
}

void CloseSocket(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

SOCKET BindListener(const wchar_t* address, uint16_t port, int type, int protocol) {
    SOCKET s = socket(AF_INET, type, protocol);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    // SO_EXCLUSIVEADDRUSE is the whole point of binding here rather than with a
    // plain bind: without it another program can later take the same address with
    // SO_REUSEADDR and be handed the queries meant for us. A failure means that
    // guarantee is not in place, so the listener is refused rather than opened
    // with the protection silently missing.
    BOOL exclusive = TRUE;
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char*>(&exclusive),
                   sizeof(exclusive)) == SOCKET_ERROR) {
        // Saved and restored because closesocket is allowed to overwrite the
        // error, and the caller logs the one that made this fail.
        const int err = WSAGetLastError();
        closesocket(s);
        WSASetLastError(err);
        return INVALID_SOCKET;
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (InetPtonW(AF_INET, address, &addr.sin_addr) != 1 ||
        bind(s, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        const int err = WSAGetLastError();
        closesocket(s);
        WSASetLastError(err);
        return INVALID_SOCKET;
    }
    SetNonBlocking(s);
    return s;
}

bool SameHost(const sockaddr_storage& a, const sockaddr_storage& b) {
    if (a.ss_family != b.ss_family) return false;
    if (a.ss_family == AF_INET) {
        return std::memcmp(&reinterpret_cast<const sockaddr_in&>(a).sin_addr,
                           &reinterpret_cast<const sockaddr_in&>(b).sin_addr,
                           sizeof(in_addr)) == 0;
    }
    if (a.ss_family == AF_INET6) {
        return std::memcmp(&reinterpret_cast<const sockaddr_in6&>(a).sin6_addr,
                           &reinterpret_cast<const sockaddr_in6&>(b).sin6_addr,
                           sizeof(in6_addr)) == 0;
    }
    return false;
}

std::wstring AddressText(const sockaddr_storage& addr, int, bool withPort) {
    wchar_t host[INET6_ADDRSTRLEN] = {};

    // InetNtopW rather than getnameinfo because only the literal is wanted: a
    // name here would be the logging path doing its own DNS lookup, and that
    // lookup would go to the very server that may just have failed.
    if (addr.ss_family == AF_INET) {
        const in_addr& v4 = reinterpret_cast<const sockaddr_in&>(addr).sin_addr;
        if (InetNtopW(AF_INET, &v4, host, INET6_ADDRSTRLEN) == nullptr) return L"?";
    } else if (addr.ss_family == AF_INET6) {
        const in6_addr& v6 = reinterpret_cast<const sockaddr_in6&>(addr).sin6_addr;
        if (InetNtopW(AF_INET6, &v6, host, INET6_ADDRSTRLEN) == nullptr) return L"?";
    } else {
        return L"?";
    }

    if (!withPort) return host;

    uint16_t port = 0;
    if (addr.ss_family == AF_INET) {
        port = ntohs(reinterpret_cast<const sockaddr_in&>(addr).sin_port);
    } else {
        port = ntohs(reinterpret_cast<const sockaddr_in6&>(addr).sin6_port);
    }

    // An IPv6 literal goes in brackets when a port is attached, which is the only
    // way the two are not read as one colon-separated field.
    if (addr.ss_family == AF_INET6) {
        return std::wstring(L"[") + host + L"]:" + std::to_wstring(port);
    }
    return std::wstring(host) + L":" + std::to_wstring(port);
}

}  // namespace SocketUtils
}  // namespace Dns

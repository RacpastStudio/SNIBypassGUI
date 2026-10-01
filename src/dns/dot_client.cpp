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

#include "dns/dot_client.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <windows.h>

#include <cstring>

#include "app/logging.h"
#include "app/text.h"
#include "dns/network_utils.h"
#include "dns/socket_utils.h"
#include "dns/tcp_session.h"
#include "dns/tls_utils.h"

namespace Dns {

std::vector<uint8_t> QueryDoT(const std::vector<uint8_t>& query, const std::string& address,
                              const std::string& hostname,
                              const std::vector<std::vector<uint8_t>>& certificateHashes,
                              uint32_t timeoutMs, const CancelToken* cancel) {
    if (query.empty() || query.size() > SocketUtils::kMaxMessage) return {};

    NetworkUtils::IpEndpoint endpoint;
    if (!NetworkUtils::ParseIpEndpoint(address, 853, endpoint)) {
        LOGW(L"DoT: invalid IP endpoint: " + Utf8ToWide(address));
        return {};
    }

    SocketUtils::SocketHandle sock(
        socket(endpoint.address.ss_family, SOCK_STREAM, IPPROTO_TCP));
    if (!sock.IsValid()) return {};

    if (!NetworkUtils::ConnectWithTimeout(sock,
                                          reinterpret_cast<const sockaddr*>(&endpoint.address),
                                          endpoint.length, timeoutMs / 2, cancel)) {
        return {};
    }

    // Registered before the handshake, because the handshake is the longest
    // blocking step here and the one most worth abandoning. The handle remembers
    // the token, so the socket is closed exactly once by whichever of the two
    // gets there first.
    if (!sock.RegisterWith(cancel)) return {};

    TlsUtils::CredHandle credHandle;
    TlsUtils::CtxtHandle ctxtHandle;

    const std::wstring sniW =
        hostname.empty() ? Utf8ToWide(endpoint.host) : Utf8ToWide(hostname);
    if (!TlsUtils::Handshake(sock, sniW, ctxtHandle, credHandle, certificateHashes,
                             timeoutMs / 2, cancel)) {
        return {};
    }

    if (!TlsUtils::Send(sock, ctxtHandle.Get(), EncodeTcpMessage(query), timeoutMs / 2,
                        cancel)) {
        return {};
    }

    // DoT framing is length-prefixed, so the whole answer is one message and
    // the shared reader can reassemble it across TLS records.
    const uint64_t deadline = SocketUtils::Now() + timeoutMs;
    TcpSessionReader reader;
    for (;;) {
        if (SocketUtils::Now() >= deadline) break;

        const std::vector<uint8_t> chunk = TlsUtils::Recv(
            sock, ctxtHandle, static_cast<uint32_t>(deadline - SocketUtils::Now()), cancel);
        if (chunk.empty()) break;

        reader.Append(chunk.data(), chunk.size());
        if (reader.HasMessage()) break;
    }

    std::vector<uint8_t> message = reader.TakeMessage();
    return message;
}

}  // namespace Dns

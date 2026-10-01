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

#include "dns/tcp_session.h"

#include <cstring>

namespace Dns {
namespace {

// The two-byte prefix describes the payload only, so all 65535 payload bytes are
// valid and the in-memory framed representation may occupy 65537 bytes.
constexpr size_t kMaxFramedMessage = SocketUtils::kMaxMessage;

}  // namespace

std::vector<uint8_t> EncodeTcpMessage(const std::vector<uint8_t>& message) {
    if (message.empty() || message.size() > kMaxFramedMessage) return {};

    std::vector<uint8_t> framed;
    framed.reserve(message.size() + 2);
    framed.push_back(static_cast<uint8_t>((message.size() >> 8) & 0xFF));
    framed.push_back(static_cast<uint8_t>(message.size() & 0xFF));
    framed.insert(framed.end(), message.begin(), message.end());
    return framed;
}

TcpSessionReader::State TcpSessionReader::Parse() {
    m_readyLen = 0;

    // Two bytes of length, then that many bytes of message. Anything short of
    // the prefix is simply not a message yet.
    if (m_in.size() < 2) return State::Incomplete;

    const size_t declared = (static_cast<size_t>(m_in[0]) << 8) | static_cast<size_t>(m_in[1]);

    // A zero-length message is legal on the wire and means nothing to anyone;
    // without rejecting it here the prefix would never advance and the
    // connection would spin forever on the same two bytes.
    if (declared == 0) return State::Broken;

    if (declared > kMaxFramedMessage) return State::Broken;

    if (m_in.size() < declared + 2) return State::Incomplete;

    m_readyLen = declared;
    return State::Ready;
}

TcpSessionReader::State TcpSessionReader::Append(const uint8_t* data, size_t len) {
    // A broken stream stays broken: the caller has already been told to drop
    // the connection and must not be handed a half-parsed message afterwards.
    if (m_readyLen == 0 && m_in.size() > kMaxFramedMessage + 2) return State::Broken;

    if (data != nullptr && len > 0) {
        // Refuse the read rather than growing without bound. This is the only
        // place the cap can be enforced once bytes are in flight, because the
        // prefix is not readable until it has been buffered.
        if (len > kMaxFramedMessage + 2 - m_in.size()) {
            m_in.clear();
            m_readyLen = 0;
            return State::Broken;
        }
        m_in.insert(m_in.end(), data, data + len);
    }

    return Parse();
}

std::vector<uint8_t> TcpSessionReader::TakeMessage() {
    if (m_readyLen == 0) return {};

    std::vector<uint8_t> message(m_in.begin() + 2, m_in.begin() + 2 + m_readyLen);
    m_in.erase(m_in.begin(), m_in.begin() + 2 + m_readyLen);
    Parse();  // a pipelined second message may already be sitting here
    return message;
}

void TcpSessionReader::Clear() {
    m_in.clear();
    m_readyLen = 0;
}

}  // namespace Dns

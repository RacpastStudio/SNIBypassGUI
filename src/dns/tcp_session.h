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
// DNS-over-TCP framing, in one place.
//
// A DNS message on TCP is a 16-bit big-endian length followed by that many
// bytes. Both the clients here and the upstream sessions speak it, so the
// accumulator and the encoder live together rather than being written once per
// direction per side.
//
// The accumulator is bounded: a peer that announces 65535 bytes and then keeps
// sending cannot make a session allocate without limit. Crossing the bound is
// reported as Broken, which the owner treats as a dead connection.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "dns/socket_utils.h"

namespace Dns {

// Prefix `message` with its 16-bit length, ready to write to a stream socket.
// Returns empty if `message` is too long to frame, which is the only case a
// caller has to handle separately.
std::vector<uint8_t> EncodeTcpMessage(const std::vector<uint8_t>& message);

// Reassembles length-prefixed messages from a byte stream that arrives in
// arbitrary pieces. One instance holds one direction of one connection.
class TcpSessionReader {
public:
    // How the last Append() left the stream.
    enum class State {
        Incomplete,  // no complete message yet; keep reading
        Ready,       // a whole message is waiting for TakeMessage()
        Broken,      // framing this receiver cannot recover from
    };

    // Add bytes read from the socket.
    State Append(const uint8_t* data, size_t len);

    // Whether a complete message is waiting.
    bool HasMessage() const { return m_readyLen != 0; }

    // Remove and return the waiting message, clearing it from the stream. If a
    // second message was already buffered behind it, that one becomes ready.
    std::vector<uint8_t> TakeMessage();

    void Clear();

private:
    // Recompute m_readyLen from the front of the stream.
    State Parse();

    std::vector<uint8_t> m_in;  // unconsumed stream bytes, no message claimed
    size_t m_readyLen = 0;      // length of the complete message at the front
};

}  // namespace Dns

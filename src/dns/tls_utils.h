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
// Shared TLS utilities using Windows Schannel.
//
// This module provides RAII wrappers and common operations for TLS connections
// used by DoH and DoT clients.
#include <winsock2.h>

#include <windows.h>

#define SECURITY_WIN32
#include <schannel.h>
#include <security.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "dns/cancel.h"

namespace Dns {
namespace TlsUtils {

// RAII wrapper for Schannel credential handle.
class CredHandle {
public:
    CredHandle() = default;
    ~CredHandle() { Release(); }

    CredHandle(const CredHandle&) = delete;
    CredHandle& operator=(const CredHandle&) = delete;

    CredHandle(CredHandle&& other) noexcept : m_handle(other.m_handle), m_valid(other.m_valid) {
        other.m_valid = false;
    }

    CredHandle& operator=(CredHandle&& other) noexcept {
        if (this != &other) {
            Release();
            m_handle = other.m_handle;
            m_valid = other.m_valid;
            other.m_valid = false;
        }
        return *this;
    }

    ::CredHandle* Get() { return &m_handle; }
    const ::CredHandle* Get() const { return &m_handle; }
    bool IsValid() const { return m_valid; }
    void SetValid(bool valid) { m_valid = valid; }

    void Release() {
        if (m_valid) {
            FreeCredentialsHandle(&m_handle);
            m_valid = false;
        }
    }

private:
    ::CredHandle m_handle = {};
    bool m_valid = false;
};

// RAII wrapper for Schannel context handle.
class CtxtHandle {
public:
    CtxtHandle() = default;
    ~CtxtHandle() { Release(); }

    CtxtHandle(const CtxtHandle&) = delete;
    CtxtHandle& operator=(const CtxtHandle&) = delete;

    CtxtHandle(CtxtHandle&& other) noexcept
        : m_handle(other.m_handle),
          m_valid(other.m_valid),
          m_pending(std::move(other.m_pending)) {
        other.m_valid = false;
    }

    CtxtHandle& operator=(CtxtHandle&& other) noexcept {
        if (this != &other) {
            Release();
            m_handle = other.m_handle;
            m_valid = other.m_valid;
            m_pending = std::move(other.m_pending);
            other.m_valid = false;
        }
        return *this;
    }

    ::CtxtHandle* Get() { return &m_handle; }
    const ::CtxtHandle* Get() const { return &m_handle; }
    bool IsValid() const { return m_valid; }
    void SetValid(bool valid) { m_valid = valid; }

    void SetPending(const uint8_t* data, size_t size) {
        if (size == 0) {
            m_pending.clear();
        } else {
            m_pending.assign(data, data + size);
        }
    }
    std::vector<uint8_t> TakePending() { return std::move(m_pending); }

    void Release() {
        if (m_valid) {
            DeleteSecurityContext(&m_handle);
            m_valid = false;
        }
        m_pending.clear();
    }

private:
    ::CtxtHandle m_handle = {};
    bool m_valid = false;
    std::vector<uint8_t> m_pending;
};

// Perform a TLS handshake over `sock`.
//
// Returns true on success. On success, credHandle and ctxtHandle are populated
// and must be kept alive for subsequent encryption/decryption operations.
//
// A cancelled token abandons the handshake: the token closes the socket, which
// unblocks the read underneath, and this returns false. The caller must not
// close the socket itself in that case — see the token's contract.
bool Handshake(SOCKET sock, const std::wstring& sni, CtxtHandle& ctxtHandle,
               CredHandle& credHandle,
               const std::vector<std::vector<uint8_t>>& certificateHashes, uint32_t timeoutMs,
               const CancelToken* cancel = nullptr);

// Encrypt and send data over TLS.
// Returns true if all data was sent, false on error.
bool Send(SOCKET sock, ::CtxtHandle* context, const std::vector<uint8_t>& data,
          uint32_t timeoutMs, const CancelToken* cancel = nullptr);

// Receive and decrypt one TLS application record within `timeoutMs`.
// Returns decrypted data, or an empty vector on timeout, error, or cancellation.
//
// Encrypted bytes beyond that record remain attached to `context` for the next
// call, including application data that arrived with the final handshake token.
std::vector<uint8_t> Recv(SOCKET sock, CtxtHandle& context, uint32_t timeoutMs,
                          const CancelToken* cancel = nullptr);

}  // namespace TlsUtils
}  // namespace Dns

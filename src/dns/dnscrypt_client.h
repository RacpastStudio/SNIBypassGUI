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
// DNSCrypt client with certificate caching and TCP/UDP transport.
//
// Sends DNS queries using the DNSCrypt protocol (draft-denis-dprive-dnscrypt).
// DNSCrypt encrypts DNS queries with authenticated encryption (XSalsa20-Poly1305
// or XChaCha20-Poly1305 depending on the certificate's es-version) and provides
// authentication through the provider's Ed25519 public key.
//
// Certificates are cached by provider name and refreshed when they expire or approach
// expiration. Both UDP and TCP transports are supported; if a UDP response has the TC
// (truncated) bit set, the query is automatically retried over TCP as required by the
// DNSCrypt specification.
//
// Thread-safety: QueryDNSCrypt is thread-safe. Multiple threads can query different
// or the same upstream concurrently; certificate cache access is internally synchronized.
#include <cstdint>
#include <string>
#include <vector>

#include "dns/cancel.h"

namespace Dns {

// Send a DNS query to a DNSCrypt endpoint.
//
// `query` is the DNS message in wire format.
// `address` is the server IP:port (e.g., "1.1.1.1:443").
// `providerName` is the provider name (e.g., "2.dnscrypt-cert.cloudflare.com").
// `publicKey` is the provider's Ed25519 public key (32 bytes).
// `timeoutMs` is the total timeout for the operation (including cert fetch if needed).
// `cancel`, when given, abandons the query as soon as it fires, including while a
// certificate is being fetched — the certificate cache is shared, so a cancelled
// fetch still lets another thread populate it.
//
// Returns the DNS response in wire format, or an empty vector on failure.
// If the UDP response has TC=1, automatically retries over TCP.
std::vector<uint8_t> QueryDNSCrypt(const std::vector<uint8_t>& query,
                                   const std::string& address, const std::string& providerName,
                                   const std::vector<uint8_t>& publicKey, uint32_t timeoutMs,
                                   const CancelToken* cancel = nullptr);

}  // namespace Dns

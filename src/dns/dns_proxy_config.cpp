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

#include "dns/dns_proxy_config.h"

#include <windows.h>

#include <algorithm>

#include "app/logging.h"
#include "app/text.h"
#include "dns/dnsstamp.h"
#include "dns/network_utils.h"

namespace Dns {
namespace {

// Enumerate all section names in an INI file
std::vector<std::wstring> EnumerateSections(const std::wstring& path) {
    std::vector<std::wstring> sections;

    DWORD size = 8192;
    std::vector<wchar_t> buffer(size);

    DWORD result = GetPrivateProfileSectionNamesW(buffer.data(), size, path.c_str());

    while (result == size - 2) {
        size *= 2;
        if (size > 1024 * 1024) break;
        buffer.resize(size);
        result = GetPrivateProfileSectionNamesW(buffer.data(), size, path.c_str());
    }

    const wchar_t* ptr = buffer.data();
    while (*ptr != L'\0') {
        std::wstring section = ptr;
        sections.push_back(section);
        ptr += section.length() + 1;
    }

    return sections;
}

}  // namespace

DnsProxyConfig DnsProxyConfig::Load(const std::wstring& path) {
    DnsProxyConfig cfg;

    cfg.timeoutMs = GetPrivateProfileIntW(L"General", L"TimeoutMs", 3000, path.c_str());

    // Clamped rather than refused: a pool of zero would deadlock the proxy, and a
    // pool larger than any query needs is only wasted memory. Both are config
    // mistakes worth surviving, not fatal ones.
    cfg.threadPoolSize = static_cast<size_t>(std::clamp<int>(
        GetPrivateProfileIntW(L"General", L"ThreadPoolSize", 32, path.c_str()), 1, 256));

    const std::vector<std::wstring> sections = EnumerateSections(path);

    const std::wstring upstreamPrefix = L"Upstream.";
    for (const std::wstring& section : sections) {
        if (section.find(upstreamPrefix) != 0) continue;

        const std::wstring name = section.substr(upstreamPrefix.length());

        const bool enabled =
            GetPrivateProfileIntW(section.c_str(), L"Enabled", 0, path.c_str()) != 0;

        wchar_t stamp[2048] = {};
        GetPrivateProfileStringW(section.c_str(), L"Stamp", L"", stamp, 2048, path.c_str());
        if (stamp[0] == L'\0') {
            LOGW(L"DNS forwarder config: [" + section + L"] missing Stamp, skipped");
            continue;
        }

        const DNSStamp parsed = ParseDNSStamp(stamp);
        if (!parsed.valid) {
            LOGW(L"DNS forwarder config: [" + section + L"] invalid DNSStamp, skipped");
            continue;
        }

        DnsProxyEndpoint up;
        up.name = name;
        up.enabled = enabled;
        switch (parsed.protocol) {
            case StampProtocol::DoH:
                up.protocol = DnsProxyProtocol::DoH;
                up.address = parsed.address;
                up.hostname = parsed.hostname;
                up.path = parsed.path;
                up.certificateHashes = parsed.hashes;
                break;
            case StampProtocol::DoT:
                up.protocol = DnsProxyProtocol::DoT;
                up.address = parsed.address;
                up.hostname = parsed.hostname;
                up.certificateHashes = parsed.hashes;
                break;
            case StampProtocol::DNSCrypt:
                up.protocol = DnsProxyProtocol::DNSCrypt;
                up.address = parsed.address;
                up.providerName = parsed.providerName;
                up.publicKey = parsed.publicKey;
                break;
            default:
                LOGW(L"DNS forwarder config: [" + section + L"] unknown protocol, skipped");
                continue;
        }

        uint16_t defaultPort = 443;
        if (up.protocol == DnsProxyProtocol::DoT) defaultPort = 853;
        NetworkUtils::IpEndpoint endpoint;
        if (!NetworkUtils::ParseIpEndpoint(up.address, defaultPort, endpoint)) {
            LOGW(L"DNS forwarder config: [" + section + L"] invalid numeric endpoint, skipped");
            continue;
        }

        cfg.upstreams.push_back(up);
    }

    const size_t enabledCount = cfg.EnabledCount();
    LOGI(L"DNS forwarder config loaded: " + std::to_wstring(cfg.upstreams.size()) +
         L" upstream(s), " + std::to_wstring(enabledCount) + L" enabled");

    return cfg;
}

}  // namespace Dns

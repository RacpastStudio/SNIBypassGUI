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

#include "update/http.h"

#include <windows.h>

#include <winhttp.h>

#include <string>

#include "app/logging.h"
#include "app/version.h"

namespace Http {
namespace {

// Per-operation timeouts, in milliseconds. WinHTTP's defaults leave a stalled
// server able to hold the caller indefinitely; the update runs on a worker thread
// but the user is watching a progress tip, so bounding each phase is the difference
// between "the check is slow" and "the program looks hung". Receive is the most
// generous because it covers the body transfer, not just a header round-trip.
constexpr int kResolveTimeoutMs = 15000;
constexpr int kConnectTimeoutMs = 15000;
constexpr int kSendTimeoutMs = 30000;
constexpr int kReceiveTimeoutMs = 60000;

// The pieces of a URL that WinHTTP wants separately: WinHttpConnect takes a host
// and port, and the request takes everything from the path onward. `secure` also
// fixes the scheme, so a caller cannot accidentally get a plaintext request from
// an https: URL or vice versa.
struct Url {
    std::wstring host;
    std::wstring path;  // includes the leading '/' and any query
    INTERNET_PORT port = 0;
    bool secure = false;
};

// Split `url` into the form WinHTTP takes. Returns false on anything that is not an
// absolute http(s) URL with a non-empty host, which is a programming error in this
// module rather than a runtime condition — every endpoint here is a compile-time
// constant.
bool ParseUrl(const std::wstring& url, Url& out) {
    const std::wstring lower = [&url] {
        std::wstring s = url;
        for (wchar_t& c : s)
            if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        return s;
    }();

    size_t afterScheme = 0;
    if (lower.rfind(L"https://", 0) == 0) {
        out.secure = true;
        afterScheme = 8;
    } else if (lower.rfind(L"http://", 0) == 0) {
        out.secure = false;
        afterScheme = 7;
    } else {
        return false;
    }

    const size_t slash = url.find(L'/', afterScheme);
    const std::wstring authority = (slash == std::wstring::npos)
                                       ? url.substr(afterScheme)
                                       : url.substr(afterScheme, slash - afterScheme);
    if (authority.empty()) return false;

    out.path = (slash == std::wstring::npos) ? L"/" : url.substr(slash);

    // An explicit port is the only thing after a colon in the authority. A ':' here
    // can only be a port separator in a well-formed URL.
    const size_t colon = authority.find(L':');
    if (colon == std::wstring::npos) {
        out.host = authority;
        out.port = 0;  // let WinHTTP pick from the scheme
    } else {
        out.host = authority.substr(0, colon);
        const std::wstring portText = authority.substr(colon + 1);
        if (portText.empty()) return false;
        unsigned long value = 0;
        for (wchar_t c : portText) {
            if (c < L'0' || c > L'9') return false;
            value = value * 10 + static_cast<unsigned long>(c - L'0');
            if (value > 65535) return false;
        }
        out.port = static_cast<INTERNET_PORT>(value);
    }
    return !out.host.empty();
}

// A WinHTTP handle that closes itself, so every early return below is a return and
// not a cleanup site.
struct Handle {
    HINTERNET h = nullptr;
    Handle() = default;
    explicit Handle(HINTERNET handle) : h(handle) {}
    ~Handle() {
        if (h) WinHttpCloseHandle(h);
    }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    operator HINTERNET() const { return h; }
    explicit operator bool() const { return h != nullptr; }
};

}  // namespace

// The manifest and every chunk are fetched through WinHTTP with its own defaults,
// NOT through WinINet's per-user configuration.
//
// The distinction is deliberate and is about where the transport takes its inputs
// from. WinINet reads the proxy and PAC settings out of HKCU — a hive the user
// owns — so the endpoint, the certificate chain and the redirect target of every
// update request were things the local user (or anything running as them) could
// redefine. The manifest is signed and verified against a key compiled into this
// binary before a single field is parsed, so this was never a way to change WHAT
// the update says. It was a way to change WHERE the request goes, whether it
// completes, and whether the server's certificate chain is the real one. Those are
// availability and hygiene properties, and the fix for them is to stop consulting
// per-user state at all.
//
// So: no proxy (the update host is reached directly), no redirects (the endpoint
// does not get to relocate the request), TLS 1.2 as a hard floor rather than
// whatever the machine's crypto policy currently happens to allow, and a status
// code that must be read and must be 2xx.
bool Get(const std::wstring& url, std::string& out) {
    out.clear();

    Url parts;
    if (!ParseUrl(url, parts)) {
        LOGE(L"Update: refusing a malformed endpoint: " + url);
        return false;
    }

    Handle session(WinHttpOpen(APP_NAME L"/" APP_VERSION_NUM, WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) {
        LOGE(L"Update: WinHttpOpen failed (err " + std::to_wstring(GetLastError()) + L").");
        return false;
    }
    WinHttpSetTimeouts(session, kResolveTimeoutMs, kConnectTimeoutMs, kSendTimeoutMs,
                       kReceiveTimeoutMs);
    // Redirects are refused rather than followed. The body is signature-verified, so
    // a redirect cannot change WHAT we install — but it would let the endpoint hand
    // the request to a location of its choosing, and there is no reason for the
    // update transport to travel anywhere we did not name.
    //
    // The return value is checked rather than discarded: a silently ignored option
    // would leave redirects enabled while the code reads as though they were off, and
    // "a security setting that failed to apply and said nothing" is worse than no
    // setting at all.
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(session, WINHTTP_OPTION_REDIRECT_POLICY, &redirectPolicy,
                          sizeof(redirectPolicy))) {
        LOGE(L"Update: cannot disable redirects (err " + std::to_wstring(GetLastError()) +
             L"); refusing to fetch over an unconstrained redirect policy.");
        return false;
    }

    Handle connection(WinHttpConnect(session, parts.host.c_str(), parts.port, 0));
    if (!connection) {
        LOGE(L"Update: cannot connect to " + parts.host + L" (err " +
             std::to_wstring(GetLastError()) + L").");
        return false;
    }

    Handle request(WinHttpOpenRequest(connection, L"GET", parts.path.c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      parts.secure ? WINHTTP_FLAG_SECURE : 0));
    if (!request) {
        LOGE(L"Update: cannot create the request for " + url + L" (err " +
             std::to_wstring(GetLastError()) + L").");
        return false;
    }

    if (parts.secure) {
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
        WinHttpSetOption(request, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols,
                         sizeof(protocols));
    }

    if (!WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA,
                            0, 0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        LOGE(L"Update: request to " + url + L" failed (err " + std::to_wstring(GetLastError()) +
             L").");
        return false;
    }

    DWORD status = 0;
    DWORD statusLen = sizeof(status);
    if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusLen,
                             WINHTTP_NO_HEADER_INDEX)) {
        // A response we cannot interpret is not a response we can trust. Never fall
        // back to the body: a status that failed to read is exactly the case where
        // guessing "probably 200" turns one confusing failure into a harder one.
        LOGE(L"Update: cannot read the status code from " + url + L" (err " +
             std::to_wstring(GetLastError()) + L").");
        return false;
    }
    if (status < 200 || status >= 300) {
        LOGE(L"Update: " + url + L" returned HTTP " + std::to_wstring(status) + L".");
        return false;
    }

    char buf[16384];
    for (;;) {
        DWORD n = 0;
        if (!WinHttpReadData(request, buf, static_cast<DWORD>(sizeof(buf)), &n)) {
            LOGE(L"Update: reading the body from " + url + L" failed (err " +
                 std::to_wstring(GetLastError()) + L").");
            out.clear();
            return false;
        }
        if (n == 0) break;  // clean end of stream
        out.append(buf, n);
    }
    return true;
}

}  // namespace Http

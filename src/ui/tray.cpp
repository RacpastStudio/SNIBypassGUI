// Copyright © 2026 Racpast. All Rights Reserved.
//
// This file is part of SNIBypassGUI, a proprietary software project.
//
// NOTICE: All information contained herein is, and remains the property of
// Racpast. The intellectual and technical concepts contained herein are
// proprietary to Racpast. All rights reserved.
//
// Unauthorized copying, modification, distribution, or use of this file,
// via any medium, is strictly prohibited.
//
// For licensing inquiries: snibypassgui@gmail.com or racpast@gmail.com
//
// See the LICENSE file in the project root for full license terms.

#include "ui/tray.h"

#include <shellapi.h>

#include <cwchar>
#include <iterator>
#include <string>
#include <vector>

#include "app/controller.h"
#include "app/i18n.h"
#include "app/logging.h"
#include "app/services.h"
#include "app/settings.h"
#include "app/text.h"
#include "app/version.h"
#include "platform/autostart.h"
#include "platform/dialogs.h"
#include "platform/process.h"
#include "platform/shell.h"
#include "ui/eula.h"
#include "ui/supported_sites.h"

// What this module owns is the tray icon, its menu, and the mapping from a menu
// command to an application operation. What an operation DOES — starting the stack,
// applying an update, uninstalling — belongs to Controller (src/app/controller.h),
// which is also where the gates that serialize those operations live. Nothing here
// reads a service gate or decides service policy.

namespace Tray {
namespace {

constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kTrayIconId = 1;
constexpr wchar_t kWindowClass[] = L"SNIBypassGUI_TrayWnd";

enum MenuId : UINT {
    kIdStatusDns = 2000,
    kIdStatusProxy,
    kIdStatusNginx,
    kIdStatusRoute,
    kIdVersion,
    kIdStart,
    kIdStop,
    kIdToggleAutostart,
    kIdCheckUpdate,
    kIdToggleAutoUpdate,
    kIdEditHosts,
    kIdCleanCache,
    kIdToggleLog,
    kIdLangEnglish,
    kIdLangChinese,
    kIdExit,
    kIdUninstall,
    kIdAboutApp,
    kIdAboutCopyright,
    kIdAboutQq1,
    kIdAboutQq2,
    kIdAboutTelegram,
    kIdAboutEmail,
    kIdAboutStar,
    kIdAboutSponsor,
    kIdViewEula,
    kIdSupportedSitesFirst = 5000,
};

// About-panel destinations.
constexpr wchar_t kUrlApp[] = L"https://snib.racpast.com";
constexpr wchar_t kUrlCopyright[] = L"https://github.com/racpast";
constexpr wchar_t kUrlQq1[] =
    L"https://qm.qq.com/cgi-bin/qm/qr?k=IXuDK0pmAcqFxgF_dUExYaU6oWFRReiT&jump_from=webapi&"
    L"authKey=WC2UM5ybN9Ez1FIWZdhOaa+K/A4aheJzgEm9GIeRmGHctOiRnpG1hRvb79vMQEaC";
constexpr wchar_t kUrlQq2[] =
    L"https://qm.qq.com/cgi-bin/qm/qr?k=kJXlDDpMHOThp2FIlsVxBf3V-Ad7vWV6&jump_from=webapi&"
    L"authKey=LFzTy1SORNq/kfexzzecmejNKPrP3D+/xYd1UzfPc3y1ZoKWijCNvBsTBcb+qFeV";
constexpr wchar_t kUrlTelegram[] = L"https://t.me/snibypassgui";
constexpr wchar_t kUrlSponsor[] = L"https://ifdian.net/a/racpast";
constexpr wchar_t kEmail[] = L"snibypassgui@gmail.com";

HWND g_window = nullptr;
HICON g_icon = nullptr;
UINT g_taskbarCreated = 0;
std::vector<std::wstring> g_supportedSiteLinks;

// The system's own directory, resolved rather than assumed.
//
// The paths below used to be the literals "C:\Windows\System32\..." — which is only
// where Windows lives until someone installs it somewhere else, and then the Hosts
// menu item launches a process that does not exist. What the user sees is a menu
// entry that does nothing, on exactly the machine where the guess was wrong.
const std::wstring& WindowsDir() {
    static const std::wstring dir = [] {
        wchar_t buf[MAX_PATH] = {};
        const UINT n = GetWindowsDirectoryW(buf, static_cast<UINT>(std::size(buf)));
        if (n == 0 || n >= std::size(buf)) return std::wstring();
        std::wstring s(buf, n);
        if (!s.empty() && s.back() == L'\\') s.pop_back();
        return s;
    }();
    return dir;
}

// "<Windows>\System32\<relative>", or empty when the directory could not be resolved.
std::wstring SystemFile(const wchar_t* relative) {
    const std::wstring& dir = WindowsDir();
    if (dir.empty()) return L"";
    return dir + L"\\System32\\" + relative;
}

std::wstring BuildTrayTooltip() {
    return std::wstring(APP_NAME) + L" " + GetVersionDisplayStr();
}

void CopyBounded(wchar_t* dst, size_t capacity, const std::wstring& text) {
    const size_t n = (text.size() < capacity - 1) ? text.size() : capacity - 1;
    std::wmemcpy(dst, text.c_str(), n);
    dst[n] = L'\0';
}

// Just enough of the structure to name our icon.
//
// Every notify-icon call builds its own copy rather than sharing one: tooltips and
// balloons are updated from the worker threads behind Start, Stop, cache cleanup
// and the update check, while the UI thread re-adds the icon when Explorer
// restarts. One shared NOTIFYICONDATAW would have those threads writing the same
// flags and buffers at the same time.
NOTIFYICONDATAW IconIdentity() {
    NOTIFYICONDATAW data = {};
    data.cbSize = sizeof(data);
    data.hWnd = g_window;
    data.uID = kTrayIconId;
    return data;
}

void SetTip(const std::wstring& tip) {
    NOTIFYICONDATAW data = IconIdentity();
    data.uFlags = NIF_TIP;
    CopyBounded(data.szTip, std::size(data.szTip), tip);
    Shell_NotifyIconW(NIM_MODIFY, &data);
}

void ResetTip() {
    SetTip(BuildTrayTooltip());
}

void ShowBalloon(const std::wstring& title, const std::wstring& text) {
    NOTIFYICONDATAW data = IconIdentity();
    data.uFlags = NIF_INFO;
    CopyBounded(data.szInfoTitle, std::size(data.szInfoTitle), title);
    CopyBounded(data.szInfo, std::size(data.szInfo), text);
    data.dwInfoFlags = NIIF_INFO;
    Shell_NotifyIconW(NIM_MODIFY, &data);
}

void AddIcon() {
    NOTIFYICONDATAW data = IconIdentity();
    data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    data.uCallbackMessage = kTrayMessage;
    data.hIcon = g_icon;
    CopyBounded(data.szTip, std::size(data.szTip), BuildTrayTooltip());
    Shell_NotifyIconW(NIM_ADD, &data);
}

// Ask the program to exit. Posted rather than torn down here: this is called from a
// worker thread, and DestroyWindow belongs on the thread that owns the window.
void RequestQuit() {
    PostMessageW(g_window, WM_CLOSE, 0, 0);
}

std::wstring StatusLabel(const wchar_t* nameKey, bool running) {
    return std::wstring(T(nameKey)) + T(L"punct.colon") +
           (running ? std::wstring(L"● ") + T(L"status.running")
                    : std::wstring(L"○ ") + T(L"status.stopped"));
}

HMENU BuildAboutMenu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kIdAboutApp, APP_NAME);
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdVersion,
                (std::wstring(T(L"menu.version")) + L" " + GetVersionDisplayStr()).c_str());
    AppendMenuW(menu, MF_STRING, kIdAboutCopyright, T(L"about.copyright"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdViewEula, T(L"menu.viewEula"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.qqGroups"));
    AppendMenuW(menu, MF_STRING, kIdAboutQq1, L"① 946813204");
    AppendMenuW(menu, MF_STRING, kIdAboutQq2, L"② 1055626367");
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.telegram"));
    AppendMenuW(menu, MF_STRING, kIdAboutTelegram, L"@snibypassgui");
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.email"));
    AppendMenuW(menu, MF_STRING, kIdAboutEmail, kEmail);
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.star"));
    AppendMenuW(menu, MF_STRING, kIdAboutStar, T(L"about.github"));
    AppendMenuW(menu, MF_STRING | MF_GRAYED, 0, T(L"about.sponsor"));
    AppendMenuW(menu, MF_STRING, kIdAboutSponsor, T(L"about.afdian"));
    return menu;
}

void ShowContextMenu() {
    const bool dns = Services::DnsRedirectRunning();
    const bool proxy = Services::DnsProxyRunning();
    const bool nginx = Services::NginxRunning();
    const bool sniGate = Services::SniGateRunning();
    // An update or cleanup in flight owns the service state, so disable the items that
    // would race it (Start/Stop) or launch a second update/cleanup. The controller owns
    // that answer; this only asks.
    const bool busy = Controller::Busy();

    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdStatusDns,
                StatusLabel(L"status.dns", dns).c_str());
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdStatusProxy,
                StatusLabel(L"status.proxy", proxy).c_str());
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdStatusNginx,
                StatusLabel(L"status.nginx", nginx).c_str());
    AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdStatusRoute,
                StatusLabel(L"status.route", sniGate).c_str());
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    // Offer only one of Start/Stop: if anything is running, only "Stop" — which
    // prevents clicking "Start" when the ports are already held by our own services.
    const UINT startStopFlags = MF_STRING | (busy ? MF_GRAYED : 0);
    if (dns || proxy || nginx || sniGate)
        AppendMenuW(menu, startStopFlags, kIdStop, T(L"menu.stop"));
    else
        AppendMenuW(menu, startStopFlags, kIdStart, T(L"menu.start"));

    const bool autostart = Autostart::IsEnabled();
    AppendMenuW(menu, MF_STRING, kIdToggleAutostart,
                autostart ? T(L"menu.disableAuto") : T(L"menu.enableAuto"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU sitesMenu = CreatePopupMenu();
    g_supportedSiteLinks = SupportedSites::PopulateMenu(sitesMenu, kIdSupportedSitesFirst);
    UINT sitesFlags = MF_POPUP;
    if (GetMenuItemCount(sitesMenu) == 0) sitesFlags |= MF_GRAYED;
    AppendMenuW(menu, sitesFlags, reinterpret_cast<UINT_PTR>(sitesMenu),
                T(L"menu.supportedSites"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    // While busy the item becomes a grayed indicator; the live step is carried by the
    // tray tooltip, which can repaint while the menu is held open.
    if (busy)
        AppendMenuW(menu, MF_STRING | MF_GRAYED, kIdCheckUpdate, T(L"menu.updating"));
    else
        AppendMenuW(menu, MF_STRING, kIdCheckUpdate, T(L"menu.checkUpdate"));
    AppendMenuW(menu, MF_STRING | (AutoUpdateEnabled() ? MF_CHECKED : 0), kIdToggleAutoUpdate,
                T(L"menu.autoUpdate"));

    // Each language entry shows its own name, with the active one checked.
    const Lang lang = GetLang();
    HMENU langMenu = CreatePopupMenu();
    AppendMenuW(langMenu, MF_STRING | (lang == Lang::English ? MF_CHECKED : 0), kIdLangEnglish,
                T(L"lang.en"));
    AppendMenuW(langMenu, MF_STRING | (lang == Lang::Chinese ? MF_CHECKED : 0), kIdLangChinese,
                T(L"lang.zh"));
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(langMenu), T(L"menu.language"));

    HMENU miscMenu = CreatePopupMenu();
    AppendMenuW(miscMenu, MF_STRING | (LogEnabled() ? MF_CHECKED : 0), kIdToggleLog,
                T(L"menu.logging"));
    AppendMenuW(miscMenu, MF_STRING, kIdEditHosts, T(L"menu.editHosts"));
    // Show "Cleaning..." when cleanup is in progress.
    if (busy)
        AppendMenuW(miscMenu, MF_STRING | MF_GRAYED, kIdCleanCache, T(L"msg.cleaningCache"));
    else
        AppendMenuW(miscMenu, MF_STRING, kIdCleanCache, T(L"menu.cleanCache"));
    // Grayed while an update or a cleanup is in flight, for the same reason Start and
    // Stop are: an uninstall would delete the tree out from under it. Showing it
    // enabled and then doing nothing on click would look like a broken menu item.
    AppendMenuW(miscMenu, MF_STRING | (busy ? MF_GRAYED : 0), kIdUninstall,
                T(L"menu.uninstall"));
    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(miscMenu), T(L"menu.misc"));

    AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(BuildAboutMenu()), T(L"menu.about"));
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kIdExit, T(L"menu.exit"));

    POINT cursor;
    GetCursorPos(&cursor);
    SetForegroundWindow(g_window);  // so the menu dismisses correctly
    TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, cursor.x, cursor.y, 0, g_window,
                   nullptr);
    // TrackPopupMenu leaves the window with capture and the menu in the queue, so
    // without this the next click goes to the stale menu instead of dismissing it —
    // the classic "tray menu will not close". The documented follow-up is a null
    // post to the owner.
    PostMessageW(g_window, WM_NULL, 0, 0);
    DestroyMenu(menu);
}

void HandleCommand(int id) {
    if (id >= static_cast<int>(kIdSupportedSitesFirst) &&
        id < static_cast<int>(kIdSupportedSitesFirst) +
                 static_cast<int>(g_supportedSiteLinks.size())) {
        Shell::OpenUrl(g_supportedSiteLinks[id - kIdSupportedSitesFirst].c_str());
        return;
    }

    switch (id) {
        case kIdStart: Controller::Start(); break;
        case kIdStop: Controller::Stop(); break;
        case kIdToggleAutostart: Controller::ToggleAutostart(); break;
        case kIdCheckUpdate: Controller::CheckForUpdates(); break;
        case kIdToggleAutoUpdate: SetAutoUpdateEnabled(!AutoUpdateEnabled()); break;
        case kIdToggleLog: LogSetEnabled(!LogEnabled()); break;
        case kIdCleanCache: Controller::CleanCache(); break;
        case kIdLangEnglish: Controller::SetLanguage(Lang::English); break;
        case kIdLangChinese: Controller::SetLanguage(Lang::Chinese); break;
        case kIdAboutApp: Shell::OpenUrl(kUrlApp); break;
        case kIdAboutCopyright: Shell::OpenUrl(kUrlCopyright); break;
        case kIdAboutQq1: Shell::OpenUrl(kUrlQq1); break;
        case kIdAboutQq2: Shell::OpenUrl(kUrlQq2); break;
        case kIdAboutTelegram: Shell::OpenUrl(kUrlTelegram); break;
        case kIdAboutStar: Shell::OpenUrl(APP_HOMEPAGE); break;
        case kIdAboutSponsor: Shell::OpenUrl(kUrlSponsor); break;
        case kIdViewEula: Eula::ShowForReading(GetModuleHandleW(nullptr)); break;
        case kIdUninstall: Controller::Uninstall(); break;
        case kIdAboutEmail:
            Shell::CopyToClipboard(kEmail);
            ShowBalloon(APP_NAME, T(L"msg.copied"));
            break;
        case kIdEditHosts: {
            const std::wstring hosts = SystemFile(L"drivers\\etc\\hosts");
            const std::wstring notepad = SystemFile(L"notepad.exe");
            if (hosts.empty() || notepad.empty()) {
                // No resolved Windows directory means no path to hand an editor.
                // Saying so beats launching a process that is not there, which looks
                // like a dead menu item.
                LOGE(L"Edit hosts: the Windows directory could not be resolved.");
                Dialogs::Show(T(L"msg.editHostsFail"), MB_ICONERROR);
                break;
            }
            // We already run elevated, so notepad inherits that. It is launched
            // detached on purpose: an editor the user is typing in must not be taken
            // down when the tray exits.
            Process::LaunchDetached(notepad, std::wstring(L"\"") + hosts + L"\"", L"", false);
            break;
        }
        case kIdExit: RequestQuit(); break;
        default: break;
    }
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Explorer re-registers this message when it restarts, so re-add the icon.
    if (msg == g_taskbarCreated) {
        AddIcon();
        return 0;
    }

    // A dialog requested from a worker thread. Handled here so it is modal to this
    // window and runs on the thread that owns it; the requester is blocked until the
    // answer is ready.
    if (Dialogs::IsShowMessage(msg)) {
        Dialogs::HandleShowMessage(hwnd, lp);
        return 0;
    }

    switch (msg) {
        case kTrayMessage:
            if (LOWORD(lp) == WM_RBUTTONUP || LOWORD(lp) == WM_CONTEXTMENU ||
                LOWORD(lp) == WM_LBUTTONUP)
                ShowContextMenu();
            return 0;

        case WM_COMMAND: HandleCommand(LOWORD(wp)); return 0;

        case WM_CLOSE: DestroyWindow(hwnd); return 0;

        case WM_DESTROY: PostQuitMessage(0); return 0;

        default: return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

}  // namespace

bool Create(HINSTANCE instance) {
    g_taskbarCreated = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.lpszClassName = kWindowClass;
    RegisterClassExW(&wc);

    // WS_EX_TOOLWINDOW keeps it off the taskbar, and it is never shown.
    g_window = CreateWindowExW(WS_EX_TOOLWINDOW, kWindowClass, APP_NAME, WS_POPUP, 0, 0, 0, 0,
                               nullptr, nullptr, instance, nullptr);
    if (!g_window) {
        LOGE(L"Could not create the tray window.");
        return false;
    }

    g_icon = static_cast<HICON>(
        LoadImageW(instance, MAKEINTRESOURCEW(1), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE));
    if (!g_icon) g_icon = LoadIconW(nullptr, IDI_APPLICATION);

    // From here on every dialog raised from a worker thread is marshalled to this
    // window and owned by it. Armed only once the window exists, so the startup
    // dialogs in main() — which run before it — stay inline.
    Dialogs::Init(g_window);

    // The controller's only route to the user. Every callback runs on the thread that
    // raised it — a worker, never this one — which is what the notify-icon helpers
    // (each building its own NOTIFYICONDATAW) and the posted close are written for.
    Controller::Attach({ShowBalloon, SetTip, ResetTip, RequestQuit});

    AddIcon();
    return true;
}

void Destroy() {
    // Disarm first: a detached worker still unwinding must not reach a window that is
    // about to be destroyed, and after this it cannot. The controller is disarmed
    // before the dialogs for the same reason — it holds the callbacks that post here.
    Controller::Detach();
    Dialogs::Shutdown();

    NOTIFYICONDATAW data = IconIdentity();
    Shell_NotifyIconW(NIM_DELETE, &data);
}

int RunMessageLoop() {
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return static_cast<int>(msg.wParam);
}

void StartSilentUpdateCheck() {
    Controller::StartSilentUpdateCheck();
}

}  // namespace Tray

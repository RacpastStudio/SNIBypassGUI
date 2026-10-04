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
// See the LICENSE file in the project root for full license terms.

#pragma once
#include <functional>
#include <string>

#include "app/i18n.h"

// Application-layer orchestration: what each user-facing command actually DOES.
//
// These operations used to live in src/ui/tray.cpp, next to the menu that invokes
// them. That put service lifecycle policy — when the stack may be started or stopped,
// which operations may overlap, how an update applies itself around a running stack —
// in the presentation layer, and it made the two busy gates that enforce the policy
// properties of a translation unit the test runner deliberately does not link.
//
// The split now is: the tray decides what to show and which command a click means;
// this module decides what happens. It knows nothing about menus, command ids or
// window handles, and the only way it reaches the user is through the Presenter
// attached to it.
namespace Controller {

// What the controller needs from whatever is presenting the program.
//
// Attached once at startup and detached before the window goes away. Every callback
// runs on the thread that raised it — a worker, never the UI thread — so an
// implementation must be safe to enter from there. That is exactly what the tray's
// own helpers are written for: the tooltip and balloons are updated by building a
// fresh NOTIFYICONDATAW rather than sharing one, and the exit request is a posted
// message rather than a direct teardown.
struct Presenter {
    // A transient notification. Runs on a worker thread.
    std::function<void(const std::wstring& title, const std::wstring& text)> balloon;

    // Replace the tray tooltip. Runs on a worker thread, and repeats while a
    // download is in progress, so it may not assume it is the only writer.
    std::function<void(const std::wstring& tip)> setTip;

    // Restore the tooltip to what it says at rest. Runs on a worker thread.
    std::function<void()> resetTip;

    // Ask the program to exit. Runs on a worker thread and must not block: the
    // caller is on its way out and has nothing left to do but return.
    std::function<void()> quit;
};

// Arm the controller with the presenter above. Until this runs, an operation that
// wants to talk to the user does so without one: the notifications are dropped and a
// quit request is ignored. That is the correct behaviour for the startup path, which
// runs before any window exists and does not raise these operations at all.
void Attach(Presenter presenter);

// Disarm, before the window is destroyed.
void Detach();

// True while an operation that owns the service state is in flight — an update
// applying, or a cache cleanup part-way through its stop/clean/restart. Callers use
// it to disable the commands that would race it.
//
// This is the whole of what the presentation layer needs to know about the gates. It
// replaced two separate flags owned by the tray, whose values only ever described
// operations that belong to this module.
bool Busy();

// ---- Commands ---------------------------------------------------------------

// Every one of these returns promptly: the work runs on a thread of its own, and an
// operation that is already in flight makes the call a no-op rather than a second
// run. A failure to create that thread is reported rather than thrown.
void Start();
void Stop();
void ToggleAutostart();
void SetLanguage(Lang lang);

// Fetch, confirm and apply, showing any error. The interactive command.
void CheckForUpdates();

// The same path with every failure swallowed to a log line, for the startup check.
void StartSilentUpdateCheck();

void Uninstall();
void CleanCache();

}  // namespace Controller

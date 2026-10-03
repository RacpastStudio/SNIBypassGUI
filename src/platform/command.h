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
#include <windows.h>

#include <string>

namespace Command {

// Run a command line hidden and wait for it. Returns the child's exit code, -1
// if it could not be started, or -2 if it was killed on timeout. When `out` is
// given, stdout and stderr are captured into it.
int RunHidden(const std::wstring& cmdline, std::wstring* out = nullptr,
              DWORD timeoutMs = 30000);

// There is deliberately no "run a generated script" helper here.
//
// The self-update and self-removal helpers used to be batch scripts written into
// %TEMP% and started through cmd.exe, which meant every path handed to them was
// re-parsed as command language by an already-elevated shell. Both now go through the
// updater instead (src/updater/), which reads a work order and performs the moves with
// Win32 calls. Anything that would reintroduce a shell on a path assembled from
// runtime data belongs there too, not here.

}  // namespace Command

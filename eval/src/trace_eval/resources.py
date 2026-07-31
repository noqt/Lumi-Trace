# SPDX-License-Identifier: Apache-2.0
"""Portable, best-effort process-tree resource observations."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _linux_processes() -> dict[int, int]:
    relationships: dict[int, int] = {}
    proc = Path("/proc")
    if not proc.is_dir():
        return relationships
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text(encoding="ascii").split()
            relationships[int(entry.name)] = int(fields[3])
        except (OSError, ValueError, IndexError):
            continue
    return relationships


def _linux_rss(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _linux_cpu_time_ms(pid: int) -> int:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
        ticks = int(fields[13]) + int(fields[14])
        return (ticks * 1000) // int(os.sysconf("SC_CLK_TCK"))
    except (OSError, ValueError, IndexError):
        return 0


def _windows_processes() -> dict[int, int]:
    import ctypes
    from ctypes import wintypes

    snapshot_flag = 0x00000002
    invalid_handle = ctypes.c_void_p(-1).value

    class ProcessEntry(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel32.CreateToolhelp32Snapshot(snapshot_flag, 0)
    if snapshot == invalid_handle:
        return {}
    relationships: dict[int, int] = {}
    entry = ProcessEntry()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        present = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while present:
            relationships[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
            present = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return relationships


def _windows_rss(pid: int) -> int:
    import ctypes
    from ctypes import wintypes

    query = 0x1000
    read = 0x0010

    class Counters(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("PageFaultCount", wintypes.DWORD),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
            ("PrivateUsage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(Counters),
        wintypes.DWORD,
    ]
    handle = kernel32.OpenProcess(query | read, False, pid)
    if not handle:
        return 0
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    try:
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), ctypes.sizeof(counters)):
            return 0
        return int(counters.WorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


def _windows_cpu_time_ms(pid: int) -> int:
    import ctypes
    from ctypes import wintypes

    query = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetProcessTimes.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    handle = kernel32.OpenProcess(query, False, pid)
    if not handle:
        return 0
    created = wintypes.FILETIME()
    exited = wintypes.FILETIME()
    kernel = wintypes.FILETIME()
    user = wintypes.FILETIME()
    try:
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            return 0
        kernel_ticks = (int(kernel.dwHighDateTime) << 32) | int(kernel.dwLowDateTime)
        user_ticks = (int(user.dwHighDateTime) << 32) | int(user.dwLowDateTime)
        return (kernel_ticks + user_ticks) // 10_000
    finally:
        kernel32.CloseHandle(handle)


def process_tree_observation(root_pid: int) -> tuple[int, int, dict[int, int]]:
    """Return aggregate RSS, process count, and per-process CPU time."""

    if sys.platform == "win32":
        relationships = _windows_processes()
        rss = _windows_rss
        cpu_time_ms = _windows_cpu_time_ms
    elif os.name == "posix":
        relationships = _linux_processes()
        rss = _linux_rss
        cpu_time_ms = _linux_cpu_time_ms
    else:
        return 0, 0, {}
    selected = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, parent in relationships.items():
            if parent in selected and pid not in selected:
                selected.add(pid)
                changed = True
    return (
        sum(rss(pid) for pid in selected),
        len(selected),
        {pid: cpu_time_ms(pid) for pid in selected},
    )


def process_tree_snapshot(root_pid: int) -> tuple[int, int]:
    """Return current aggregate RSS and process count for a process tree."""

    resident_bytes, process_count, _ = process_tree_observation(root_pid)
    return resident_bytes, process_count

"""
VIRO - Virus Inspection & Response Organizer
AI-powered file monitor, scanner, alerter, and organizer.
Authors: Lovekesh Dishwar (2514), Shalini Rawat (2542) | MCA Sem III 2025-26

v2 additions:
  * Scan Already Downloaded Files  -- bulk-scan everything in ~/Downloads
  * Deep EXE Analysis              -- section entropy, suspicious imports,
                                      overlay, authenticode stub, PE anomalies

v8 multi-format static analysis improvements:
  * Missing dataset builder implemented with SHA-256 duplicate checks
  * Background scan workers and stable-download handling
  * Static script analysis for BAT/CMD/PS1/VBS/JS; unsupported types go to review

ML functionality:
  * Multi-algorithm ML ensemble    -- RandomForest, ExtraTrees, GradientBoosting,
                                      LogisticRegression, SVM, KNN combined by
                                      accuracy-weighted soft voting
  * 15 features per file           -- adds PE structure, imported-API, byte-statistics
                                      and double-extension signals
  * Train on real data             -- python viro_app.py --build-dataset ... / --train
"""

import os
import re
import sys
import csv
import time
import math
import argparse
import shutil
import struct
import hashlib
import threading
import subprocess
import json
import datetime
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
import joblib
import numpy as np

# -- Optional imports --
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_OK = True
except ImportError:
    WATCHDOG_OK = False
    # Keep the module importable even when watchdog is not installed.
    Observer = None
    class FileSystemEventHandler:
        def __init__(self, *args, **kwargs):
            pass

try:
    import pefile
    PEFILE_OK = True
except ImportError:
    PEFILE_OK = False

try:
    from plyer import notification
    PLYER_OK = True
except ImportError:
    PLYER_OK = False

# -- Paths --
DOWNLOADS_DIR  = Path.home() / "Downloads"
DESKTOP_DIR    = Path.home() / "Desktop"
QUARANTINE_DIR = DESKTOP_DIR / "VIRO_Quarantine"
MODEL_PATH     = Path(__file__).parent / "model" / "viro_model.pkl"

ORGANIZED_DIRS = {
    "Documents" : [".pdf", ".docx", ".doc", ".txt", ".xlsx", ".xls", ".pptx", ".csv", ".odt"],
    "Images"    : [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".tiff"],
    "Videos"    : [".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".m4v"],
    "Music"     : [".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a"],
    "Archives"  : [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"],
}

EXE_EXTENSIONS  = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".msi", ".com", ".pif"}
PE_EXTENSIONS = {".exe", ".dll", ".scr", ".com", ".pif"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".ps1", ".vbs", ".js"}
SAFE_THRESHOLD  = 30
WARN_THRESHOLD  = 70

# Extended suspicious PE indicators
# DLLs below are treated only as weak/contextual indicators. Many legitimate
# applications use networking/registry DLLs, so imports alone must never trigger
# a high threat score.
SUSPICIOUS_DLLS = {
    "wininet.dll", "urlmon.dll", "winhttp.dll", "ws2_32.dll",
    "mshtml.dll", "wtsapi32.dll", "dbghelp.dll",
}
SUSPICIOUS_APIS = {
    b"VirtualAlloc", b"CreateRemoteThread", b"WriteProcessMemory",
    b"ShellExecute", b"WinExec", b"URLDownloadToFile",
    b"RegSetValueEx", b"OpenProcess", b"SetWindowsHookEx",
    b"NtUnmapViewOfSection", b"IsDebuggerPresent",
}

# -- Feature extraction --

def get_entropy(data):
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())

def byte_stats(data):
    """Entropy, zero-byte ratio and printable-ASCII ratio from a single pass."""
    if not data:
        return 0.0, 0.0, 0.0
    counts   = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    n        = len(data)
    p        = counts[counts > 0] / n
    entropy  = float(-(p * np.log2(p)).sum())
    zero     = counts[0] / n
    printable = (counts[32:127].sum() + counts[[9, 10, 13]].sum()) / n
    return entropy, float(zero), float(printable)

def get_magic_bytes(path):
    try:
        with open(path, "rb") as f:
            raw = f.read(4)
        return int.from_bytes(raw.ljust(4, b"\x00"), "little")
    except Exception:
        return 0

def extension_mismatch(path):
    magic_map = {
        b"MZ"     : [".exe", ".dll", ".com", ".scr"],
        b"PK"     : [".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk"],
        b"\x89PNG" : [".png"],
        b"\xff\xd8": [".jpg", ".jpeg"],
        b"%PDF"   : [".pdf"],
    }
    ext = path.suffix.lower()
    try:
        with open(path, "rb") as f:
            header = f.read(4)
        for magic, exts in magic_map.items():
            if header.startswith(magic):
                return 0 if ext in exts else 1
    except Exception:
        pass
    return 0

def has_hidden_dll_calls(path):
    if not PEFILE_OK:
        return 0
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
        ])
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            dlls = {e.dll.decode(errors="ignore").lower() for e in pe.DIRECTORY_ENTRY_IMPORT}
            return int(bool(dlls & SUSPICIOUS_DLLS))
    except Exception:
        pass
    return 0

# Order matters: the model is trained on columns in exactly this order.
FEATURE_NAMES = [
    "size_log", "entropy", "ext_suspicious", "magic_mismatch", "dll_calls",
    "api_hits", "is_pe", "double_ext", "zero_ratio", "printable_ratio",
    "num_sections", "max_section_entropy", "has_overlay", "has_signature",
    "risky_dll_count",
]

# kernel32/user32/ntdll/shell32 are imported by nearly every Windows program, so on
# their own they say nothing. These are the ones that actually hint at malicious intent.
RISKY_DLLS = {"wininet.dll", "ws2_32.dll", "urlmon.dll", "advapi32.dll", "winhttp.dll"}
DOC_MEDIA_EXTS = {e for exts in ORGANIZED_DIRS.values() for e in exts}
PE_DEEP_SIZE_LIMIT = None          # section entropy is calculated for all parsed PE sections
MAX_SCAN_SIZE = None              # no fixed file-size rejection; analysis uses bounded/streaming reads
FILE_STABLE_CHECKS = 3
FILE_STABLE_INTERVAL = 0.5

# Known packer / protector section names. These are weak signals, not proof.
PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".themida",
    ".packed", ".enigma1", ".enigma2", ".vmp0", ".vmp1", ".vmp2",
}

# API groups are more useful than counting every API equally.
API_GROUPS = {
    "process_injection": {
        "CreateRemoteThread", "WriteProcessMemory", "OpenProcess",
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "QueueUserAPC",
    },
    "download": {
        "URLDownloadToFile", "InternetOpenUrl", "WinHttpOpenRequest",
        "WinHttpSendRequest", "InternetReadFile",
    },
    "persistence": {
        "RegSetValueEx", "RegCreateKeyEx", "CreateServiceA", "CreateServiceW",
        "SchTasks", "TaskScheduler",
    },
    "execution": {
        "ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcessA",
        "CreateProcessW",
    },
    "evasion": {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtUnmapViewOfSection",
    },
}

def _normalise_api_name(name):
    if isinstance(name, bytes):
        return name.decode(errors="ignore")
    return str(name)

def _powershell_authenticode(path):
    """Best-effort Windows Authenticode status using built-in PowerShell.
    This verifies the Windows signature state, but a valid signature does NOT
    prove that the program is safe.
    """
    if sys.platform != "win32":
        return {"status": "Unavailable", "publisher": ""}

    escaped = str(path).replace("'", "''")
    ps = (
        "$s=Get-AuthenticodeSignature -LiteralPath '" + escaped + "';"
        "[pscustomobject]@{Status=[string]$s.Status;"
        "Subject=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{''}}"
        "|ConvertTo-Json -Compress"
    )
    try:
        cp = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, timeout=8, check=False
        )
        raw = (cp.stdout or "").strip()
        if not raw:
            return {"status": "Unknown", "publisher": ""}
        data = json.loads(raw)
        return {
            "status": str(data.get("Status", "Unknown")),
            "publisher": str(data.get("Subject", "")),
        }
    except Exception:
        return {"status": "Unknown", "publisher": ""}

def pe_features(path, size, head):
    """Parse PE once for the 15-feature ML vector.

    The ML vector is intentionally conservative: common Windows DLLs are not
    treated as malicious, and suspicious API evidence is based on actual
    import names where possible.
    """
    api_hits = sum(1 for api in SUSPICIOUS_APIS if api in head)
    if not PEFILE_OK:
        return 0, api_hits, 0, 0.0, 0, 0, 0

    dll_calls = risky = num_sections = has_overlay = has_sig = 0
    max_sec_ent = 0.0

    try:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]
            ])
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                dlls = {e.dll.decode(errors="ignore").lower()
                        for e in pe.DIRECTORY_ENTRY_IMPORT if e.dll}
                names = [
                    _normalise_api_name(imp.name)
                    for e in pe.DIRECTORY_ENTRY_IMPORT
                    for imp in e.imports
                    if imp.name
                ]
                dll_calls = int(bool(dlls & SUSPICIOUS_DLLS))
                risky = len(dlls & RISKY_DLLS)
                api_hits = sum(
                    1 for api in SUSPICIOUS_APIS
                    if any(api.decode(errors="ignore") in n for n in names)
                )

            sec_dir = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            has_sig = int(pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir].VirtualAddress != 0)
            num_sections = len(pe.sections)

            if pe.sections:
                last = max(
                    s.PointerToRawData + s.SizeOfRawData
                    for s in pe.sections
                )
                has_overlay = int(last < size)
                if size <= PE_DEEP_SIZE_LIMIT:
                    max_sec_ent = max(s.get_entropy() for s in pe.sections)
        finally:
            pe.close()
    except Exception:
        pass

    return dll_calls, api_hits, num_sections, float(max_sec_ent), has_overlay, has_sig, risky

def extract_features(path):
    """Extract the fixed 15-feature vector with bounded memory; never executes files."""
    path = Path(path)
    size = path.stat().st_size
    with path.open("rb") as f:
        data = f.read(min(1_000_000, size))
    entropy, zero_ratio, printable_ratio = byte_stats(data)
    ext_sus = int(path.suffix.lower() in EXE_EXTENSIONS)
    magic = extension_mismatch(path)
    is_pe = int(data[:2] == b"MZ")
    suffixes = [s.lower() for s in path.suffixes]
    double_ext = int(len(suffixes) >= 2 and suffixes[-1] in EXE_EXTENSIONS and suffixes[-2] in DOC_MEDIA_EXTS)
    if is_pe:
        dll_calls, api_hits, n_sec, max_sec_ent, overlay, sig, risky = pe_features(path, size, data)
    else:
        dll_calls = api_hits = n_sec = overlay = sig = risky = 0
        max_sec_ent = 0.0
    return np.array([[math.log10(size + 1), entropy, ext_sus, magic, dll_calls,
                      api_hits, is_pe, double_ext, zero_ratio, printable_ratio,
                      n_sec, max_sec_ent, overlay, sig, risky]], dtype=float)

# -- Deep EXE Analysis (NEW) --

def _file_contains_any(path, patterns, chunk_size=4 * 1024 * 1024):
    """Search the entire file for byte patterns with bounded memory."""
    patterns = [p for p in patterns if p]
    if not patterns:
        return []
    overlap = max(len(p) for p in patterns) - 1
    found = set()
    tail = b""
    with Path(path).open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            block = tail + chunk
            for pattern in patterns:
                if pattern not in found and pattern in block:
                    found.add(pattern)
            if len(found) == len(patterns):
                break
            tail = block[-overlap:] if overlap > 0 else b""
    return list(found)


def deep_exe_analysis(path):
    """Detailed static analysis for PE/EXE files.

    Produces evidence and a heuristic score. The score is deliberately not
    called a malware probability; it represents static-risk evidence only.
    """
    result = {
        "is_pe": False,
        "machine": "Unknown",
        "compile_time": "Unknown",
        "sections": [],
        "suspicious_apis": [],
        "api_groups": [],
        "api_group_hits": {},
        "imported_dlls": [],
        "risky_dlls": [],
        "has_overlay": False,
        "overlay_entropy": 0.0,
        "has_resources": False,
        "is_packed": False,
        "packer_sections": [],
        "writable_executable_sections": 0,
        "imports_missing": False,
        "authenticode": "Unknown",
        "publisher": "",
        "risk_flags": [],
        "risk_score": 0,
        "summary": "",
    }

    if not path.exists():
        result["summary"] = "File not found."
        return result

    try:
        size = path.stat().st_size
        with open(path, "rb") as f:
            head = f.read(1_000_000)
        found_api_bytes = _file_contains_any(path, SUSPICIOUS_APIS)
    except Exception as e:
        result["summary"] = f"Cannot read file: {e}"
        return result

    if head[:2] != b"MZ":
        result["summary"] = "Not a valid PE file (no MZ header)."
        result["risk_flags"].append("Invalid / non-PE executable header")
        result["risk_score"] = _calc_risk(result)
        return result

    result["is_pe"] = True

    # Raw string hits are evidence only; import-table hits are stronger.
    found_apis = [api.decode(errors="ignore") for api in found_api_bytes]

    # Signature status is checked independently of pefile parsing.
    sig = _powershell_authenticode(path)
    result["authenticode"] = sig["status"]
    result["publisher"] = sig["publisher"]

    if not PEFILE_OK:
        ent = get_entropy(head)
        if ent > 7.4:
            result["is_packed"] = True
            result["risk_flags"].append(
                f"High overall entropy ({ent:.2f}) — possible packing/encryption"
            )
        result["suspicious_apis"] = found_apis
        if found_apis:
            result["risk_flags"].append(
                f"Suspicious API strings found: {', '.join(found_apis)}"
            )
        if result["authenticode"] == "NotSigned":
            result["risk_flags"].append("Executable is not digitally signed")
        result["risk_score"] = _calc_risk(result)
        return result

    try:
        pe = pefile.PE(str(path), fast_load=False)
    except Exception as e:
        result["summary"] = f"PE parse error: {e}"
        result["risk_flags"].append("PE structure could not be parsed correctly")
        result["risk_score"] = _calc_risk(result)
        return result

    try:
        machine_map = {0x14C: "x86", 0x8664: "x64", 0xAA64: "ARM64"}
        result["machine"] = machine_map.get(
            pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine)
        )

        # Timestamps before 2000 were previously penalised, but timestamps can
        # legitimately be old and are also easy to forge, so we only flag
        # clearly future timestamps.
        ts = pe.FILE_HEADER.TimeDateStamp
        try:
            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            result["compile_time"] = dt.strftime("%Y-%m-%d %H:%M UTC")
            if dt > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=2):
                result["risk_flags"].append("PE compile timestamp is in the future")
        except Exception:
            result["compile_time"] = str(ts)

        high_entropy_sections = 0
        for s in pe.sections:
            name = s.Name.decode(errors="replace").rstrip("\x00")
            data = s.get_data()
            ent = get_entropy(data) if data else 0.0
            characteristics = int(s.Characteristics)

            is_exec = bool(characteristics & 0x20000000)
            is_write = bool(characteristics & 0x80000000)

            if is_exec and is_write:
                result["writable_executable_sections"] += 1

            lower_name = name.lower()
            if lower_name in PACKER_SECTION_NAMES:
                result["packer_sections"].append(name)

            result["sections"].append({
                "name": name,
                "entropy": round(ent, 2),
                "size": len(data),
                "executable": is_exec,
                "writable": is_write,
            })

            if ent >= 7.2:
                high_entropy_sections += 1

        if high_entropy_sections:
            result["is_packed"] = True
            result["risk_flags"].append(
                f"{high_entropy_sections} section(s) have very high entropy (>=7.2)"
            )

        if result["packer_sections"]:
            result["risk_flags"].append(
                "Known packer/protector-like section names: " +
                ", ".join(result["packer_sections"])
            )

        if result["writable_executable_sections"]:
            result["risk_flags"].append(
                f"{result['writable_executable_sections']} executable section(s) are also writable"
            )

        # Imports
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                dlls = [
                    e.dll.decode(errors="ignore").lower()
                    for e in pe.DIRECTORY_ENTRY_IMPORT if e.dll
                ]
                result["imported_dlls"] = sorted(set(dlls))
                result["risky_dlls"] = sorted(set(dlls) & RISKY_DLLS)

                imported_names = [
                    _normalise_api_name(imp.name)
                    for e in pe.DIRECTORY_ENTRY_IMPORT
                    for imp in e.imports
                    if imp.name
                ]

                # Exact imported API names are stronger than raw strings.
                exact_hits = sorted({
                    api_name
                    for api_group in API_GROUPS.values()
                    for api_name in api_group
                    if any(api_name.lower() == n.lower() for n in imported_names)
                })
                if exact_hits:
                    result["suspicious_apis"] = exact_hits
                else:
                    result["suspicious_apis"] = found_apis

                group_hits = []
                result["api_group_hits"] = {}
                for group, names in API_GROUPS.items():
                    hits = sorted({
                        name for name in names
                        if any(name.lower() == n.lower() for n in imported_names)
                    })
                    if hits:
                        group_hits.append(group)
                        result["api_group_hits"][group] = hits
                result["api_groups"] = group_hits

                if group_hits:
                    result["risk_flags"].append(
                        "Suspicious API groups: " + ", ".join(group_hits)
                    )

                if result["risky_dlls"]:
                    result["risk_flags"].append(
                        "Contextual network/system DLL imports: " +
                        ", ".join(result["risky_dlls"])
                    )
            else:
                result["imports_missing"] = True
                result["risk_flags"].append(
                    "No import table found — may be packed or intentionally minimal"
                )
        except Exception:
            result["imports_missing"] = True

        # Overlay / appended data.
        try:
            last_offset = max(
                s.PointerToRawData + s.SizeOfRawData
                for s in pe.sections
            ) if pe.sections else 0
            if last_offset and last_offset < len(raw):
                overlay_data = raw[last_offset:]
                result["has_overlay"] = True
                result["overlay_entropy"] = round(get_entropy(overlay_data), 2)
                if len(overlay_data) >= 4096:
                    result["risk_flags"].append(
                        f"Overlay/appended data: {len(overlay_data):,} bytes "
                        f"(entropy {result['overlay_entropy']:.2f})"
                    )
        except Exception:
            pass

        # Resources are common in legitimate Windows programs, so do not score
        # resources as suspicious by themselves.
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
            result["has_resources"] = hasattr(pe, "DIRECTORY_ENTRY_RESOURCE")
        except Exception:
            pass

        # Cryptographic signature state.
        if result["authenticode"] == "Valid":
            result["risk_flags"].append(
                "Authenticode signature is valid (publisher trust signal, not proof of safety)"
            )
        elif result["authenticode"] == "NotSigned":
            result["risk_flags"].append("Executable is not digitally signed")
        elif result["authenticode"] not in ("Unknown", "Unavailable"):
            result["risk_flags"].append(
                f"Authenticode status: {result['authenticode']}"
            )

        if result["suspicious_apis"]:
            result["risk_flags"].append(
                "Imported suspicious APIs: " + ", ".join(result["suspicious_apis"])
            )

    finally:
        pe.close()

    result["risk_score"] = _calc_risk(result)

    if result["risk_score"] >= 75:
        result["summary"] = "High static-risk indicators detected."
    elif result["risk_score"] >= 45:
        result["summary"] = "Some suspicious static indicators detected."
    else:
        result["summary"] = "No strong static-malware pattern detected."

    return result


def _calc_risk(r):
    """Conservative static-evidence score (0-100), matching report Table 6.

    This is not a malware probability. Indicators are contextual and should
    be interpreted together; a valid signature is not proof of safety.
    """
    score = 0.0
    groups = set(r.get("api_groups", []) or [])

    # Process-injection APIs are strongest when several related imports co-occur.
    if "process_injection" in groups:
        group_hits = r.get("api_group_hits", {}) or {}
        hits = len(group_hits.get("process_injection", []) or [])
        score += 28 if hits >= 3 else 7

    if "persistence" in groups:
        score += 18
    if "download" in groups:
        score += 8
    if "evasion" in groups:
        score += 4

    if int(r.get("writable_executable_sections", 0) or 0) > 0:
        score += 14
    if r.get("packer_sections"):
        score += 7
    if r.get("is_packed"):
        score += 5

    overlay_entropy = float(r.get("overlay_entropy", 0.0) or 0.0)
    if r.get("has_overlay"):
        score += 3
        if overlay_entropy >= 6.0:
            score += 4
        if overlay_entropy >= 7.2:
            score += 4

    if r.get("imports_missing"):
        score += 5

    # Weak contextual signal, capped at +3 as stated in the report.
    score += min(len(r.get("risky_dlls", []) or []), 3)

    signature = str(r.get("authenticode", "Unknown"))
    if signature == "Valid":
        score -= 15
    elif signature == "NotSigned":
        score += 1
    elif signature in {"HashMismatch", "NotTrusted", "UnknownError",
                       "NotTrustedError", "HashMismatchError"}:
        score += 10

    return int(round(np.clip(score, 0, 100)))

# -- ML Model --

MODEL_VERSION = 8                                   # bump when model bundle/calibration changes
TRAINING_CSV  = Path(__file__).parent / "model" / "training_data.csv"
MIN_REAL_ROWS = 200

def _make_base_models():
    """Build the model families documented in the VIRO research report.

    Four core models are always available. XGBoost and LightGBM are optional
    additions when their packages are installed.
    """
    from sklearn.ensemble import (
        ExtraTreesClassifier, RandomForestClassifier,
        HistGradientBoostingClassifier
    )
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    models = {
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=500, min_samples_leaf=2,
            class_weight="balanced", max_features="sqrt",
            random_state=42, n_jobs=-1
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=500, min_samples_leaf=2,
            class_weight="balanced", max_features="sqrt",
            random_state=42, n_jobs=-1
        ),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=300, learning_rate=0.05, max_leaf_nodes=31,
            random_state=42
        ),
        "LogisticRegression": make_pipeline(
            StandardScaler(),
            LogisticRegression(C=1.0, max_iter=2000, class_weight="balanced")
        ),
    }

    try:
        from xgboost import XGBClassifier
        models["XGBoost"] = XGBClassifier(
            n_estimators=400, max_depth=5, learning_rate=0.05,
            tree_method="hist", eval_metric="logloss",
            subsample=0.9, colsample_bytree=0.9,
            random_state=42, n_jobs=-1
        )
    except ImportError:
        pass

    try:
        from lightgbm import LGBMClassifier
        models["LightGBM"] = LGBMClassifier(
            n_estimators=400, learning_rate=0.05,
            num_leaves=31, class_weight="balanced",
            random_state=42, verbosity=-1, n_jobs=-1
        )
    except ImportError:
        pass

    return models

def train_ensemble(X, y, log=print):
    """Cross-validate every algorithm, weight each by how well it did, then fit the final ensemble.
    Soft voting = weighted average of each model's malicious probability."""
    from sklearn.base import clone
    from sklearn.ensemble import VotingClassifier
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.metrics import roc_auc_score, f1_score, precision_score, recall_score
    from sklearn.isotonic import IsotonicRegression

    base  = _make_base_models()
    folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    oof, report = {}, {}
    for name, est in base.items():
        t0 = time.time()
        oof[name] = cross_val_predict(clone(est), X, y, cv=folds, method="predict_proba")[:, 1]
        log(f"  cross-validated {name:<19} ({time.time() - t0:4.1f}s)")

    # A model that is no better than a coin flip (AUC 0.5) gets ~zero say in the vote.
    weights = {n: max(2 * roc_auc_score(y, p) - 1, 0.01) for n, p in oof.items()}
    total   = sum(weights.values())
    oof["ENSEMBLE"] = sum(weights[n] * oof[n] for n in weights) / total   # identical maths to soft voting

    for name, p in oof.items():
        pred = (p >= 0.5).astype(int)
        report[name] = {
            "auc"      : round(float(roc_auc_score(y, p)), 4),
            "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
            "recall"   : round(float(recall_score(y, pred, zero_division=0)), 4),
            "f1"       : round(float(f1_score(y, pred, zero_division=0)), 4),
            "weight"   : round(weights[name] / total, 3) if name in weights else 1.0,
        }
    ensemble = VotingClassifier(list(base.items()), voting="soft",
                                weights=[weights[n] for n in base]).fit(X, y)

    # Calibrate the ensemble probability using only out-of-fold predictions.
    # This avoids calibrating on the same fitted predictions used for training.
    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(oof["ENSEMBLE"], y)

    for est in ensemble.estimators_:            # single-file predictions are faster without a thread pool
        if hasattr(est, "n_jobs"):
            est.n_jobs = 1
    return ensemble, report, calibrator

def synthetic_dataset(n=4000, seed=42):
    """BOOTSTRAP ONLY. Hand-designed class distributions with deliberate overlap and label noise.
    This encodes general malware heuristics; it is NOT real malware data (see --build-dataset)."""
    rng = np.random.default_rng(seed)
    y   = (rng.random(n) < 0.4).astype(int)
    m   = y == 1
    def pick(b, mal): return np.where(m, mal, b)
    size_log = np.clip(rng.normal(pick(6.3, 5.4), pick(1.1, 0.9)), 2, 9)
    entropy  = np.clip(rng.normal(pick(5.6, 6.9), pick(1.4, 0.8)), 0, 8)
    ext_sus  = (rng.random(n) < pick(0.25, 0.85)).astype(float)
    magic    = (rng.random(n) < pick(0.02, 0.18)).astype(float)
    is_pe    = (rng.random(n) < np.where(ext_sus == 1, 0.9, 0.03)).astype(float)
    double   = (rng.random(n) < pick(0.005, 0.08)).astype(float)
    zero_r   = np.where(m, rng.beta(2, 14, n), rng.beta(2, 8, n))
    print_r  = np.where(m, rng.beta(3, 5, n),  rng.beta(4, 4, n))
    dll      = is_pe * (rng.random(n) < pick(0.90, 0.95))            # nearly universal -> weak signal
    risky    = is_pe * np.clip(rng.poisson(pick(0.8, 2.2)), 0, 5)
    api      = is_pe * np.clip(rng.poisson(pick(0.7, 3.0)), 0, len(SUSPICIOUS_APIS))
    n_sec    = is_pe * np.clip(rng.poisson(pick(5.5, 3.6)), 1, 12)
    sec_ent  = is_pe * np.clip(rng.normal(pick(6.2, 7.0), pick(0.8, 0.6)), 0, 8)
    overlay  = is_pe * (rng.random(n) < pick(0.25, 0.50))
    sig      = is_pe * (rng.random(n) < pick(0.55, 0.08))
    X = np.column_stack([size_log, entropy, ext_sus, magic, dll, api, is_pe, double,
                         zero_r, print_r, n_sec, sec_ent, overlay, sig, risky])
    flip = rng.random(n) < 0.03                                     # label noise
    return X, np.where(flip, 1 - y, y)

def build_dataset(benign_dir, malware_dir, output_path=TRAINING_CSV):
    """Create labelled feature rows from supplied folders; files are never executed."""
    benign_root = Path(benign_dir).expanduser().resolve()
    malware_root = Path(malware_dir).expanduser().resolve()
    for folder in (benign_root, malware_root):
        if not folder.is_dir():
            raise ValueError(f"Dataset folder does not exist: {folder}")
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows, seen, skipped = [], set(), 0
    for folder, label in ((benign_root, 0), (malware_root, 1)):
        for path in folder.rglob("*"):
            if not path.is_file():
                continue
            try:
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                sha = digest.hexdigest()
                if sha in seen:
                    continue
                seen.add(sha)
                rows.append([*extract_features(path)[0].tolist(), label, sha, str(path)])
            except Exception as exc:
                skipped += 1
                print(f"[SKIP] {path}: {exc}")
    if not rows or {int(r[len(FEATURE_NAMES)]) for r in rows} != {0, 1}:
        raise ValueError("Need at least one readable unique file in each class (benign and malware).")
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(FEATURE_NAMES + ["label", "sha256", "source_path"])
        writer.writerows(rows)
    benign_count = sum(int(r[len(FEATURE_NAMES)]) == 0 for r in rows)
    print(f"Dataset saved: {output_path}\nUnique samples: {len(rows)} | benign: {benign_count} | malware: {len(rows)-benign_count} | skipped: {skipped}")
    print("Reminder: split by source/family and keep an independent test set to avoid data leakage.")


def load_training_csv(csv_path=TRAINING_CSV):
    """Read a real labelled dataset (columns = FEATURE_NAMES + 'label'; label 1 = malicious)."""
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        missing = [c for c in FEATURE_NAMES + ["label"] if c not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"{csv_path.name} is missing columns: {missing}")
        rows = []
        for line_no, row in enumerate(reader, start=2):
            try:
                values = [float(row[c]) for c in FEATURE_NAMES]
                label = int(float(row["label"]))
                if label not in (0, 1):
                    raise ValueError("label must be 0 or 1")
                rows.append(values + [label])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid training row {line_no}: {exc}") from exc
    if not rows:
        raise ValueError(f"{csv_path.name} contains no training rows")
    arr = np.asarray(rows, dtype=float)
    return arr[:, :-1], arr[:, -1].astype(int)

def load_or_train_model(force_retrain=False, log=print):
    """Returns a bundle dict with calibrated ML probabilities."""
    if MODEL_PATH.exists() and not force_retrain:
        try:
            bundle = joblib.load(MODEL_PATH)
            if isinstance(bundle, dict) and bundle.get("version") == MODEL_VERSION:
                return bundle
            log("Saved model is from an older VIRO version — retraining.")
        except Exception as e:                       # e.g. scikit-learn version changed
            log(f"Could not load saved model ({e}) — retraining.")

    source = "synthetic"
    if TRAINING_CSV.exists():
        try:
            X, y = load_training_csv()
            class_counts = np.bincount(y.astype(int), minlength=2)
            if len(y) >= MIN_REAL_ROWS and np.all(class_counts >= 5):
                source = "real"
            else:
                log(
                    "training_data.csv needs at least "
                    f"{MIN_REAL_ROWS} rows and at least 5 samples per class "
                    "(for 5-fold stratified CV) — using bootstrap data."
                )
        except Exception as e:
            log(f"Could not read training_data.csv ({e}) — using bootstrap data.")
    if source == "synthetic":
        X, y = synthetic_dataset()

    log(f"Training {len(_make_base_models())}-algorithm ensemble on {len(y)} {source} samples...")
    model, report, calibrator = train_ensemble(X, y, log=log)
    bundle = {
        "version": MODEL_VERSION,
        "model": model,
        "calibrator": calibrator,
        "source": source,
        "report": report,
        "n_samples": int(len(y)),
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, MODEL_PATH)
    return bundle

def _heuristic_probability(path):
    """Return static-risk score as probability-like value in [0,1]."""
    with path.open("rb") as handle:
        is_pe_header = handle.read(2) == b"MZ"
    if path.suffix.lower() in EXE_EXTENSIONS or is_pe_header:
        try:
            r = deep_exe_analysis(path)
            return r["risk_score"] / 100.0, r
        except Exception:
            pass
    # For non-PE files, retain the original lightweight score contribution.
    return 0.0, None



def _build_explanations(evidence, features=None):
    """Create human-readable evidence explanations, not formal SHAP/LIME values."""
    evidence = evidence or {}
    flagged = []
    reassuring = []

    if not evidence.get("is_pe"):
        if evidence.get("summary", "").startswith("Not a valid PE"):
            flagged.append("The file has an executable-style extension but no valid MZ/PE header.")
        else:
            reassuring.append("No PE-specific indicators were available for this file type.")
    else:
        groups = set(evidence.get("api_groups", []) or [])
        if "process_injection" in groups:
            flagged.append("Process-manipulation API imports were detected.")
        if "persistence" in groups:
            flagged.append("Persistence-related API imports were detected.")
        if "download" in groups:
            flagged.append("Download/network retrieval API imports were detected.")
        if "evasion" in groups:
            flagged.append("Anti-analysis/evasion-related API imports were detected.")
        if evidence.get("writable_executable_sections"):
            flagged.append("One or more PE sections are both writable and executable.")
        if evidence.get("packer_sections"):
            flagged.append("Packer/protector-like section names were found: " +
                           ", ".join(evidence["packer_sections"]))
        high_entropy = [
            sec for sec in evidence.get("sections", [])
            if float(sec.get("entropy", 0)) >= 7.2
        ]
        if high_entropy:
            flagged.append("High-entropy PE sections may indicate packing or encryption.")
        if evidence.get("has_overlay"):
            flagged.append(
                f"Appended overlay data was found (entropy {evidence.get('overlay_entropy', 0):.2f})."
            )
        if evidence.get("imports_missing"):
            flagged.append("The PE import table is missing or could not be parsed.")
        if evidence.get("risky_dlls"):
            flagged.append("Contextual DLL imports: " + ", ".join(evidence["risky_dlls"]))
        if evidence.get("authenticode") == "NotSigned":
            flagged.append("The executable is unsigned; this is only a weak trust signal.")
        elif evidence.get("authenticode") not in {"Valid", "Unknown", "Unavailable", "NotSigned"}:
            flagged.append("Authenticode verification reported: " + str(evidence["authenticode"]))

        if evidence.get("authenticode") == "Valid":
            reassuring.append(
                "A valid Authenticode signature was reported (publisher-trust signal only; not proof of safety)."
            )
        if not groups and not evidence.get("suspicious_apis"):
            reassuring.append("No configured suspicious API groups were identified.")
        if not evidence.get("writable_executable_sections"):
            reassuring.append("No writable-executable PE sections were identified.")
        if not evidence.get("packer_sections") and not high_entropy:
            reassuring.append("No configured packer-like section or high-entropy section indicator was identified.")
        if not evidence.get("has_overlay"):
            reassuring.append("No appended overlay data was identified.")

    if not flagged:
        flagged.append("No strong configured static-risk indicator was identified.")
    if not reassuring:
        reassuring.append("Static analysis has limits; absence of these indicators does not establish that a file is safe.")

    return {"why_flagged": flagged, "why_may_be_legitimate": reassuring}


# -- Multi-format script analysis (static only; never executes input files) --

SCRIPT_MAX_BYTES = 2_000_000

# Each rule is deliberately evidence-oriented. Single weak matches contribute
# little; combinations of download, obfuscation, execution and persistence
# indicators carry more weight. These are heuristic scores, not probabilities.
SCRIPT_RULES = {
    "encoded_powershell": {
        "extensions": {".bat", ".cmd", ".ps1"},
        "patterns": [
            r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]{0,300}(?:-enc(?:odedcommand)?\b|-e\s+[A-Za-z0-9+/=]{20,})",
            r"(?i)\b-frombase64string\s*\(",
        ],
        "points": 28,
        "description": "Encoded or Base64-decoded PowerShell command detected.",
    },
    "download_and_execute": {
        "extensions": {".bat", ".cmd", ".ps1", ".vbs", ".js"},
        "patterns": [
            r"(?i)\b(?:downloadstring|downloadfile|invoke-webrequest|iwr|start-bitstransfer)\b",
            r"(?i)\b(?:urlmon|xmlhttp|winhttp)\b.{0,180}\b(?:open|send|responsebody|responsetext)\b",
            r"(?i)\b(?:curl|wget|bitsadmin|certutil)\b[^\r\n]{0,240}(?:https?://|ftp://)",
        ],
        "points": 20,
        "description": "A command/API associated with retrieving remote content was detected.",
    },
    "download_then_execute": {
        "extensions": {".bat", ".cmd", ".ps1", ".vbs", ".js"},
        "patterns": [
            r"(?is)(?:downloadstring|downloadfile|invoke-webrequest|start-bitstransfer|certutil|bitsadmin).{0,500}(?:\biex\b|invoke-expression|start-process|wscript\.shell|shell\.run|cmd(?:\.exe)?\s+/c)",
            r"(?is)(?:\biex\b|invoke-expression|start-process|shell\.run).{0,500}(?:https?://|downloadstring|downloadfile)",
        ],
        "points": 28,
        "description": "Remote-content retrieval appears combined with execution.",
    },
    "obfuscated_script": {
        "extensions": {".bat", ".cmd", ".ps1", ".vbs", ".js"},
        "patterns": [
            r"(?i)\b(?:-windowstyle\s+hidden|-w\s+hidden|hidden\s+window)\b",
            r"(?i)\b(?:char\s*\(\s*\d+\s*\)|fromcharcode\s*\(|chrw?\s*\(\s*\d+\s*\))",
            r"(?i)\b(?:replace|substring|join)\s*\(.{0,100}(?:frombase64string|fromcharcode)",
        ],
        "points": 10,
        "description": "Obfuscation or hidden-window execution indicators were detected.",
    },
    "persistence": {
        "extensions": {".bat", ".cmd", ".ps1", ".vbs", ".js"},
        "patterns": [
            r"(?i)\\software\\microsoft\\windows\\currentversion\\run(?:once)?",
            r"(?i)\bschtasks(?:\.exe)?\b.{0,200}\b/create\b",
            r"(?i)\bnew-scheduledtask\b|\bregister-scheduledtask\b",
            r"(?i)\bshell:startup\b|\\start menu\\programs\\startup\\",
        ],
        "points": 22,
        "description": "A Windows startup or scheduled-task persistence mechanism was detected.",
    },
    "destructive_commands": {
        "extensions": {".bat", ".cmd", ".ps1"},
        "patterns": [
            r"(?i)\bformat(?:\.com)?\s+[a-z]:",
            r"(?i)\b(?:del|erase|rd|rmdir)\b[^\r\n]{0,120}(?:/s|/q|/s\s+/q|/q\s+/s)",
            r"(?i)\bvssadmin(?:\.exe)?\s+delete\s+shadows\b",
            r"(?i)\bwbadmin(?:\.exe)?\s+delete\s+catalog\b",
            r"(?i)\bdiskpart\b.{0,250}\bclean\b",
        ],
        "points": 24,
        "description": "Potentially destructive file, backup or disk commands were detected.",
    },
    "security_control_tampering": {
        "extensions": {".bat", ".cmd", ".ps1"},
        "patterns": [
            r"(?i)\bset-mppreference\b.{0,200}(?:disablerealtimemonitoring|disablebehaviormonitoring)\s+\$?true",
            r"(?i)\bsc(?:\.exe)?\s+stop\s+(?:windefend|wscsvc|sense)\b",
            r"(?i)\bnetsh\b.{0,150}\badvfirewall\s+set\s+allprofiles\s+state\s+off\b",
            r"(?i)\breg(?:\.exe)?\s+add\b.{0,250}\\\\policies\\\\microsoft\\\\windows defender",
        ],
        "points": 24,
        "description": "Commands that may weaken endpoint protection or firewall controls were detected.",
    },
    "suspicious_lolbin": {
        "extensions": {".bat", ".cmd", ".ps1"},
        "patterns": [
            r"(?i)\b(?:mshta|rundll32|regsvr32|installutil|cmstp)(?:\.exe)?\b",
            r"(?i)\b(?:wmic|wscript|cscript)(?:\.exe)?\b",
        ],
        "points": 8,
        "description": "A Windows utility sometimes abused for indirect execution was referenced.",
    },
    "credential_access": {
        "extensions": {".bat", ".cmd", ".ps1", ".vbs", ".js"},
        "patterns": [
            r"(?i)\b(?:sekurlsa|lsass|sam\s+hive|ntds\.dit|mimikatz)\b",
            r"(?i)\b(?:vaultcmd|cmdkey)\b.{0,120}\b(?:list|generic)\b",
        ],
        "points": 25,
        "description": "Credential-store or credential-access related terms were detected.",
    },
    "remote_shell_or_reverse_connection": {
        "extensions": {".bat", ".cmd", ".ps1", ".vbs", ".js"},
        "patterns": [
            r"(?i)\b(?:netcat|ncat|nc\.exe)\b.{0,180}\b(?:-e|-c)\b",
            r"(?i)\b(?:tcpclient|socket)\b.{0,250}\b(?:connect|stream)\b",
            r"(?i)\b(?:invoke-expression|\biex\b)\b.{0,200}\b(?:tcpclient|downloadstring)\b",
        ],
        "points": 22,
        "description": "A reverse-connection or remote command execution pattern was detected.",
    },
}


def analyze_batch_control_flow(script_text):
    """Statically inspect BAT/CMD labels and GOTO edges; never execute commands."""
    lines = script_text.splitlines()
    labels, gotos, commands = {}, [], []
    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.lower().startswith("rem ") or line.lower() == "rem" or line.startswith("::"):
            continue
        match = re.match(r"^:([A-Za-z0-9_.-]+)\s*(?:$|&)", line)
        if match:
            labels.setdefault(match.group(1).lower(), index)
            continue
        jump = re.search(r"(?i)(?:^|[&\s])goto\s+:?([A-Za-z0-9_.-]+)", line)
        if jump:
            gotos.append((index, jump.group(1).lower()))
        commands.append((index, line))

    loops = []
    for goto_line, target in gotos:
        if target not in labels or labels[target] > goto_line:
            continue
        start = labels[target]
        body = "\n".join(line for idx, line in commands if start < idx <= goto_line)
        creates = bool(re.search(r"(?i)(?:^|[&\s])(?:mkdir|md)\s+", body))
        changes = bool(re.search(r"(?i)(?:^|[&\s])(?:cd|chdir|pushd)\s+", body))
        loops.append({
            "label": target, "label_line": start + 1, "goto_line": goto_line + 1,
            "directory_creation": creates, "directory_navigation": changes,
            "potential_nested_directory_growth": creates and changes,
        })
    return {
        "backward_goto_loops": loops,
        "has_backward_loop": bool(loops),
        "has_directory_creation": bool(re.search(r"(?im)^\s*(?:mkdir|md)\s+", script_text)),
        "has_directory_navigation": bool(re.search(r"(?im)^\s*(?:cd|chdir|pushd)\s+", script_text)),
        "potential_nested_directory_growth": any(x["potential_nested_directory_growth"] for x in loops),
    }


def analyze_script_file(path):
    """Inspect BAT/CMD/PowerShell/VBS/JS text without executing it.

    Returns a 0-100 heuristic evidence score. The result is not a probability
    and should be used for triage, not as a definitive malware verdict.
    """
    path = Path(path)
    result = {
        "analysis_type": "script",
        "script_type": path.suffix.lower(),
        "is_pe": False,
        "risk_score": 0,
        "risk_flags": [],
        "matched_rules": [],
        "why_flagged": [],
        "why_may_be_legitimate": [],
        "summary": "",
        "bytes_inspected": 0,
        "truncated": False,
        "execution_performed": False,
    }
    if not path.is_file():
        result["summary"] = "File not found."
        result["why_flagged"] = ["The selected file could not be found."]
        return result

    size = path.stat().st_size
    with path.open("rb") as handle:
        raw = handle.read(SCRIPT_MAX_BYTES + 1)
    result["bytes_inspected"] = min(len(raw), SCRIPT_MAX_BYTES)
    result["truncated"] = len(raw) > SCRIPT_MAX_BYTES
    text = raw[:SCRIPT_MAX_BYTES].decode("utf-8-sig", errors="replace")
    # Remove NUL bytes often present in UTF-16LE/BE text and normalise line endings.
    if text.count("\x00") > max(4, len(text) // 10):
        try:
            text = raw[:SCRIPT_MAX_BYTES].decode("utf-16", errors="replace")
        except Exception:
            pass
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    batch_flow = None
    if path.suffix.lower() in {".bat", ".cmd"}:
        batch_flow = analyze_batch_control_flow(text)
        result["batch_control_flow"] = batch_flow

    score = 0
    matched = []
    matched_ids = set()
    for rule_id, rule in SCRIPT_RULES.items():
        if path.suffix.lower() not in rule["extensions"]:
            continue
        hits = []
        for pattern in rule["patterns"]:
            try:
                if re.search(pattern, text):
                    hits.append(pattern)
            except re.error:
                continue
        if hits:
            score += int(rule["points"])
            matched_ids.add(rule_id)
            matched.append({
                "id": rule_id,
                "description": rule["description"],
                "points": int(rule["points"]),
                "matches": len(hits),
            })

    # Backward GOTO loops can repeat commands. mkdir plus cd/pushd inside
    # the loop is a potential nested-directory/resource-exhaustion pattern.
    if batch_flow and batch_flow["has_backward_loop"]:
        loop_count = len(batch_flow["backward_goto_loops"])
        score += 35
        matched.append({
            "id": "batch_unbounded_backward_loop",
            "description": f"Potential unbounded batch loop detected ({loop_count} backward GOTO jump(s)).",
            "points": 35, "matches": loop_count,
        })
        if batch_flow["potential_nested_directory_growth"]:
            score += 25
            matched.append({
                "id": "batch_repeated_directory_growth",
                "description": "Directory creation and navigation occur inside a backward-jump loop; repeated nested directory growth or resource exhaustion may result.",
                "points": 25, "matches": 1,
            })
    elif batch_flow and batch_flow["has_directory_creation"]:
        result["batch_behavior_note"] = (
            "Directory creation command found, but no backward GOTO loop was detected. "
            "The script may create a directory once if run."
        )

    # Strong combinations matter more than isolated utilities.
    if "download_and_execute" in matched_ids and "obfuscated_script" in matched_ids:
        score += 12
        matched.append({
            "id": "download_execute_obfuscation",
            "description": "Remote retrieval/execution is combined with obfuscation.",
            "points": 12,
            "matches": 1,
        })
    if "persistence" in matched_ids and (
        "encoded_powershell" in matched_ids or "download_then_execute" in matched_ids
    ):
        score += 10
        matched.append({
            "id": "persistence_execution_chain",
            "description": "Persistence indicators are combined with encoded or downloaded execution.",
            "points": 10,
            "matches": 1,
        })

    score = int(np.clip(score, 0, 100))
    result["risk_score"] = score
    result["matched_rules"] = matched
    result["risk_flags"] = [item["description"] for item in matched]
    result["why_flagged"] = list(result["risk_flags"])

    if result["truncated"]:
        result["why_flagged"].append(
            f"Only the first {SCRIPT_MAX_BYTES:,} bytes were inspected; review is incomplete."
        )
    if not matched:
        result["why_may_be_legitimate"] = []
        if result.get("batch_behavior_note"):
            result["why_may_be_legitimate"].append(result["batch_behavior_note"])
        result["why_may_be_legitimate"].extend([
            "No configured suspicious command-pattern combination was identified.",
            "The file was inspected as text only; no command or script was executed.",
        ])
        result["summary"] = (
            "No configured script-risk indicators found. This is a low-risk "
            "heuristic result, not proof that the script is safe."
        )
    else:
        result["why_may_be_legitimate"] = [
            "Some flagged commands can also appear in legitimate administration scripts.",
            "Review the full script and its intended purpose before taking action.",
        ]
        result["summary"] = (
            f"Detected {len(matched)} configured suspicious pattern group(s). "
            "Manual review is recommended."
        )
    if result["truncated"]:
        result["summary"] += " The file was truncated for analysis."
    return result


def _unsupported_file_result(path):
    """Do not label unknown/uninspected formats as safe."""
    return (
        0, {},
        {
            "analysis_type": "unsupported",
            "source": "none",
            "confidence": "not assessed",
            "ml_probability": None,
            "static_risk": None,
            "why_flagged": [
                f"VIRO does not currently have a dedicated analyser for {Path(path).suffix or 'this file type'}."
            ],
            "why_may_be_legitimate": [
                "No conclusion about safety can be made because this format was not analysed."
            ],
            "score_formula": "No score — unsupported file type",
        }
    )


def compute_threat_details(path, bundle):
    """Route each file to its appropriate static analyser; never execute files."""
    path = Path(path)
    suffix = path.suffix.lower()

    if suffix in SCRIPT_EXTENSIONS:
        evidence = analyze_script_file(path)
        score = int(evidence["risk_score"])
        level = "low" if score < SAFE_THRESHOLD else (
            "warning" if score < WARN_THRESHOLD else "high"
        )
        details = {
            "analysis_type": "script",
            "ml_probability": None,
            "static_risk": float(score),
            "confidence": "heuristic",
            "source": "script rules",
            "evidence": evidence,
            "why_flagged": evidence["why_flagged"] or [
                "No configured suspicious script pattern was identified."
            ],
            "why_may_be_legitimate": evidence["why_may_be_legitimate"],
            "score_formula": "Rule-based script evidence score — not an ML probability",
            "level": level,
        }
        return score, {}, details

    if suffix in PE_EXTENSIONS:
        try:
            with path.open("rb") as handle:
                has_mz_header = handle.read(2) == b"MZ"
        except OSError:
            has_mz_header = False
        if not has_mz_header:
            return (
                0, {},
                {
                    "analysis_type": "invalid_pe",
                    "source": "header validation",
                    "confidence": "not assessed",
                    "ml_probability": None,
                    "static_risk": None,
                    "why_flagged": [
                        "The file uses an executable extension but does not contain the expected MZ header."
                    ],
                    "why_may_be_legitimate": [
                        "The file may be corrupted, misnamed or a non-standard installer; manual verification is required."
                    ],
                    "score_formula": "No score — executable header validation failed",
                }
            )

    if suffix not in PE_EXTENSIONS and suffix not in DOC_MEDIA_EXTS:
        return _unsupported_file_result(path)

    features = extract_features(path)
    model = bundle["model"]

    raw_proba = model.predict_proba(features)[0]
    model_p = float(raw_proba[1]) if len(raw_proba) > 1 else 0.0

    calibrator = bundle.get("calibrator")
    if calibrator is not None:
        try:
            model_p = float(calibrator.predict([model_p])[0])
        except Exception:
            pass

    votes = {}
    named = getattr(model, "named_estimators_", {})
    estimators = getattr(model, "estimators_", [])
    if hasattr(named, "items"):
        for name, estimator in named.items():
            try:
                p = estimator.predict_proba(features)[0]
                votes[name] = float(p[1]) if len(p) > 1 else 0.0
            except Exception:
                continue
    else:
        for index, estimator in enumerate(estimators):
            try:
                p = estimator.predict_proba(features)[0]
                votes[f"Model_{index+1}"] = float(p[1]) if len(p) > 1 else 0.0
            except Exception:
                continue

    heuristic_p, evidence = _heuristic_probability(path)
    if evidence is None:
        evidence = {
            "is_pe": False, "summary": "Non-PE document/media file; PE-specific evidence unavailable.",
            "risk_score": 0, "risk_flags": [], "api_groups": [],
            "suspicious_apis": [], "sections": [], "risky_dlls": [],
            "why_flagged": [], "why_may_be_legitimate": []
        }

    if bundle.get("source") == "real":
        final_p = 0.65 * model_p + 0.35 * heuristic_p
        confidence = "experimental"
    else:
        final_p = 0.25 * model_p + 0.75 * heuristic_p
        confidence = "low"

    score = int(round(np.clip(final_p, 0, 1) * 100))
    explanations = _build_explanations(evidence, features)
    evidence["why_flagged"] = explanations["why_flagged"]
    evidence["why_may_be_legitimate"] = explanations["why_may_be_legitimate"]

    details = {
        "analysis_type": "pe" if suffix in PE_EXTENSIONS else "document_media",
        "ml_probability": round(model_p * 100, 1),
        "static_risk": round(heuristic_p * 100, 1),
        "confidence": confidence,
        "source": bundle.get("source", "unknown"),
        "evidence": evidence,
        "why_flagged": explanations["why_flagged"],
        "why_may_be_legitimate": explanations["why_may_be_legitimate"],
        "score_formula": "65% ML + 35% static evidence" if bundle.get("source") == "real"
                         else "25% ML + 75% static evidence (synthetic bootstrap)",
    }
    return score, votes, details

def compute_threat_score(path, bundle):
    return compute_threat_details(path, bundle)[0]


def model_summary(bundle):
    n = len(bundle["model"].estimators_)
    if bundle["source"] == "real":
        auc = bundle["report"]["ENSEMBLE"]["auc"]
        return (
            f"Model: {n}-algorithm ensemble | real data "
            f"({bundle['n_samples']:,} files, internal CV AUC {auc:.3f}) | experimental"
        )
    return (
        f"Model: {n}-algorithm ensemble | bootstrap data only | "
        f"LOW CONFIDENCE — synthetic training only; manual review required"
    )


def print_report(bundle):
    print(
        f"\nSource: {bundle['source']} data, {bundle['n_samples']} samples "
        f"(5-fold cross-validated)"
    )
    print(
        f"{'Algorithm':<20}{'AUC':>7}{'Prec':>8}"
        f"{'Recall':>8}{'F1':>8}{'Weight':>9}"
    )
    for name, r in bundle["report"].items():
        print(
            f"{name:<20}{r['auc']:>7.3f}{r['precision']:>8.3f}"
            f"{r['recall']:>8.3f}{r['f1']:>8.3f}{r['weight']:>9.3f}"
        )
    if bundle["source"] == "synthetic":
        print(
            "\nWARNING: synthetic/bootstrap data is not a real malware benchmark."
        )
        print(
            "Use --build-dataset with known-good and known-malicious files, then"
            " --train for meaningful model performance."
        )

# -- File Organizer --

def organize_safe_file(path):
    ext = path.suffix.lower()
    for folder, exts in ORGANIZED_DIRS.items():
        if ext in exts:
            dest_dir = DESKTOP_DIR / folder
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / path.name
            counter = 1
            while dest.exists():
                dest = dest_dir / f"{path.stem}_{counter}{path.suffix}"
                counter += 1
            shutil.move(str(path), str(dest))
            return folder, dest
    return None, path

def quarantine_file(path):
    """Move a file into quarantine and write original-path/hash metadata."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"File no longer exists: {path}")
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    dest = QUARANTINE_DIR / path.name
    counter = 1
    while dest.exists():
        dest = QUARANTINE_DIR / f"{path.stem}_{counter}{path.suffix}"
        counter += 1
    original = str(path.resolve())
    shutil.move(str(path), str(dest))
    metadata = {"original_path": original, "quarantined_path": str(dest.resolve()),
                "sha256": digest.hexdigest(),
                "quarantined_at": datetime.datetime.now().isoformat(timespec="seconds"),
                "note": "A file move is not cryptographic isolation."}
    dest.with_name(dest.name + ".viro.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return dest

# -- VIRO GUI --

class ViroApp(tk.Tk):
    COLORS = {
        "bg": "#0d1117", "panel": "#161b22", "accent": "#58a6ff",
        "safe": "#3fb950", "warn": "#d29922", "danger": "#f85149",
        "fg": "#c9d1d9", "fg_dim": "#6e7681",
        "btn_bg": "#21262d", "btn_hover": "#30363d", "border": "#30363d",
    }

    def __init__(self):
        super().__init__()
        self.title("VIRO — Virus Inspection & Response Organizer")
        self.geometry("1320x850")
        self.configure(bg=self.COLORS["bg"])
        self.resizable(True, True)
        self.title("VIRO — preparing ML model (first run only)...")
        self.update()
        self.model         = load_or_train_model()
        self.title("VIRO — Virus Inspection & Response Organizer")
        self.observer      = None
        self.monitoring    = False
        self.log_rows      = []
        self._bulk_running = False
        self._scan_lock = threading.Lock()
        self._active_scans = set()
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        """Responsive SharpScanner-inspired dashboard with a scrollable workspace."""
        C = self.COLORS
        self.geometry("1440x900")
        self.minsize(1050, 700)
        self.configure(bg="#07111c")

        self.UI = {
            "shell": "#07111c", "sidebar": "#081725", "top": "#0a1927",
            "panel": "#0d1d2b", "panel2": "#102437", "border": "#1c354a",
            "text": "#e8f2fb", "muted": "#8299ad", "blue": "#28a9ff",
            "cyan": "#19c8d2", "green": "#43c77b", "orange": "#f39a36",
            "purple": "#a879f5", "red": "#f05b63"
        }
        U = self.UI

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "VIRO.Treeview", background="#0a1825", foreground=U["text"],
            fieldbackground="#0a1825", rowheight=30,
            font=("Segoe UI", 9), borderwidth=0
        )
        style.configure(
            "VIRO.Treeview.Heading", background="#142b3e",
            foreground="#8ecaff", font=("Segoe UI", 8, "bold"),
            relief="flat", padding=(8, 9)
        )
        style.map("VIRO.Treeview",
                  background=[("selected", "#17466b")],
                  foreground=[("selected", "#ffffff")])
        style.configure(
            "VIRO.Horizontal.TProgressbar",
            troughcolor="#142a3d", background=U["blue"],
            bordercolor="#142a3d", lightcolor=U["blue"],
            darkcolor=U["blue"], thickness=10
        )

        # Main shell
        shell = tk.Frame(self, bg=U["shell"])
        shell.pack(fill="both", expand=True)

        # Fixed left navigation rail
        self.sidebar = tk.Frame(shell, bg=U["sidebar"], width=205)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=U["sidebar"], padx=17, pady=21)
        brand.pack(fill="x")
        tk.Label(brand, text="⬡", font=("Segoe UI Symbol", 29, "bold"),
                 fg=U["blue"], bg=U["sidebar"]).pack(side="left", padx=(0, 10))
        brand_text = tk.Frame(brand, bg=U["sidebar"])
        brand_text.pack(side="left")
        tk.Label(brand_text, text="VIRO", font=("Segoe UI", 19, "bold"),
                 fg=U["text"], bg=U["sidebar"]).pack(anchor="w")
        tk.Label(brand_text, text="INSPECT. RESPOND. PROTECT.",
                 font=("Segoe UI", 6, "bold"), fg=U["muted"],
                 bg=U["sidebar"]).pack(anchor="w")

        tk.Frame(self.sidebar, bg=U["border"], height=1).pack(fill="x", padx=14, pady=(0, 14))
        self.nav_buttons = {}
        nav_items = [
            ("▦", "Dashboard", self._show_dashboard),
            ("⌕", "Quick Scan", self._manual_scan),
            ("◉", "File Monitor", self._toggle_monitoring),
            ("⚑", "Deep Analysis", self._deep_exe_dialog),
            ("▣", "Quarantine", self._open_quarantine),
            ("⚙", "Settings", self._show_settings),
        ]
        for glyph, label, command in nav_items:
            btn = tk.Button(
                self.sidebar, text=f"  {glyph}    {label}", command=command,
                anchor="w", bg="#103451" if label == "Dashboard" else U["sidebar"],
                fg=U["text"] if label == "Dashboard" else "#b4c5d4",
                activebackground="#17466b", activeforeground="#ffffff",
                relief="flat", bd=0, padx=13, pady=12,
                font=("Segoe UI", 9), cursor="hand2"
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[label] = btn
            btn.bind("<Enter>", lambda e, b=btn: b.configure(bg="#102a40"))
            btn.bind("<Leave>", lambda e, b=btn, l=label:
                     b.configure(bg="#103451" if l == "Dashboard" else U["sidebar"]))

        spacer = tk.Frame(self.sidebar, bg=U["sidebar"])
        spacer.pack(fill="both", expand=True)
        promo = tk.Frame(self.sidebar, bg="#102a40", padx=12, pady=12,
                         highlightthickness=1, highlightbackground=U["border"])
        promo.pack(fill="x", padx=12, pady=13)
        tk.Label(promo, text="✦  VIRO SECURITY",
                 font=("Segoe UI", 8, "bold"), fg=U["blue"],
                 bg="#102a40").pack(anchor="w")
        tk.Label(promo, text="Static file inspection\nand download monitoring.",
                 font=("Segoe UI", 8), fg="#b1c5d7",
                 bg="#102a40", justify="left").pack(anchor="w", pady=(6, 0))
        tk.Label(self.sidebar, text="VIRO 6.0  •  PYTHON / TKINTER",
                 font=("Segoe UI", 6, "bold"), fg="#58748b",
                 bg=U["sidebar"]).pack(pady=(0, 13))

        # Right workspace and fixed title bar
        workspace = tk.Frame(shell, bg=U["shell"])
        workspace.pack(side="left", fill="both", expand=True)
        topbar = tk.Frame(workspace, bg=U["top"], height=58)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)
        self.page_title = tk.Label(
            topbar, text="Dashboard", font=("Segoe UI", 14, "bold"),
            fg=U["text"], bg=U["top"]
        )
        self.page_title.pack(side="left", padx=22)
        self.top_status_dot = tk.Label(
            topbar, text="●", font=("Arial", 11),
            fg=U["muted"], bg=U["top"]
        )
        self.top_status_dot.pack(side="right", padx=(12, 6))
        self.top_status_text = tk.Label(
            topbar, text="NOT MONITORING", font=("Segoe UI", 8, "bold"),
            fg=U["muted"], bg=U["top"]
        )
        self.top_status_text.pack(side="right", padx=(0, 20))

        # Scrollable dashboard: the canvas viewport expands with the window.
        scroll_host = tk.Frame(workspace, bg=U["shell"])
        scroll_host.pack(fill="both", expand=True)
        self.dashboard_canvas = tk.Canvas(
            scroll_host, bg=U["shell"], highlightthickness=0,
            borderwidth=0
        )
        self.dashboard_scrollbar = ttk.Scrollbar(
            scroll_host, orient="vertical", command=self.dashboard_canvas.yview
        )
        self.dashboard_canvas.configure(yscrollcommand=self.dashboard_scrollbar.set)
        self.dashboard_scrollbar.pack(side="right", fill="y")
        self.dashboard_canvas.pack(side="left", fill="both", expand=True)

        self.dashboard_content = tk.Frame(self.dashboard_canvas, bg=U["shell"])
        self.dashboard_window = self.dashboard_canvas.create_window(
            (0, 0), window=self.dashboard_content, anchor="nw"
        )
        self.dashboard_content.bind(
            "<Configure>",
            lambda e: self.dashboard_canvas.configure(
                scrollregion=self.dashboard_canvas.bbox("all")
            )
        )
        self.dashboard_canvas.bind(
            "<Configure>",
            lambda e: self.dashboard_canvas.itemconfigure(
                self.dashboard_window, width=e.width
            )
        )
        self.dashboard_canvas.bind_all("<MouseWheel>", self._on_dashboard_mousewheel)
        self.dashboard_canvas.bind_all("<Button-4>", self._on_dashboard_mousewheel)
        self.dashboard_canvas.bind_all("<Button-5>", self._on_dashboard_mousewheel)

        content = self.dashboard_content
        content.configure(padx=18, pady=16)

        # Welcome hero + honest engine status card
        hero_row = tk.Frame(content, bg=U["shell"])
        hero_row.pack(fill="x", pady=(0, 14))
        hero = tk.Frame(hero_row, bg="#0b2b47", height=178,
                        highlightthickness=1, highlightbackground="#18517a")
        hero.pack(side="left", fill="both", expand=True, padx=(0, 10))
        hero.pack_propagate(False)
        hero_left = tk.Frame(hero, bg="#0b2b47")
        hero_left.pack(side="left", fill="both", expand=True, padx=23, pady=18)
        tk.Label(hero_left, text="WELCOME BACK!",
                 font=("Segoe UI", 8, "bold"), fg="#68c5ff",
                 bg="#0b2b47").pack(anchor="w")
        tk.Label(hero_left, text="Your files. Your control.\nA clearer view of file security.",
                 font=("Segoe UI", 18, "bold"), fg="#f3f8ff",
                 bg="#0b2b47", justify="left").pack(anchor="w", pady=(7, 6))
        tk.Label(hero_left, text="Scan files  •  Monitor Downloads  •  Review suspicious indicators",
                 font=("Segoe UI", 8), fg="#b2cde2",
                 bg="#0b2b47").pack(anchor="w")
        self.hero_model_label = tk.Label(
            hero_left, text=self._model_status_text(),
            font=("Segoe UI", 7, "bold"), fg="#4ed39a",
            bg="#0b2b47"
        )
        self.hero_model_label.pack(anchor="w", pady=(12, 0))
        tk.Label(hero, text="⬡", font=("Segoe UI Symbol", 88, "bold"),
                 fg="#1476b5", bg="#0b2b47").pack(side="right", padx=27)

        health = tk.Frame(hero_row, bg=U["panel"], width=290, height=178,
                          highlightthickness=1, highlightbackground=U["border"])
        health.pack(side="right", fill="y")
        health.pack_propagate(False)
        tk.Label(health, text="VIRO ENGINE HEALTH",
                 font=("Segoe UI", 8, "bold"), fg=U["text"],
                 bg=U["panel"]).pack(anchor="w", padx=15, pady=(14, 6))
        self.engine_health_value = tk.Label(
            health, text="READY", font=("Segoe UI", 23, "bold"),
            fg=U["green"], bg=U["panel"]
        )
        self.engine_health_value.pack(anchor="w", padx=15)
        tk.Label(health, text=f"Model source   {self.model.get('source', 'unknown').upper()}",
                 font=("Segoe UI", 8), fg="#b3c6d7",
                 bg=U["panel"]).pack(anchor="w", padx=15, pady=(3, 4))
        tk.Label(health, text=f"ML algorithms   {len(self.model['model'].estimators_)}",
                 font=("Segoe UI", 8), fg="#b3c6d7",
                 bg=U["panel"]).pack(anchor="w", padx=15, pady=3)
        tk.Label(health, text="File size limit   NONE (streaming)",
                 font=("Segoe UI", 8), fg="#b3c6d7",
                 bg=U["panel"]).pack(anchor="w", padx=15, pady=3)
        tk.Label(health, text="Static analysis only — files are not executed",
                 font=("Segoe UI", 7), fg=U["muted"],
                 bg=U["panel"]).pack(anchor="w", padx=15, pady=(8, 0))

        # Action cards in one flexible row
        section = tk.Frame(content, bg=U["shell"])
        section.pack(fill="x", pady=(0, 8))
        tk.Label(section, text="Quick Actions", font=("Segoe UI", 11, "bold"),
                 fg=U["text"], bg=U["shell"]).pack(side="left")
        tk.Label(section, text="Select a task",
                 font=("Segoe UI", 8), fg=U["muted"],
                 bg=U["shell"]).pack(side="right")

        actions = tk.Frame(content, bg=U["shell"])
        actions.pack(fill="x", pady=(0, 14))
        specs = [
            ("⌕", "Quick Scan", "Scan a selected file", "SCAN FILE",
             self._manual_scan, U["blue"]),
            ("◉", "File Monitor", "Watch the Downloads folder", "START / STOP",
             self._toggle_monitoring, U["cyan"]),
            ("⚠", "Deep Analysis", "Inspect EXE / DLL indicators", "ANALYSE",
             self._deep_exe_dialog, U["orange"]),
            ("▦", "Scan Downloads", "Scan existing downloaded files", "SCAN NOW",
             self._bulk_scan_downloads, U["purple"]),
            ("▣", "Quarantine", "Open quarantined-file folder", "OPEN FOLDER",
             self._open_quarantine, U["green"]),
        ]
        self.action_buttons = {}
        for i, (glyph, title, desc, label, command, accent) in enumerate(specs):
            card = tk.Frame(actions, bg=U["panel"], padx=10, pady=11,
                            highlightthickness=1, highlightbackground=U["border"])
            card.pack(side="left", fill="both", expand=True,
                      padx=(0 if i == 0 else 5, 5 if i < 4 else 0))
            tk.Label(card, text=glyph, font=("Segoe UI Symbol", 24, "bold"),
                     fg=accent, bg=U["panel"]).pack(anchor="center")
            tk.Label(card, text=title, font=("Segoe UI", 9, "bold"),
                     fg=U["text"], bg=U["panel"]).pack(pady=(5, 3))
            tk.Label(card, text=desc, font=("Segoe UI", 7),
                     fg=U["muted"], bg=U["panel"], height=2,
                     wraplength=145, justify="center").pack(fill="x")
            btn = tk.Button(
                card, text=label, command=command, bg="#123653",
                fg=accent, activebackground="#1b4a6d",
                activeforeground="#ffffff", relief="flat", bd=0,
                font=("Segoe UI", 7, "bold"), padx=6, pady=7,
                cursor="hand2"
            )
            btn.pack(fill="x", pady=(9, 0))
            self.action_buttons[title] = btn

        # Progress panel
        progress = tk.Frame(content, bg=U["panel"], padx=14, pady=12,
                            highlightthickness=1, highlightbackground=U["border"])
        progress.pack(fill="x", pady=(0, 14))
        phead = tk.Frame(progress, bg=U["panel"])
        phead.pack(fill="x")
        tk.Label(phead, text="SCAN ACTIVITY",
                 font=("Segoe UI", 8, "bold"), fg=U["text"],
                 bg=U["panel"]).pack(side="left")
        self.progress_text = tk.Label(
            phead, text="Ready — no scan running",
            font=("Segoe UI", 8), fg=U["muted"], bg=U["panel"]
        )
        self.progress_text.pack(side="right")
        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(
            progress, variable=self.progress_var, maximum=100,
            mode="determinate", style="VIRO.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(fill="x", pady=(9, 0))

        # Three lower panels; they naturally extend the scrollable content.
        lower = tk.Frame(content, bg=U["shell"])
        lower.pack(fill="both", expand=True, pady=(0, 14))

        severity = tk.Frame(lower, bg=U["panel"], width=235, padx=13, pady=12,
                            highlightthickness=1, highlightbackground=U["border"])
        severity.pack(side="left", fill="y", padx=(0, 9))
        severity.pack_propagate(False)
        tk.Label(severity, text="ISSUE SEVERITY",
                 font=("Segoe UI", 8, "bold"), fg=U["text"],
                 bg=U["panel"]).pack(anchor="w")
        self.severity_canvas = tk.Canvas(
            severity, width=150, height=150, bg=U["panel"],
            highlightthickness=0
        )
        self.severity_canvas.pack(pady=5)
        self.severity_counts = tk.Frame(severity, bg=U["panel"])
        self.severity_counts.pack(fill="x")
        self._draw_severity_chart()

        summary = tk.Frame(lower, bg=U["panel"], width=260, padx=13, pady=12,
                           highlightthickness=1, highlightbackground=U["border"])
        summary.pack(side="left", fill="y", padx=(0, 9))
        summary.pack_propagate(False)
        tk.Label(summary, text="PROTECTION SUMMARY",
                 font=("Segoe UI", 8, "bold"), fg=U["text"],
                 bg=U["panel"]).pack(anchor="w", pady=(0, 10))
        self.engine_rows = {}
        for label, value in [
            ("Monitoring", "ACTIVE" if self.monitoring else "OFF"),
            ("ML model", self.model.get("source", "unknown").upper()),
            ("Model samples", str(self.model.get("n_samples", "—"))),
            ("Scan size limit", "No fixed limit"),
            ("Quarantine", "AVAILABLE"),
            ("Watchdog", "AVAILABLE" if WATCHDOG_OK else "NOT INSTALLED"),
            ("PE parser", "AVAILABLE" if PEFILE_OK else "NOT INSTALLED"),
        ]:
            row = tk.Frame(summary, bg=U["panel"])
            row.pack(fill="x", pady=6)
            tk.Label(row, text=label, font=("Segoe UI", 8),
                     fg="#9bb0c2", bg=U["panel"]).pack(side="left")
            value_label = tk.Label(
                row, text=value, font=("Segoe UI", 8, "bold"),
                fg=U["green"] if value in {"ACTIVE", "AVAILABLE", "REAL"} else U["muted"],
                bg=U["panel"]
            )
            value_label.pack(side="right")
            self.engine_rows[label] = value_label
        tk.Frame(summary, bg=U["border"], height=1).pack(fill="x", pady=8)
        tk.Label(
            summary, text="VIRO is an educational static-analysis tool.\n"
                          "A score is not proof that a file is safe or malicious.",
            font=("Segoe UI", 7), fg=U["muted"],
            bg=U["panel"], justify="left", wraplength=225
        ).pack(anchor="w")

        recent = tk.Frame(lower, bg=U["panel"], padx=12, pady=12,
                          highlightthickness=1, highlightbackground=U["border"])
        recent.pack(side="left", fill="both", expand=True)
        recent_head = tk.Frame(recent, bg=U["panel"])
        recent_head.pack(fill="x", pady=(0, 9))
        tk.Label(recent_head, text="RECENT SECURITY ACTIVITY",
                 font=("Segoe UI", 8, "bold"), fg=U["text"],
                 bg=U["panel"]).pack(side="left")
        tk.Label(recent_head, text="THIS SESSION",
                 font=("Segoe UI", 7, "bold"), fg=U["blue"],
                 bg=U["panel"]).pack(side="right")
        table_wrap = tk.Frame(recent, bg=U["panel"])
        table_wrap.pack(fill="both", expand=True)
        cols = ("Time", "File", "Threat Score", "Status", "Action")
        self.tree = ttk.Treeview(
            table_wrap, columns=cols, show="headings", height=9,
            selectmode="browse", style="VIRO.Treeview"
        )
        self._style_tree(cols)
        vsb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Footer stays visible while the central dashboard scrolls.
        footer = tk.Frame(workspace, bg="#081522", height=34)
        footer.pack(side="bottom", fill="x")
        footer.pack_propagate(False)
        tk.Label(footer, text="⬡  VIRO FILE PROTECTION",
                 font=("Segoe UI", 7, "bold"), fg=U["green"],
                 bg="#081522").pack(side="left", padx=13)
        tk.Label(footer, text="Static analysis • User-controlled response",
                 font=("Segoe UI", 7), fg=U["muted"],
                 bg="#081522").pack(side="left", padx=12)
        tk.Label(footer, text="Python + Tkinter",
                 font=("Segoe UI", 7), fg=U["muted"],
                 bg="#081522").pack(side="right", padx=13)

    def _on_dashboard_mousewheel(self, event):
        """Scroll the main dashboard with the mouse wheel."""
        if not hasattr(self, "dashboard_canvas"):
            return
        if getattr(event, "num", None) == 4:
            self.dashboard_canvas.yview_scroll(-3, "units")
        elif getattr(event, "num", None) == 5:
            self.dashboard_canvas.yview_scroll(3, "units")
        else:
            delta = getattr(event, "delta", 0)
            if delta:
                self.dashboard_canvas.yview_scroll(int(-1 * (delta / 120)), "units")

    def _model_status_text(self):
        if self.model.get("source") == "real":
            return "●  REAL-LABELLED TRAINING DATA — EXPERIMENTAL"
        return "●  SYNTHETIC TRAINING DATA — LOW CONFIDENCE; REVIEW REQUIRED"

    def _draw_severity_chart(self):
        if not hasattr(self, "severity_canvas"):
            return
        canvas = self.severity_canvas
        canvas.delete("all")
        counts = getattr(self, "_severity_totals", {"low": 0, "review": 0, "high": 0})
        total = sum(counts.values())
        x1, y1, x2, y2 = 15, 12, 135, 132
        canvas.create_oval(x1, y1, x2, y2, outline="#203b51", width=14)
        if total:
            start = 90
            for key, color in [
                ("low", self.UI["green"]),
                ("review", self.UI["orange"]),
                ("high", self.UI["red"])
            ]:
                value = counts[key]
                if value:
                    extent = 360 * value / total
                    canvas.create_arc(
                        x1, y1, x2, y2, start=start, extent=extent,
                        style="arc", outline=color, width=14
                    )
                    start += extent
        canvas.create_text(75, 58, text=str(total), fill=self.UI["text"],
                           font=("Segoe UI", 22, "bold"))
        canvas.create_text(75, 81, text="SCANS", fill=self.UI["muted"],
                           font=("Segoe UI", 8, "bold"))
        for child in self.severity_counts.winfo_children():
            child.destroy()
        for label, key, color in [
            ("Low risk", "low", self.UI["green"]),
            ("Needs review", "review", self.UI["orange"]),
            ("High risk", "high", self.UI["red"])
        ]:
            row = tk.Frame(self.severity_counts, bg=self.UI["panel"])
            row.pack(fill="x", pady=3)
            tk.Label(row, text="●", fg=color, bg=self.UI["panel"],
                     font=("Arial", 8)).pack(side="left")
            tk.Label(row, text=label, fg="#9bb0c2", bg=self.UI["panel"],
                     font=("Segoe UI", 8)).pack(side="left", padx=5)
            tk.Label(row, text=str(counts[key]), fg=self.UI["text"],
                     bg=self.UI["panel"], font=("Segoe UI", 8, "bold")).pack(side="right")

    def _refresh_dashboard_stats(self):
        if not hasattr(self, "tree"):
            return
        counts = {"low": 0, "review": 0, "high": 0}
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            state = str(values[3]).upper()
            if state in {"LOW RISK", "SAFE", "SCRIPT LOW RISK"}:
                counts["low"] += 1
            elif state in {"DANGER", "HIGH RISK", "MALICIOUS", "SCRIPT HIGH RISK"}:
                counts["high"] += 1
            else:
                counts["review"] += 1
        self._severity_totals = counts
        self._draw_severity_chart()

    def _show_dashboard(self):
        self.page_title.config(text="Dashboard")
        self._set_nav_active("Dashboard")

    def _set_nav_active(self, selected):
        for label, button in self.nav_buttons.items():
            active = label == selected
            button.configure(
                bg="#103b5b" if active else self.UI["sidebar"],
                fg="#ffffff" if active else "#b4c5d4"
            )

    def _toggle_monitoring(self):
        if self.monitoring:
            self._stop_monitoring()
            self._set_nav_active("Dashboard")
        else:
            self._start_monitoring()
            if self.monitoring:
                self._set_nav_active("File Monitor")
                self.page_title.config(text="File Monitor")

    def _show_settings(self):
        self._set_nav_active("Settings")
        self.page_title.config(text="Settings")
        U = self.UI
        win = tk.Toplevel(self)
        win.title("VIRO Settings")
        win.geometry("600x470")
        win.configure(bg=U["shell"])
        win.transient(self)
        tk.Label(win, text="Application Settings",
                 font=("Segoe UI", 16, "bold"), fg=U["text"],
                 bg=U["shell"]).pack(anchor="w", padx=22, pady=(20, 5))
        tk.Label(win, text="Configuration currently used by this VIRO installation.",
                 font=("Segoe UI", 9), fg=U["muted"],
                 bg=U["shell"]).pack(anchor="w", padx=22, pady=(0, 14))
        for label, value in [
            ("Downloads folder", str(DOWNLOADS_DIR)),
            ("Quarantine folder", str(QUARANTINE_DIR)),
            ("Model file", str(MODEL_PATH)),
            ("Maximum scan size", "No fixed limit (streaming reads)"),
            ("Model source", str(self.model.get("source", "unknown")).upper()),
            ("Watchdog library", "Installed" if WATCHDOG_OK else "Missing"),
            ("PE parser", "Installed" if PEFILE_OK else "Missing"),
        ]:
            card = tk.Frame(win, bg=U["panel"], padx=12, pady=8)
            card.pack(fill="x", padx=20, pady=3)
            tk.Label(card, text=label, font=("Segoe UI", 8, "bold"),
                     fg=U["muted"], bg=U["panel"]).pack(anchor="w")
            tk.Label(card, text=value, font=("Segoe UI", 8),
                     fg=U["text"], bg=U["panel"],
                     wraplength=520, justify="left").pack(anchor="w", pady=(2, 0))
        tk.Button(win, text="Close", command=win.destroy,
                  bg="#123b5e", fg="#ffffff", relief="flat",
                  padx=20, pady=7).pack(anchor="e", padx=20, pady=12)

    def _btn(self, parent, text, cmd):
        C = self.COLORS
        button = tk.Button(
            parent, text=text, command=cmd,
            bg=C["btn_bg"], fg=C["fg"],
            activebackground=C["accent"], activeforeground="#ffffff",
            relief="flat", bd=0, font=("Segoe UI", 9, "bold"),
            padx=12, pady=9, cursor="hand2",
            highlightthickness=1, highlightbackground=C["border"]
        )
        button.bind("<Enter>", lambda event: button.config(bg=C["btn_hover"]))
        button.bind("<Leave>", lambda event: button.config(bg=C["btn_bg"]))
        return button

    def _style_tree(self, cols):
        widths = [82, 250, 105, 100, 145]
        for col, width in zip(cols, widths):
            self.tree.heading(col, text=col.upper())
            self.tree.column(
                col, width=width, minwidth=65,
                anchor="w" if col == "File" else "center",
                stretch=(col == "File")
            )
        self.tree.tag_configure("safe", foreground=self.UI["green"])
        self.tree.tag_configure("warn", foreground=self.UI["orange"])
        self.tree.tag_configure("danger", foreground=self.UI["red"])

    def _start_monitoring(self):
        if self.monitoring: return
        if not WATCHDOG_OK:
            messagebox.showerror("Missing Library", "watchdog is not installed.\nRun: pip install watchdog")
            return
        DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
        handler = _DownloadHandler(self._on_new_file)
        self.observer = Observer()
        self.observer.schedule(handler, str(DOWNLOADS_DIR), recursive=False)
        self.observer.start()
        self.monitoring = True
        self._set_status("Monitoring " + str(DOWNLOADS_DIR), active=True)

    def _stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self.monitoring = False
        self._set_status("Idle — not monitoring", active=False)

    def _set_status(self, text, active=False):
        color = self.UI["green"] if active else self.UI["muted"]
        if hasattr(self, "top_status_dot"):
            self.top_status_dot.config(fg=color)
            self.top_status_text.config(
                text="MONITORING ACTIVE" if self.monitoring else "NOT MONITORING",
                fg=color
            )
        if hasattr(self, "progress_text"):
            self.progress_text.config(text=text)
        if hasattr(self, "engine_rows") and "Monitoring" in self.engine_rows:
            self.engine_rows["Monitoring"].config(
                text="ACTIVE" if self.monitoring else "OFF",
                fg=self.UI["green"] if self.monitoring else self.UI["muted"]
            )

    def _wait_until_stable(self, path):
        """Wait for a download to finish writing before scanning it."""
        previous, stable = None, 0
        for _ in range(30):
            try:
                current = path.stat().st_size
            except OSError:
                return False
            if current == previous and current > 0:
                stable += 1
                if stable >= FILE_STABLE_CHECKS:
                    return True
            else:
                stable = 0
            previous = current
            time.sleep(FILE_STABLE_INTERVAL)
        return False

    def _on_new_file(self, path):
        path = Path(path)
        def wait_worker():
            if self._wait_until_stable(path):
                self._scan_and_respond(path)
        threading.Thread(target=wait_worker, daemon=True).start()

    def _manual_scan(self):
        from tkinter.filedialog import askopenfilename
        fp = askopenfilename(title="Select a file to scan", initialdir=str(DOWNLOADS_DIR))
        if fp:
            self._scan_and_respond(Path(fp))

    def _scan_and_respond(self, path):
        """Run feature extraction/model inference in a worker thread."""
        path = Path(path)
        if not path.is_file():
            return
        key = str(path.resolve())
        with self._scan_lock:
            if key in self._active_scans:
                return
            self._active_scans.add(key)
        self.after(0, lambda: self._set_status(f"Scanning {path.name}...", active=True))
        def worker():
            try:
                result = compute_threat_details(path, self.model)
                self.after(0, lambda: self._handle_scan_result(path, result))
            except Exception as exc:
                error = str(exc)
                self.after(0, lambda: self._handle_scan_error(path, error))
            finally:
                with self._scan_lock:
                    self._active_scans.discard(key)
        threading.Thread(target=worker, daemon=True).start()

    def _handle_scan_error(self, path, error):
        self._log(time.strftime("%H:%M:%S"), path.name, 0, "NOT SCANNED", "Kept unchanged", "warn")
        self._set_status("Scan failed — file left unchanged.", active=False)
        messagebox.showwarning("VIRO could not scan this file", f"{path.name}\n\n{error}\n\nThe file was left unchanged.")

    def _handle_scan_result(self, path, result):
        score, votes, details = result
        ts = time.strftime("%H:%M:%S")
        analysis_type = (details or {}).get("analysis_type", "")

        if analysis_type == "unsupported":
            self._log(ts, path.name, 0, "NEEDS REVIEW", "Unsupported format — left unchanged", "warn")
            self._set_status("Unsupported file type — no safe verdict was made.", active=False)
            messagebox.showwarning(
                "VIRO — File not assessed",
                f"{path.name}\n\nVIRO does not currently analyse this file format. "
                "It has NOT been classified as safe and was left unchanged."
            )
            return

        if analysis_type == "script":
            if score < SAFE_THRESHOLD:
                status, tag = "SCRIPT LOW RISK", "safe"
                action = "Static script review — not executed"
                self._log(ts, path.name, score, status, action, tag)
                self._set_status(
                    f"Script scan complete ({score}/100). No configured suspicious pattern found; not a safety guarantee.",
                    active=False
                )
                return
            if score < WARN_THRESHOLD:
                self._log(ts, path.name, score, "SCRIPT WARNING", "Pending user decision", "warn")
                self._set_status("Script contains suspicious patterns — user review required.", active=False)
                self._show_threat_dialog(path, score, level="warning", votes=votes, details=details)
            else:
                self._log(ts, path.name, score, "SCRIPT HIGH RISK", "Pending user decision", "danger")
                self._set_status("Script contains high-risk pattern combinations — user review required.", active=False)
                self._show_threat_dialog(path, score, level="danger", votes=votes, details=details)
            return

        if score < SAFE_THRESHOLD:
            folder, destination = organize_safe_file(path)
            if folder:
                action = f"Organized → {folder}"
                self._notify("VIRO — Low-risk file organized", path.name)
            else:
                action = "Left in original location"
            self._log(ts, path.name, score, "LOW RISK", action, "safe")
            self._set_status(
                f"Low-risk assessment ({score}/100) — {action.lower()}.",
                active=False
            )
            return

        if score < WARN_THRESHOLD:
            self._log(ts, path.name, score, "WARNING", "Pending user decision", "warn")
            self._set_status("Suspicious indicators — user review required.", active=False)
            self._show_threat_dialog(path, score, level="warning", votes=votes, details=details)
        else:
            self._log(ts, path.name, score, "DANGER", "Pending user decision", "danger")
            self._set_status("High-risk indicators — user review required.", active=False)
            self._show_threat_dialog(path, score, level="danger", votes=votes, details=details)

    def _bulk_scan_downloads(self):
        if self._bulk_running:
            messagebox.showinfo("Busy", "A bulk scan is already running.")
            return
        DOWNLOADS_DIR.mkdir(parents=True, exist_ok=True)
        files = [f for f in DOWNLOADS_DIR.iterdir() if f.is_file()]
        if not files:
            messagebox.showinfo("No Files", "No files found in Downloads folder.")
            return
        if not messagebox.askyesno("Scan Downloaded Files", f"Found {len(files)} file(s) in:\n{DOWNLOADS_DIR}\n\nScan all now?"):
            return
        self._bulk_running = True
        self.progress_var.set(0)
        self._set_status(f"Scanning {len(files)} files...", active=True)
        def worker():
            total = len(files)
            for idx, path in enumerate(files, 1):
                try:
                    if not self._wait_until_stable(path):
                        raise RuntimeError("File did not become stable")
                    result = compute_threat_details(path, self.model)
                    self.after(0, lambda p=path, r=result: self._handle_scan_result(p, r))
                except Exception as exc:
                    err = str(exc)
                    self.after(0, lambda p=path, e=err: self._handle_scan_error(p, e))
                self.after(0, lambda v=idx / total * 100: self.progress_var.set(v))
                self.after(0, lambda i=idx, n=total: self.progress_text.config(
                    text=f"Scanning {i} of {n} files..."
                ))
            def done():
                self._bulk_running = False
                self.progress_var.set(100)
                self._set_status(f"Bulk scan complete — {total} files processed.", active=False)
                messagebox.showinfo("Scan Complete", f"Processed {total} files. Check the scan log.")
            self.after(0, done)
        threading.Thread(target=worker, daemon=True).start()

    def _deep_exe_dialog(self):
        from tkinter.filedialog import askopenfilename
        fp = askopenfilename(title="Select EXE / DLL for Deep Analysis", initialdir=str(DOWNLOADS_DIR),
                             filetypes=[("Executable files", "*.exe *.dll *.scr *.com *.msi"), ("All files", "*.*")])
        if not fp:
            return
        path = Path(fp)
        self._set_status(f"Deep-analysing {path.name}...", active=True)
        def worker():
            try:
                report = deep_exe_analysis(path)
                self.after(0, lambda: self._show_exe_report(path, report))
            except Exception as exc:
                error = str(exc)
                self.after(0, lambda: self._handle_scan_error(path, error))
        threading.Thread(target=worker, daemon=True).start()

    def _show_exe_report(self, path, r):
        C = self.COLORS
        self._set_status("Deep EXE analysis complete.", active=False)
        score = r["risk_score"]
        tag   = "safe" if score < SAFE_THRESHOLD else ("warn" if score < WARN_THRESHOLD else "danger")
        stxt  = "SAFE" if score < SAFE_THRESHOLD else ("WARNING" if score < WARN_THRESHOLD else "DANGER")
        self._log(time.strftime("%H:%M:%S"), path.name, score, stxt, "Deep analysis", tag)

        win = tk.Toplevel(self)
        win.title(f"Deep EXE Analysis -- {path.name}")
        win.geometry("700x580")
        win.configure(bg=C["bg"])
        score_color = C["safe"] if score < SAFE_THRESHOLD else (C["warn"] if score < WARN_THRESHOLD else C["danger"])
        hf = tk.Frame(win, bg=C["panel"], pady=10)
        hf.pack(fill="x")
        tk.Label(hf, text=f"Risk Score: {score}/100", font=("Consolas", 16, "bold"),
                 fg=score_color, bg=C["panel"]).pack(side="left", padx=16)
        tk.Label(hf, text=path.name, font=("Calibri", 11), fg=C["fg_dim"], bg=C["panel"]).pack(side="left")
        tk.Label(
            hf,
            text="Static evidence score — not a malware guarantee",
            font=("Calibri", 9),
            fg=C["fg_dim"],
            bg=C["panel"]
        ).pack(side="right", padx=12)

        txt_frame = tk.Frame(win, bg=C["bg"])
        txt_frame.pack(fill="both", expand=True, padx=12, pady=8)
        txt = tk.Text(txt_frame, bg=C["panel"], fg=C["fg"], font=("Consolas", 10),
                      wrap="word", relief="flat", padx=10, pady=8)
        vsb = tk.Scrollbar(txt_frame, command=txt.yview)
        txt.configure(yscrollcommand=vsb.set)
        txt.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        txt.tag_configure("heading", foreground=C["accent"],  font=("Consolas", 10, "bold"))
        txt.tag_configure("ok",      foreground=C["safe"])
        txt.tag_configure("warn",    foreground=C["warn"])
        txt.tag_configure("danger",  foreground=C["danger"])
        txt.tag_configure("dim",     foreground=C["fg_dim"])

        def w(line, tag=""):
            txt.insert("end", line + "\n", tag)

        w(f"File          : {path}", "dim")
        w(f"Architecture  : {r['machine']}", "dim")
        w(f"Compiled      : {r['compile_time']}", "dim")
        w(f"Digital sig   : {r['authenticode']}", "dim")
        if r.get("publisher"):
            w(f"Publisher     : {r['publisher']}", "dim")
        w("", "dim")
        w("-- PE Sections -------------------------------------", "heading")
        if r["sections"]:
            for s in r["sections"]:
                et = "danger" if s["entropy"] >= 7.2 else ("warn" if s["entropy"] >= 6.0 else "ok")
                perms = ("X" if s.get("executable") else "-") + ("W" if s.get("writable") else "-")
                w(
                    f"  {s['name']:<16} size={s['size']:>9,} "
                    f"entropy={s['entropy']:.2f} perms={perms}",
                    et
                )
        else:
            w("  (none parsed)", "dim")
        w("")
        w("-- Imported DLLs -----------------------------------", "heading")
        if r["imported_dlls"]:
            for d in r["imported_dlls"]:
                w(f"  {d}", "danger" if d in SUSPICIOUS_DLLS else "ok")
        else:
            w("  (none / parse failed)", "dim")
        w("")
        w("-- Suspicious API Strings --------------------------", "heading")
        if r["suspicious_apis"]:
            for a in r["suspicious_apis"]: w(f"  [!] {a}", "warn")
        else:
            w("  None detected", "ok")
        w("")
        w("-- Overlay / Appended Data -------------------------", "heading")
        if r["has_overlay"]:
            w(f"  [!] Overlay present  (entropy {r['overlay_entropy']:.2f})", "warn")
        else:
            w("  None", "ok")
        w("")
        w("-- Why VIRO Is Flagging This File -------------------", "heading")
        explanations = _build_explanations(r)
        for reason in explanations["why_flagged"]:
            w(f"  [!] {reason}", "warn")
        w("")
        w("-- Evidence That May Be Reassuring ------------------", "heading")
        for reason in explanations["why_may_be_legitimate"]:
            w(f"  [+] {reason}", "ok")
        w("")
        w("-- Risk Flags --------------------------------------", "heading")
        if r["risk_flags"]:
            for flag in r["risk_flags"]:
                w(f"  >> {flag}", "danger" if score >= WARN_THRESHOLD else "warn")
        else:
            w("  No significant risk flags detected.", "ok")
        w("")
        w("-- Verdict -----------------------------------------", "heading")
        vt = "ok" if score < SAFE_THRESHOLD else ("warn" if score < WARN_THRESHOLD else "danger")
        vl = (
            "LOW STATIC RISK" if score < SAFE_THRESHOLD else
            ("SUSPICIOUS -- review before running" if score < WARN_THRESHOLD
             else "HIGH STATIC RISK -- avoid execution until verified")
        )
        w(f"  {vl}  (score {score}/100)", vt)
        txt.config(state="disabled")

        bf = tk.Frame(win, bg=C["bg"], pady=8)
        bf.pack()
        if path.exists():
            self._btn(bf, "Quarantine", lambda: (quarantine_file(path),
                                                  self._update_last_action(path.name, "-> Quarantine"),
                                                  win.destroy())).pack(side="left", padx=6)
            self._btn(bf, "Delete", lambda: (os.remove(path) if path.exists() else None,
                                              self._update_last_action(path.name, "Deleted"),
                                              win.destroy())).pack(side="left", padx=6)
        self._btn(bf, "Close", win.destroy).pack(side="left", padx=6)

    def _show_threat_dialog(self, path, score, level="warning", votes=None, details=None):
        C     = self.COLORS
        color = C["warn"] if level == "warning" else C["danger"]
        label = "WARNING" if level == "warning" else "DANGER -- HIGH THREAT"
        dlg   = tk.Toplevel(self)
        dlg.title("VIRO Threat Alert")
        dlg.geometry("520x540" if details else ("460x350" if votes else "460x310"))
        dlg.configure(bg=C["bg"])
        dlg.grab_set()
        tk.Label(dlg, text=label, font=("Calibri", 14, "bold"), fg=color, bg=C["bg"]).pack(pady=(20, 6))
        tk.Label(dlg, text=path.name, font=("Consolas", 11), fg=C["fg"], bg=C["bg"], wraplength=420).pack(pady=4)
        tk.Label(
            dlg,
            text=f"Threat Score: {score}/100",
            font=("Calibri", 12, "bold"),
            fg=color,
            bg=C["bg"]
        ).pack(pady=4)
        if details:
            ml_text = (
                f"ML probability: {details['ml_probability']:.1f}%"
                if details.get("ml_probability") is not None else "ML probability: N/A"
            )
            static_text = (
                f"Static risk: {details['static_risk']:.1f}%"
                if details.get("static_risk") is not None else "Static risk: N/A"
            )
            tk.Label(
                dlg,
                text=(
                    f"{ml_text}  |  {static_text}\n"
                    f"Analysis: {details.get('analysis_type', 'file')}  |  "
                    f"Source: {details.get('source', 'unknown')}  |  "
                    f"Confidence: {details.get('confidence', 'unknown').upper()}"
                ),
                font=("Consolas", 9),
                fg=C["fg_dim"],
                bg=C["bg"],
                justify="center"
            ).pack(pady=2)
        if details:
            formula = details.get("score_formula", "")
            tk.Label(
                dlg, text=formula,
                font=("Consolas", 8), fg=C["fg_dim"], bg=C["bg"],
                wraplength=420, justify="center"
            ).pack(pady=(2, 4))
            evidence_box = tk.Frame(dlg, bg=C["panel"], padx=8, pady=6)
            evidence_box.pack(fill="x", padx=16, pady=4)
            tk.Label(
                evidence_box, text="WHY VIRO FLAGGED IT",
                font=("Calibri", 9, "bold"), fg=C["warn"], bg=C["panel"]
            ).pack(anchor="w")
            for reason in details.get("why_flagged", [])[:3]:
                tk.Label(
                    evidence_box, text="• " + reason,
                    font=("Calibri", 8), fg=C["fg"], bg=C["panel"],
                    wraplength=400, justify="left"
                ).pack(anchor="w")
            tk.Label(
                evidence_box, text="POSSIBLY REASSURING EVIDENCE",
                font=("Calibri", 9, "bold"), fg=C["safe"], bg=C["panel"]
            ).pack(anchor="w", pady=(5, 0))
            for reason in details.get("why_may_be_legitimate", [])[:2]:
                tk.Label(
                    evidence_box, text="• " + reason,
                    font=("Calibri", 8), fg=C["fg_dim"], bg=C["panel"],
                    wraplength=400, justify="left"
                ).pack(anchor="w")
        if votes:
            flagged = sorted(n for n, p in votes.items() if p >= 0.5)
            agree   = f"{len(flagged)}/{len(votes)} algorithms flag this file"
            if flagged:
                agree += f"\n({', '.join(flagged)})"
            tk.Label(dlg, text=agree, font=("Calibri", 10), fg=C["fg_dim"], bg=C["bg"],
                     wraplength=420, justify="center").pack(pady=2)
        tk.Label(dlg, text="What would you like to do?", font=("Calibri", 10), fg=C["fg_dim"], bg=C["bg"]).pack(pady=8)
        def _quarantine():
            try:
                quarantine_file(path)
                self._update_last_action(path.name, "-> Quarantine")
                self._notify("Quarantined", path.name)
                dlg.destroy()
            except Exception as exc:
                messagebox.showerror("Quarantine failed", str(exc), parent=dlg)
        def _delete():
            if not messagebox.askyesno("Confirm deletion", f"Permanently delete {path.name}?", parent=dlg):
                return
            try:
                os.remove(path)
                self._update_last_action(path.name, "Deleted")
                dlg.destroy()
            except OSError as exc:
                messagebox.showerror("Delete failed", str(exc), parent=dlg)
        def _deep():
            dlg.destroy()
            self._set_status(f"Deep-analysing {path.name}...", active=True)
            def worker():
                try:
                    report = deep_exe_analysis(path)
                    self.after(0, lambda: self._show_exe_report(path, report))
                except Exception as exc:
                    error = str(exc)
                    self.after(0, lambda: self._handle_scan_error(path, error))
            threading.Thread(target=worker, daemon=True).start()
        def _keep():
            self._update_last_action(path.name, "Kept by user")
            dlg.destroy()
        br = tk.Frame(dlg, bg=C["bg"])
        br.pack(pady=12)
        self._btn(br, "Quarantine", _quarantine).pack(side="left", padx=6)
        self._btn(br, "Delete",     _delete).pack(side="left", padx=6)
        if path.suffix.lower() in EXE_EXTENSIONS:
            self._btn(br, "Deep Scan", _deep).pack(side="left", padx=6)
        self._btn(br, "Keep", _keep).pack(side="left", padx=6)

    def _log(self, ts, name, score, status, action, tag):
        iid = self.tree.insert(
            "", 0,
            values=(ts, name, f"{score}/100", status, action),
            tags=(tag,)
        )
        self.log_rows.append((iid, name))
        self._refresh_dashboard_stats()

    def _update_last_action(self, name, action):
        for iid, n in reversed(self.log_rows):
            if n == name:
                vals = list(self.tree.item(iid, "values"))
                vals[4] = action
                self.tree.item(iid, values=vals)
                break

    def _open_quarantine(self):
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        path = str(QUARANTINE_DIR)
        if sys.platform == "win32": os.startfile(path)
        elif sys.platform == "darwin": os.system(f'open "{path}"')
        else: os.system(f'xdg-open "{path}"')

    def _notify(self, title, msg):
        if PLYER_OK:
            try: notification.notify(title=title, message=msg, app_name="VIRO", timeout=5)
            except: pass

    def _on_close(self):
        self._stop_monitoring()
        self.destroy()


class _DownloadHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
    def on_created(self, event):
        if not event.is_directory:
            self.callback(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self.callback(Path(event.dest_path))


def main():
    ap = argparse.ArgumentParser(description="VIRO — Virus Inspection & Response Organizer")
    ap.add_argument("--build-dataset", action="store_true",
                    help="extract features from --benign / --malware folders into model/training_data.csv")
    ap.add_argument("--benign",  help="folder of known-clean files (label 0)")
    ap.add_argument("--malware", help="folder of known-malicious samples (label 1) — use a VM")
    ap.add_argument("--train", action="store_true",
                    help="retrain the ensemble (uses model/training_data.csv if present) and print a report")
    args = ap.parse_args()

    if args.build_dataset:
        if not (args.benign and args.malware):
            ap.error("--build-dataset needs both --benign and --malware (a model needs both classes)")
        try:
            build_dataset(args.benign, args.malware)
        except Exception as exc:
            ap.error(str(exc))
        return
    if args.train:
        print_report(load_or_train_model(force_retrain=True))
        return
    ViroApp().mainloop()


if __name__ == "__main__":
    main()

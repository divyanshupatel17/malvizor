import os
import re
import math
import hashlib
import datetime
import zipfile
import tempfile
import shutil

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

import config


# ── PE lookup tables ───────────────────────────────────────────────────────────

_MACHINE_TYPES = {
    0x014c: "x86 (32-bit)",
    0x8664: "x86-64 (64-bit)",
    0xaa64: "ARM64",
    0x01c0: "ARM (32-bit)",
    0x01c4: "ARMv7 Thumb-2",
    0x0200: "IA-64 (Itanium)",
    0x0ebc: "EFI Byte Code",
}

_SUBSYSTEMS = {
    0:  "Unknown",       1:  "Native",
    2:  "Windows GUI",   3:  "Windows Console",
    5:  "OS/2 Console",  7:  "POSIX Console",
    9:  "Windows CE",   10:  "EFI Application",
    11: "EFI Boot Driver", 12: "EFI Runtime Driver",
    14: "Xbox",         16:  "Windows Boot",
}

_SUSPICIOUS_FUNCS = {
    # Process Injection
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "VirtualAllocEx", "VirtualProtectEx", "WriteProcessMemory",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "QueueUserAPC", "NtQueueApcThread",
    "ZwCreateThreadEx", "NtCreateThreadEx",
    "RtlCreateUserThread", "NtCreateSection",
    "SetThreadContext", "GetThreadContext",
    # Keylogging / Input
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    "GetForegroundWindow",
    # Network / Download — both bare and A/W suffix variants
    "InternetOpen", "InternetOpenA", "InternetOpenW",
    "InternetOpenUrl", "InternetOpenUrlA", "InternetOpenUrlW",
    "InternetReadFile", "InternetReadFileEx",
    "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
    "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
    "URLDownloadToCacheFile",
    "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    "WSAStartup", "WSASocket", "connect",
    "recv", "send", "bind", "listen",
    # Execution
    "WinExec",
    "ShellExecute", "ShellExecuteA", "ShellExecuteW",
    "ShellExecuteEx", "ShellExecuteExA", "ShellExecuteExW",
    "CreateProcess", "CreateProcessA", "CreateProcessW",
    "CreateProcessAsUser", "CreateProcessAsUserA", "CreateProcessAsUserW",
    "CreateProcessWithLogonW", "CreateProcessWithTokenW",
    # Persistence — registry
    "RegSetValue", "RegSetValueA", "RegSetValueW",
    "RegSetValueEx", "RegSetValueExA", "RegSetValueExW",
    "RegCreateKey", "RegCreateKeyA", "RegCreateKeyW",
    "RegCreateKeyEx", "RegCreateKeyExA", "RegCreateKeyExW",
    # Anti-analysis / evasion
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess", "ZwQueryInformationProcess",
    "OutputDebugString", "OutputDebugStringA", "OutputDebugStringW",
    "FindWindow", "FindWindowA", "FindWindowW",
    "GetTickCount", "timeGetTime",
    # Crypto (ransomware / packing)
    "CryptEncrypt", "CryptDecrypt",
    "CryptAcquireContext", "CryptAcquireContextA", "CryptAcquireContextW",
    "CryptCreateHash", "CryptDestroyHash",
    "CryptDestroyKey", "CryptImportKey", "CryptGenKey",
    # Token / privilege escalation
    "ImpersonateLoggedOnUser", "DuplicateToken", "DuplicateTokenEx",
    "AdjustTokenPrivileges", "SetThreadToken", "OpenProcessToken",
    "LookupPrivilegeValue", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    # Discovery
    "CreateToolhelp32Snapshot",
    "Process32First", "Process32FirstW",
    "Process32Next", "Process32NextW",
    "GetSystemInfo", "GetNativeSystemInfo",
    "GetComputerName", "GetComputerNameA", "GetComputerNameW",
    "GetUserName", "GetUserNameA", "GetUserNameW",
    "FindFirstFile", "FindFirstFileA", "FindFirstFileW",
    "FindNextFile", "FindNextFileA", "FindNextFileW",
}

_PE_EXTENSIONS = {".exe", ".dll", ".sys", ".drv", ".ocx", ".scr", ".cpl", ".efi"}

# ══════════════════════════════════════════════════════════════════════════════
#  FILE TYPES THAT ARE ALWAYS HIGH-ENTROPY BY DESIGN
#
#  These formats use compression or lossy encoding internally, so their byte
#  distributions always appear nearly-random (entropy 7.0–8.0).
#  Reporting entropy as "suspicious" for these types is a FALSE POSITIVE.
#
#  JPEG  — DCT + Huffman coding        → entropy always 7.5–8.0
#  PNG   — DEFLATE (zlib)              → entropy always 7.0–8.0
#  GIF   — LZW compression             → entropy always 7.0–8.0
#  PDF   — internal Flate/LZW streams  → typically 7.0–8.0
#  ZIP   — DEFLATE                     → entropy always ≈ 8.0
#  7z    — LZMA                        → entropy always ≈ 8.0
#  RAR   — proprietary compression     → entropy always ≈ 8.0
#
#  Entropy checks are ONLY meaningful for:
#    - PE executables (.exe, .dll, .sys …)
#    - ELF binaries
#    - Unknown/unrecognised files
#  where a spike above 7.5 genuinely signals packing or encryption.
# ══════════════════════════════════════════════════════════════════════════════
_NATURALLY_HIGH_ENTROPY_TYPES = frozenset({
    "jpeg_image",
    "png_image",
    "gif_image",
    "pdf",
    "zip_archive",
    "7zip_archive",
    "rar_archive",
})


# ══════════════════════════════════════════════════════════════════════════════
#  MITRE ATT&CK — DETECTION HELPERS + TECHNIQUE RULES
# ══════════════════════════════════════════════════════════════════════════════

def _get_imports(results):
    """Return all imported function names as a set from PE imports table."""
    pe = results.get("pe_info", {})
    if not pe.get("available"):
        return set()
    fns = set()
    for entry in pe.get("imports", []):
        for fn in entry.get("functions", []):
            fns.add(fn)
    return fns


def _import_any(results, apis, label):
    """
    True if ANY of the given API names appear in PE imports or extracted strings.
    Matches both exact names AND their A/W-suffixed variants automatically.
    """
    imp = _get_imports(results)

    def _variants(name):
        return {name, name + "A", name + "W", name + "Ex",
                name + "ExA", name + "ExW"}

    hits = []
    for a in apis:
        matched = _variants(a) & imp
        if matched:
            hits.append(sorted(matched)[0])
    if hits:
        return (True, f"{label}: {', '.join(hits[:4])}", "PE Import Table")

    extracted = results.get("strings", {}).get("extracted", [])
    combined  = " ".join(extracted)
    str_hits  = []
    for a in apis:
        for v in _variants(a):
            if v in combined:
                str_hits.append(v)
                break
    if str_hits:
        return (True, f"{label} (string): {', '.join(str_hits[:4])}", "String Analysis")
    return (False, "", "")


def _import_all(results, apis):
    """
    True only if ALL of the given API names appear together (combo detection).
    Each name also matches its A/W-suffixed variant.
    """
    imp = _get_imports(results)

    def _any_variant(name, source):
        for v in (name, name + "A", name + "W", name + "Ex",
                  name + "ExA", name + "ExW"):
            if v in source:
                return v
        return None

    hits = [_any_variant(a, imp) for a in apis]
    if all(hits):
        return (True, "Import combo: " + " + ".join(h for h in hits if h), "PE Import Table")

    extracted = results.get("strings", {}).get("extracted", [])
    combined  = " ".join(extracted)
    str_hits  = [_any_variant(a, combined) for a in apis]
    if all(str_hits):
        return (True, "String combo: " + " + ".join(h for h in str_hits if h), "String Analysis")
    return (False, "", "")


def _str_any(results, keywords, label, min_hits=1):
    """True if at least min_hits keywords appear in extracted strings."""
    extracted = results.get("strings", {}).get("extracted", [])
    kws_list  = results.get("strings", {}).get("interesting", {}).get("suspicious_keywords", [])
    combined  = " ".join(extracted + kws_list).lower()
    hits      = [k for k in keywords if k.lower() in combined]
    if len(hits) >= min_hits:
        return (True, f"{label}: {', '.join(hits[:4])}", "String Analysis")
    return (False, "", "")


def _yara_cat(results, categories, label):
    """True if any matched YARA rule belongs to one of the given categories."""
    yr = results.get("yara", {})
    if not yr.get("available"):
        return (False, "", "")
    for m in yr.get("matched", []):
        cat  = m.get("category", "").lower()
        rule = m.get("rule",     "").lower()
        for c in categories:
            if c.lower() in cat or c.lower() in rule:
                return (True, f"YARA: {m['rule']} [{m['category']}]", "YARA Detection")
    return (False, "", "")


def _masquerade_check(results):
    """Detect executable files pretending to have a non-executable extension."""
    ft   = results.get("file_type", "")
    name = results.get("file_name", "").lower()
    if ft in ("executable", "elf_linux_executable"):
        decoys = [".pdf", ".doc", ".docx", ".xls", ".xlsx",
                  ".jpg", ".png", ".zip", ".txt", ".mp4"]
        for ext in decoys:
            if name.endswith(ext):
                return (True, f"Executable disguised with {ext} extension", "File Type Analysis")
    return (False, "", "")


def _c2_web(results):
    """Detect HTTP/HTTPS C2 by combining API imports + URL strings."""
    api_t, api_e, api_s = _import_any(
        results,
        ["InternetOpen", "InternetOpenUrl", "WinHttpOpen",
         "URLDownloadToFile", "HttpSendRequest", "InternetReadFile"],
        "HTTP/HTTPS API imports")
    url_t, url_e, _ = _str_any(results, ["http://", "https://"], "URL strings", min_hits=1)
    if api_t and url_t:
        return (True, f"{api_e}; {url_e}", "PE Import + Strings")
    if api_t:
        return (True, api_e, api_s)
    if url_t:
        urls = results.get("strings", {}).get("interesting", {}).get("urls", [])
        if urls:
            return (True, f"URL detected: {urls[0][:60]}", "String Analysis")
    return (False, "", "")


def _build_mitre_rules():
    """
    Return the full list of MITRE ATT&CK detection rules.
    Each rule: (tid, sub, name, tactic, severity, description, check_fn)
    check_fn(results) → (triggered: bool, evidence: str, source: str)
    """
    rules = []

    def R(tid, sub, name, tactic, sev, desc, fn):
        rules.append((tid, sub, name, tactic, sev, desc, fn))

    # ── Defense Evasion ──────────────────────────────────────────────────────

    # ── FIX (BUG 3): _entropy_check now skips naturally-high-entropy file types.
    # Previously this fired for every JPEG/PNG/ZIP with entropy > 7.5, which is
    # always the case for compressed formats. Now it only triggers for file types
    # where high entropy is actually suspicious (executables, unknown files).
    def _entropy_check(r):
        # Skip file types whose high entropy is completely normal by design
        file_type = r.get("file_type", "unknown")
        if file_type in _NATURALLY_HIGH_ENTROPY_TYPES:
            return (False, "", "")

        level = r.get("entropy", {}).get("level", "")
        val   = r.get("entropy", {}).get("value", "?")
        if level == "very_high":
            return (True, f"Entropy {val} (very high — packed/encrypted)", "Entropy Analysis")
        if level == "high":
            return (True, f"Entropy {val} (high — possibly compressed)", "Entropy Analysis")
        return (False, "", "")

    R("T1027", "", "Obfuscated Files or Information", "Defense Evasion", "critical",
      "Very high file entropy indicates packing or encryption to hinder static analysis.",
      _entropy_check)

    R("T1055", "002", "PE Injection", "Defense Evasion", "critical",
      "VirtualAllocEx + WriteProcessMemory + NtUnmapViewOfSection — classic PE hollowing.",
      lambda r: _import_all(r, ["VirtualAllocEx", "WriteProcessMemory", "NtUnmapViewOfSection"]))

    R("T1055", "", "Process Injection", "Defense Evasion", "high",
      "VirtualAllocEx and WriteProcessMemory together indicate remote code injection.",
      lambda r: _import_all(r, ["VirtualAllocEx", "WriteProcessMemory"]))

    R("T1497", "001", "Virtualization/Sandbox Evasion", "Defense Evasion", "high",
      "Debugger-detection APIs detect analysis environments and halt malicious execution.",
      lambda r: _import_any(r, ["IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                                 "NtQueryInformationProcess"], "Anti-debug APIs"))

    R("T1036", "", "Masquerading", "Defense Evasion", "medium",
      "File extension or type mismatch — executable disguised as a different format.",
      lambda r: _masquerade_check(r))

    # ── Execution ─────────────────────────────────────────────────────────────

    R("T1059", "001", "PowerShell", "Execution", "high",
      "PowerShell execution strings detected — likely used for download cradle or remote execution.",
      lambda r: _str_any(r, ["powershell", "Invoke-Expression", "-enc",
                              "DownloadString", "IEX"], "PowerShell strings", min_hits=2))

    R("T1059", "003", "Windows Command Shell", "Execution", "medium",
      "cmd.exe invocation patterns found in extracted strings.",
      lambda r: _str_any(r, ["cmd.exe", "cmd /c", "cmd /k"], "cmd.exe strings", min_hits=1))

    R("T1106", "", "Native API", "Execution", "medium",
      "Direct NT native API usage — bypasses standard Win32 API monitoring hooks.",
      lambda r: _import_any(r, ["ZwCreateThreadEx", "NtCreateSection",
                                 "RtlCreateUserThread"], "Native NT API imports"))

    # ── Privilege Escalation ──────────────────────────────────────────────────

    R("T1134", "", "Access Token Manipulation", "Privilege Escalation", "high",
      "Token impersonation/duplication APIs detected — used to escalate privileges.",
      lambda r: _import_any(r, ["CreateProcessAsUser", "ImpersonateLoggedOnUser",
                                 "DuplicateToken", "SetThreadToken"],
                             "Token manipulation APIs"))

    R("T1055", "004", "Asynchronous Procedure Call", "Privilege Escalation", "high",
      "QueueUserAPC can inject code into threads of privileged processes.",
      lambda r: _import_any(r, ["QueueUserAPC"], "QueueUserAPC import"))

    # ── Persistence ───────────────────────────────────────────────────────────

    R("T1547", "001", "Registry Run Keys / Startup Folder", "Persistence", "high",
      "HKCU/HKLM Run key references found — common technique to survive reboots.",
      lambda r: _str_any(r, ["CurrentVersion\\Run", "CurrentVersion\\RunOnce",
                              "HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"],
                         "Registry Run key strings", min_hits=1))

    R("T1112", "", "Modify Registry", "Persistence", "medium",
      "Registry write APIs detected — may establish persistence or alter system settings.",
      lambda r: _import_any(r, ["RegSetValueEx", "RegCreateKeyEx",
                                 "RegSetValue", "RegCreateKey"], "Registry write APIs"))

    R("T1053", "005", "Scheduled Task/Job", "Persistence", "medium",
      "Task scheduler strings detected — may create scheduled tasks for persistence.",
      lambda r: _str_any(r, ["schtasks", "TaskScheduler", "ITaskScheduler",
                              "Schedule.Service"], "Task scheduler strings", min_hits=1))

    # ── Discovery ─────────────────────────────────────────────────────────────

    R("T1057", "", "Process Discovery", "Discovery", "medium",
      "Process enumeration APIs found — used to identify running security tools.",
      lambda r: _import_any(r, ["CreateToolhelp32Snapshot", "Process32First",
                                 "Process32Next", "EnumProcesses"],
                             "Process enumeration APIs"))

    R("T1082", "", "System Information Discovery", "Discovery", "low",
      "System information APIs detected — used to profile the victim machine.",
      lambda r: _import_any(r, ["GetSystemInfo", "GetVersionEx",
                                 "GetComputerName", "GetUserName"], "System info APIs"))

    R("T1083", "", "File and Directory Discovery", "Discovery", "low",
      "File system enumeration APIs found — may scan for target files to encrypt or exfiltrate.",
      lambda r: _import_any(r, ["FindFirstFile", "FindNextFile",
                                 "FindFirstFileEx"], "File discovery APIs"))

    # ── Command and Control ───────────────────────────────────────────────────

    R("T1071", "001", "Web Protocols (HTTP/S)", "Command and Control", "high",
      "HTTP/HTTPS APIs and URL strings detected — likely C2 beaconing or payload download.",
      lambda r: _c2_web(r))

    R("T1071", "004", "DNS", "Command and Control", "medium",
      "DNS resolution APIs detected — may use DNS tunneling for C2 channel.",
      lambda r: _import_any(r, ["DnsQuery", "DnsQueryA", "getaddrinfo",
                                 "gethostbyname"], "DNS API imports"))

    R("T1132", "", "Data Encoding", "Command and Control", "medium",
      "Base64 encoding patterns detected — likely used to obfuscate C2 traffic or payloads.",
      lambda r: _str_any(r, ["base64", "CryptBinaryToString", "decode("],
                         "Base64 / encoding strings", min_hits=1))

    R("T1095", "", "Non-Application Layer Protocol", "Command and Control", "medium",
      "Raw socket APIs detected — may use low-level TCP/UDP protocols for C2.",
      lambda r: _import_any(r, ["WSASocket", "bind", "listen", "recv", "send"],
                             "Raw socket APIs"))

    # ── Collection ────────────────────────────────────────────────────────────

    R("T1056", "001", "Keylogging", "Collection", "high",
      "Keyboard hook / key-state APIs detected — may be used to capture keystrokes.",
      lambda r: _import_any(r, ["SetWindowsHookEx", "GetAsyncKeyState",
                                 "GetKeyState", "GetKeyboardState"], "Keylogging APIs"))

    R("T1113", "", "Screen Capture", "Collection", "medium",
      "Screen capture APIs detected — may take screenshots for surveillance.",
      lambda r: _import_any(r, ["BitBlt", "GetDC", "CreateCompatibleBitmap",
                                 "PrintWindow"], "Screen capture APIs"))

    # ── Impact ────────────────────────────────────────────────────────────────

    R("T1486", "", "Data Encrypted for Impact", "Impact", "critical",
      "YARA signatures matched ransomware-specific string and encryption patterns.",
      lambda r: _yara_cat(r, ["ransomware", "wannacry", "ransom"],
                          "YARA ransomware signature"))

    R("T1490", "", "Inhibit System Recovery", "Impact", "high",
      "Shadow copy / backup deletion strings detected — typical ransomware anti-recovery.",
      lambda r: _str_any(r, ["vssadmin delete", "shadowcopy", "bcdedit /set", "wbadmin delete"],
                         "Shadow copy deletion strings", min_hits=1))

    R("T1486", "001", "Symmetric Cryptography", "Impact", "high",
      "Cryptographic API combination used for file encryption — consistent with ransomware.",
      lambda r: _import_any(r, ["CryptEncrypt", "CryptDecrypt", "CryptAcquireContext",
                                 "CryptGenKey", "CryptImportKey"], "Crypto APIs"))

    R("T1564", "001", "Hidden Files and Directories", "Defense Evasion", "medium",
      "'attrib +h' string found — malware hides files or itself from directory listings.",
      lambda r: _str_any(r, ["attrib +h", "attrib +s +h"], "File hiding command", min_hits=1))

    R("T1070", "004", "File Deletion", "Defense Evasion", "medium",
      "Self-deletion or file cleanup strings detected — malware removing traces.",
      lambda r: _str_any(r, ["cmd /c del ", "del /f /q", "DeleteFile", "remove itself"],
                         "File deletion strings", min_hits=1))

    return rules


class StaticAnalyzer:
    """Static analysis engine — analyzes a file WITHOUT executing it."""

    def __init__(self, file_path):
        self.file_path  = file_path
        self.file_name  = os.path.basename(file_path)
        self.file_size  = os.path.getsize(file_path)
        self.results    = {}
        self._file_type = None
        self._entropy   = None
        self._raw_data  = None

    def _read_file(self):
        if self._raw_data is None:
            with open(self.file_path, "rb") as f:
                self._raw_data = f.read()
        return self._raw_data

    def run(self):
        self._read_file()
        self._file_type = self._detect_file_type()
        self._entropy   = self._calculate_entropy()

        hashes  = self._compute_hashes()
        strings = self._extract_strings()

        self.results = {
            "file_name"             : self.file_name,
            "file_size"             : self.file_size,
            "file_size_human"       : self._human_readable_size(self.file_size),
            "file_type"             : self._file_type,
            "hashes"                : hashes,
            "strings"               : strings,
            "entropy"               : self._entropy,
            "pe_info"               : self._parse_pe_header(),
            "virustotal"            : self._check_virustotal(hashes["sha256"]),
            "yara"                  : self._run_yara_scan(),
            "suspicious_indicators" : self._check_suspicious_indicators(),
            "timestamp"             : datetime.datetime.now().isoformat(),
        }
        # MITRE ATT&CK mapping runs LAST — reads all other results above
        self.results["mitre_attack"] = self._map_mitre_attack()
        return self.results

    # ── 1. HASHES ─────────────────────────────────────────────────────────────

    def _compute_hashes(self):
        data = self._raw_data
        return {
            "md5"    : hashlib.md5(data).hexdigest(),
            "sha1"   : hashlib.sha1(data).hexdigest(),
            "sha256" : hashlib.sha256(data).hexdigest(),
        }

    # ── 2. STRINGS ────────────────────────────────────────────────────────────

    _BAD_WORDS = frozenset([
        # ── execution / shells ────────────────────────────────────────────────
        "cmd.exe", "cmd /c", "cmd /k", "cmd /r",
        "powershell", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "msiexec", "regsvr32", "rundll32",
        "wmic ", "certutil", "bitsadmin", "bash.exe",
        "exec(", "eval(", "system(", "os.system",
        "subprocess.popen", "subprocess.call",
        # ── download / C2 ────────────────────────────────────────────────────
        "download", "wget ", "curl ", "http://", "https://", "ftp://",
        "urldownloadtofile", "urldownloadtocachefile",
        "winhttp", "internetopen", "internetreadfile",
        "httpsendrequestex", "webClient",
        "invoke-webrequest", "downloadstring", "downloadfile",
        "net.webclient", ".onion",
        # ── persistence ──────────────────────────────────────────────────────
        "hkey_current_user", "hkey_local_machine", "hkcu\\", "hklm\\",
        "currentversion\\run", "currentversion\\runonce",
        "software\\microsoft\\windows\\currentversion",
        "schtasks", "taskscheduler", "ischeduledtask",
        "sc create", "sc start", "net start",
        "autorun.inf",
        # ── privilege escalation / tokens ────────────────────────────────────
        "sedebuggingprivilege", "setokenprivilege",
        "impersonateloggedonuser", "duplicatetoken",
        "createprocessasuser", "adjusttokenprivilege",
        "lookupprivilegevalue",
        # ── credential theft ─────────────────────────────────────────────────
        "password", "passwd", "credential", "credentials",
        "lsass.exe", "lsass", "mimikatz", "sekurlsa", "wdigest",
        "ntlmhash", "kerberoast", "sam database", "hashdump",
        "logonpasswords", "vaultcli", "dpapi",
        # ── process injection ────────────────────────────────────────────────
        "virtualallocex", "writeprocessmemory", "createremotethread",
        "ntunmapviewofsection", "queueuserapc", "zwcreatethreadex",
        "rtlcreateuserthread", "setthreadcontext",
        "process hollowing", "reflectivedll", "reflective dll",
        # ── anti-analysis / evasion ───────────────────────────────────────────
        "isdebuggerpresent", "checkremotedebuggerpresent",
        "ntqueryinformationprocess", "zwqueryinformationprocess",
        "virtualbox", "vbox", "vmware", "sandboxie", "wireshark",
        "processhacker", "x64dbg", "ollydbg", "immunity debugger",
        "suspendthread", "ntwaitforsingleobject",
        "obfuscat", "base64decode", "base64encode",
        "cryptencrypt", "cryptdecrypt",
        "cryptacquirecontext", "cryptgenkey",
        "rc4init", "rc4crypt",
        # ── ransomware / impact ───────────────────────────────────────────────
        "ransom", "your files have been", "your documents",
        "bitcoin", "btc wallet", "monero", "tor2web",
        "vssadmin delete", "shadowcopy", "bcdedit /set",
        "wbadmin delete", "deletebackup",
        "cryptowall", "wannacry", "wncrypt", ".wncry",
        "locky", "petya", "notpetya", "ryuk",
        "sodinokibi", "revil", "conti", "lockbit",
        "blackcat", "alphv", ".encrypted", ".locked",
        ".aes", "killedprocess", "iuqerfsodp",
        # ── exfiltration / collection ─────────────────────────────────────────
        "exfiltrat", "screenshot", "screencapture",
        "keylog", "keycap", "getclipboarddata",
        "recordmicrophone", "getforegroundwindow",
        "webcam", "dshow", "directshow",
        # ── malware family / framework strings ───────────────────────────────
        "backdoor", "rootkit", "botnet", "shellcode",
        "dropper", "loader", "stager", "beacon.x64",
        "cobalt strike", "cobaltstrike", "cs_beacon",
        "meterpreter", "metasploit", "msf/", "empire",
        "sliver c2", "brute ratel", "havoc c2",
        # ── suspicious paths / tools ──────────────────────────────────────────
        "\\temp\\", "%temp%\\", "%appdata%\\", "%localappdata%\\",
        "\\users\\public\\", "c:\\windows\\system32\\cmd",
        "/etc/passwd", "/etc/shadow", "/proc/self",
        "attrib +h", "attrib +s",
        "net user /add", "net localgroup administrators",
        "reg add hkcu", "reg add hklm",
        # ── network reconnaissance ─────────────────────────────────────────────
        "nmap ", "masscan", "portscan",
        "net view /all", "net accounts",
        "ipconfig /all", "arp -a",
    ])

    def _dynamic_string_limit(self) -> int:
        sz = self.file_size
        if sz < 100_000:    return 5_000
        if sz < 1_000_000:  return 15_000
        if sz < 5_000_000:  return 30_000
        if sz < 20_000_000: return 50_000
        return 80_000

    def _extract_strings(self, min_length=4):
        data  = self._raw_data
        limit = self._dynamic_string_limit()

        ascii_raw = re.findall(rb"[ -~]{" + str(min_length).encode() + rb",}", data)

        wide_raw = re.findall(
            rb"(?:[ -~]\x00){" + str(min_length).encode() + rb",}",
            data
        )
        wide_decoded = []
        for w in wide_raw:
            try:
                s = w.decode("utf-16-le", errors="ignore").strip()
                if s:
                    wide_decoded.append(s)
            except Exception:
                pass

        all_ascii = [s.decode("ascii", errors="ignore") for s in ascii_raw[:limit]]
        all_wide  = wide_decoded

        seen_str  = set()
        extracted = []
        for s in all_ascii + all_wide:
            if s and s not in seen_str:
                extracted.append(s)
                seen_str.add(s)

        interesting = self._find_interesting_strings(extracted)

        return {
            "total_count"  : len(ascii_raw) + len(wide_raw),
            "ascii_count"  : len(ascii_raw),
            "wide_count"   : len(wide_raw),
            "scanned_count": len(extracted),
            "extracted"    : extracted,
            "interesting"  : interesting,
        }

    _BENIGN_APIS = frozenset([
        "GetStartupInfoA", "GetStartupInfoW",
        "DecodePointer", "EncodePointer",
        "HeapDestroy", "HeapCreate", "HeapAlloc", "HeapFree", "HeapReAlloc",
        "HeapSize", "HeapValidate",
        "GetNativeSystemInfo", "GetSystemInfo",
        "FileDescription", "FileVersion", "ProductName", "ProductVersion",
        "LegalCopyright", "InternalName", "OriginalFilename",
        "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandle",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "FreeLibrary",
        "CloseHandle", "GetLastError", "SetLastError",
        "RtlUnwind", "UnhandledExceptionFilter", "SetUnhandledExceptionFilter",
        "GetCurrentProcess", "GetCurrentThread", "GetCurrentThreadId",
        "GetCurrentProcessId", "TerminateProcess",
        "EnterCriticalSection", "LeaveCriticalSection",
        "InitializeCriticalSection", "DeleteCriticalSection",
        "TlsAlloc", "TlsFree", "TlsGetValue", "TlsSetValue",
        "FlsAlloc", "FlsFree", "FlsGetValue", "FlsSetValue",
        "WideCharToMultiByte", "MultiByteToWideChar",
        "GetStringTypeW", "LCMapStringW",
        "IsValidCodePage", "GetACP", "GetOEMCP",
        "VirtualAlloc", "VirtualFree", "VirtualQuery",
        "Sleep",
    ])

    _BASE64_BLOB_RE = re.compile(r'^[A-Za-z0-9+/]{40,}={0,2}$')

    def _find_interesting_strings(self, strings):
        interesting = {
            "urls":                [],
            "ip_addresses":        [],
            "file_paths":          [],
            "registry_keys":       [],
            "suspicious_keywords": [],
            "emails":              [],
            "mutex_names":         [],
        }

        url_re   = re.compile(r"https?://[^\s\x00]{4,}", re.IGNORECASE)
        ip_re    = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        )
        path_re  = re.compile(
            r"[A-Za-z]:\\[^\s\x00\\]{2,}|"
            r"%(?:temp|appdata|systemroot|windir|userprofile|programfiles)[%\\]|"
            r"/(?:etc|tmp|var|proc|home|usr)/[^\s\x00]{2,}",
            re.IGNORECASE
        )
        reg_re   = re.compile(
            r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|"
            r"CURRENT_CONFIG|USERS|PERFORMANCE_DATA)|"
            r"\bHK(?:LM|CU|CR|CC)\\",
            re.IGNORECASE
        )
        email_re = re.compile(
            r"\b[A-Za-z0-9._%+\-]{3,}@[A-Za-z0-9.\-]{3,}\.[A-Za-z]{2,}\b"
        )
        mutex_re = re.compile(
            r"\b(?:Global\\|Local\\)?[A-Za-z0-9_\-]{6,}"
            r"(?:mutex|mtx|lock|semaphore)\b|"
            r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-"
            r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}",
            re.IGNORECASE
        )

        CAP = 50

        seen_url = set(); seen_ip = set(); seen_path = set()
        seen_reg = set(); seen_kw = set(); seen_email = set(); seen_mtx = set()

        for s in strings:
            sl        = s.lower()
            s_stripped = s.strip()
            is_benign  = s_stripped in self._BENIGN_APIS

            if len(interesting["urls"]) < CAP and url_re.search(s):
                key = s[:80]
                if key not in seen_url:
                    interesting["urls"].append(s[:200])
                    seen_url.add(key)

            if len(interesting["ip_addresses"]) < CAP:
                for m in ip_re.finditer(s):
                    ip = m.group(0)
                    if ip in ("127.0.0.1", "255.255.255.255", "0.0.0.0"):
                        continue
                    if ip not in seen_ip:
                        interesting["ip_addresses"].append(ip)
                        seen_ip.add(ip)
                        break

            if len(interesting["file_paths"]) < CAP and path_re.search(s):
                key = s[:80]
                if key not in seen_path:
                    interesting["file_paths"].append(s[:200])
                    seen_path.add(key)

            if len(interesting["registry_keys"]) < CAP and reg_re.search(s):
                key = s[:80]
                if key not in seen_reg:
                    interesting["registry_keys"].append(s[:200])
                    seen_reg.add(key)

            if len(interesting["emails"]) < CAP:
                m = email_re.search(s)
                if m and m.group(0) not in seen_email:
                    interesting["emails"].append(m.group(0))
                    seen_email.add(m.group(0))

            if len(interesting["mutex_names"]) < CAP:
                m = mutex_re.search(s)
                if m and m.group(0) not in seen_mtx:
                    interesting["mutex_names"].append(m.group(0))
                    seen_mtx.add(m.group(0))

            if not is_benign and len(interesting["suspicious_keywords"]) < CAP \
                    and s not in seen_kw:
                for word in self._BAD_WORDS:
                    if word in sl:
                        interesting["suspicious_keywords"].append(s[:200])
                        seen_kw.add(s)
                        break

            if len(s) < 6:
                continue
            if self._BASE64_BLOB_RE.match(s):
                continue
            if is_benign:
                continue

            rev    = s[::-1]
            rev_sl = rev.lower()

            if len(interesting["suspicious_keywords"]) < CAP and s not in seen_kw:
                for word in self._BAD_WORDS:
                    if word in rev_sl:
                        interesting["suspicious_keywords"].append(f"[reversed] {s[:120]}")
                        seen_kw.add(s)
                        break

            if len(interesting["urls"]) < CAP and url_re.search(rev):
                key = rev[:80]
                if key not in seen_url:
                    interesting["urls"].append(f"[reversed] {s[:200]}")
                    seen_url.add(key)

            if len(interesting["ip_addresses"]) < CAP and ip_re.search(rev):
                m2 = ip_re.search(rev)
                if m2 and m2.group(0) not in seen_ip:
                    interesting["ip_addresses"].append(f"[reversed] {m2.group(0)}")
                    seen_ip.add(m2.group(0))

            if len(interesting["registry_keys"]) < CAP and reg_re.search(rev):
                key = rev[:80]
                if key not in seen_reg:
                    interesting["registry_keys"].append(f"[reversed] {s[:200]}")
                    seen_reg.add(key)

        return interesting

    # ── 3. ENTROPY ────────────────────────────────────────────────────────────

    def _calculate_entropy(self):
        """
        Calculates Shannon entropy of the raw file bytes (accurate for all types).

        The entropy VALUE is always mathematically correct.
        The level and description are context-aware — compressed/encoded formats
        (JPEG, PNG, ZIP, PDF etc.) always produce high entropy by design, so
        their descriptions reflect that rather than falsely labelling them suspicious.
        """
        data = self._raw_data
        if not data:
            return {"value": 0.0, "level": "empty", "description": "File is empty"}

        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        entropy = 0.0
        length  = len(data)
        for c in counts:
            if c:
                p = c / length
                entropy -= p * math.log2(p)
        entropy = round(entropy, 4)

        # Human-readable labels for the compression format — used in description
        _FORMAT_LABELS = {
            "jpeg_image"  : "JPEG (DCT compression)",
            "png_image"   : "PNG (DEFLATE compression)",
            "gif_image"   : "GIF (LZW compression)",
            "pdf"         : "PDF (internal compression streams)",
            "zip_archive" : "ZIP (DEFLATE compression)",
            "7zip_archive": "7-Zip (LZMA compression)",
            "rar_archive" : "RAR (proprietary compression)",
        }

        ft = self._file_type or "unknown"

        if ft in _NATURALLY_HIGH_ENTROPY_TYPES:
            # Compressed/encoded format — high entropy is ALWAYS expected.
            # Report the accurate value with a neutral, informative description.
            fmt_label = _FORMAT_LABELS.get(ft, "compressed format")
            if entropy < 5.0:
                level = "normal"
                desc  = f"Normal entropy — {fmt_label}"
            elif entropy < 7.0:
                level = "moderate"
                desc  = f"Moderate entropy — {fmt_label}"
            else:
                # 7.0–8.0 is the expected range for all compressed formats
                level = "very_high"
                desc  = f"High entropy ({entropy}) — expected for {fmt_label}, not suspicious"
        else:
            # Executable, ELF, script, unknown binary — entropy IS meaningful here
            if entropy < 1.0:
                level, desc = "very_low",  "Very low entropy — sparse/simple file"
            elif entropy < 5.0:
                level, desc = "normal",    "Normal entropy — typical for text or code"
            elif entropy < 7.0:
                level, desc = "moderate",  "Moderate entropy — compiled code"
            elif entropy < 7.5:
                level, desc = "high",      "High entropy — possibly compressed or packed"
            else:
                level, desc = "very_high", "Very high entropy — likely encrypted/packed (SUSPICIOUS)"

        return {"value": entropy, "level": level, "description": desc}

    # ── 4. PE HEADER ──────────────────────────────────────────────────────────

    def _parse_pe_header(self):
        if not PEFILE_AVAILABLE:
            return {"available": False, "reason": "pefile not installed — run: pip install pefile"}
        file_type = self._file_type
        if file_type == "executable":
            return self._parse_pe_from_bytes(self._raw_data)
        if file_type in ("zip_archive", "7zip_archive"):
            return self._parse_pe_from_archive()
        return {
            "available": False,
            "reason": f"Not a PE/executable file — PE header analysis skipped "
                      f"(detected type: {file_type})"
        }

    def _parse_pe_from_bytes(self, data, source_name=None):
        if len(data) < 2 or data[:2] != b"MZ":
            return {"available": False, "reason": "Not a PE file (no MZ header)"}
        try:
            pe = pefile.PE(data=data, fast_load=False)
        except pefile.PEFormatError as e:
            return {"available": False, "reason": f"Invalid PE format: {e}"}
        except Exception as e:
            return {"available": False, "reason": f"PE parse error ({type(e).__name__}): {e}"}
        try:
            result = self._extract_pe_info(pe, source_name=source_name)
        except Exception as e:
            result = {"available": False, "reason": f"PE extraction failed: {e}"}
        finally:
            try:
                pe.close()
            except Exception:
                pass
        return result

    def _parse_pe_from_archive(self):
        tmp_dir = None
        try:
            tmp_dir = tempfile.mkdtemp(prefix="mba_extract_")
            try:
                with zipfile.ZipFile(self.file_path, "r") as zf:
                    safe_members = [
                        m for m in zf.infolist()
                        if not m.filename.startswith(("/", "..")) and ".." not in m.filename
                    ]
                    total_files = len(safe_members)
                    for member in safe_members:
                        if member.file_size <= 10 * 1024 * 1024:
                            try:
                                zf.extract(member, tmp_dir)
                            except Exception:
                                continue
            except zipfile.BadZipFile:
                return {"available": False, "reason": "Not a valid ZIP file"}
            except Exception as e:
                return {"available": False, "reason": f"ZIP extraction error: {e}"}

            pe_candidates = []
            for root, dirs, files in os.walk(tmp_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    ext   = os.path.splitext(fname)[1].lower()
                    try:
                        if ext in _PE_EXTENSIONS:
                            pe_candidates.append((fpath, fname))
                            continue
                        with open(fpath, "rb") as f:
                            magic = f.read(2)
                        if magic == b"MZ":
                            pe_candidates.append((fpath, fname))
                    except Exception:
                        continue

            if not pe_candidates:
                return {
                    "available": False,
                    "reason": f"ZIP contains {total_files} file(s) but no PE executables found"
                }

            def pe_priority(item):
                _, fname = item
                ext = os.path.splitext(fname)[1].lower()
                order = {".exe": 0, ".dll": 1, ".sys": 2, ".drv": 3}
                return (order.get(ext, 9), -os.path.getsize(item[0]))

            pe_candidates.sort(key=pe_priority)
            all_suspicious_imports = []
            primary_result = None
            parsed_names   = []

            for fpath, fname in pe_candidates[:5]:
                try:
                    with open(fpath, "rb") as f:
                        pe_bytes = f.read()
                except Exception:
                    continue
                result = self._parse_pe_from_bytes(pe_bytes, source_name=fname)
                if result.get("available"):
                    parsed_names.append(fname)
                    for imp in result.get("suspicious_imports", []):
                        if imp not in all_suspicious_imports:
                            all_suspicious_imports.append(imp)
                    if primary_result is None:
                        primary_result = result

            if primary_result is None:
                return {"available": False, "reason": "All PE files in ZIP failed to parse"}

            primary_result["suspicious_imports"] = all_suspicious_imports
            primary_result["archive_info"] = {
                "source"             : "extracted_from_zip",
                "total_files_in_zip" : total_files,
                "executables_found"  : len(pe_candidates),
                "analyzed_files"     : parsed_names,
                "primary_file"       : parsed_names[0] if parsed_names else "unknown",
            }
            return primary_result
        finally:
            if tmp_dir and os.path.exists(tmp_dir):
                try:
                    shutil.rmtree(tmp_dir)
                except Exception:
                    pass

    def _extract_pe_info(self, pe, source_name=None):
        machine_raw  = getattr(pe.FILE_HEADER, "Machine", 0)
        machine_str  = _MACHINE_TYPES.get(machine_raw, f"Unknown ({hex(machine_raw)})")
        ts_raw = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
        if ts_raw and ts_raw > 0:
            try:
                compile_time = str(datetime.datetime.utcfromtimestamp(ts_raw))
            except (OSError, OverflowError, ValueError):
                compile_time = "Invalid timestamp"
        else:
            compile_time = "Not set"
        opt           = getattr(pe, "OPTIONAL_HEADER", None)
        entry_point   = hex(opt.AddressOfEntryPoint) if opt else "N/A"
        subsystem_raw = getattr(opt, "Subsystem", 0) if opt else 0
        subsystem_str = _SUBSYSTEMS.get(subsystem_raw, f"Unknown ({subsystem_raw})")
        pe_info = {
            "available": True, "machine_type": machine_str,
            "compile_time": compile_time, "entry_point": entry_point,
            "subsystem": subsystem_str, "sections": [], "imports": [],
            "suspicious_imports": [],
        }
        if source_name:
            pe_info["source_file"] = source_name
        for section in getattr(pe, "sections", []):
            try:
                name = section.Name.decode("utf-8", errors="replace").strip("\x00").strip()
                pe_info["sections"].append({
                    "name": name or "[unnamed]",
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size":     section.SizeOfRawData,
                    "entropy":      round(section.get_entropy(), 4),
                })
            except Exception:
                continue
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            try:
                dll = (entry.dll or b"").decode("utf-8", errors="ignore")
                fns = []
                for imp in entry.imports:
                    if imp.name:
                        fn = imp.name.decode("utf-8", errors="ignore")
                        fns.append(fn)
                        if fn in _SUSPICIOUS_FUNCS:
                            pe_info["suspicious_imports"].append({"dll": dll, "function": fn})
                pe_info["imports"].append({"dll": dll, "functions": fns[:20]})
            except Exception:
                continue
        return pe_info

    # ── 5. VIRUSTOTAL ─────────────────────────────────────────────────────────

    def _check_virustotal(self, sha256):
        if not config.VIRUSTOTAL_API_KEY:
            return {"available": False, "reason": "no_key"}
        if not REQUESTS_AVAILABLE:
            return {"available": False, "reason": "requests library not installed"}
        if not sha256:
            return {"available": False, "reason": "no_hash"}
        try:
            url     = f"https://www.virustotal.com/api/v3/files/{sha256}"
            headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}
            resp    = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 404:
                return {"available": True, "found": False, "message": "Hash not found in VirusTotal"}
            if resp.status_code != 200:
                return {"available": False, "reason": f"VT API returned HTTP {resp.status_code}"}
            data   = resp.json()
            attrs  = data["data"]["attributes"]
            stats  = attrs.get("last_analysis_stats", {})
            malicious  = stats.get("malicious",  0)
            suspicious = stats.get("suspicious", 0)
            undetected = stats.get("undetected", 0)
            harmless   = stats.get("harmless",   0)
            total      = malicious + suspicious + undetected + harmless
            raw_results = attrs.get("last_analysis_results", {})
            engines = []
            for engine_name, detail in raw_results.items():
                category = detail.get("category", "undetected")
                result   = detail.get("result") or "Clean"
                engines.append({"name": engine_name, "category": category, "result": result})
            engines.sort(key=lambda e: (
                0 if e["category"] == "malicious"  else
                1 if e["category"] == "suspicious" else 2
            ))
            return {
                "available": True, "found": True,
                "malicious": malicious, "suspicious": suspicious,
                "undetected": undetected, "total_engines": total,
                "detection_ratio": f"{malicious}/{total}",
                "engines": engines[:12],
                "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
        except requests.exceptions.Timeout:
            return {"available": False, "reason": "VT request timed out"}
        except Exception as e:
            return {"available": False, "reason": str(e)}

    # ── 6. YARA SCAN ──────────────────────────────────────────────────────────

    def _run_yara_scan(self):
        if not YARA_AVAILABLE:
            return {"available": False, "reason": "yara-python not installed"}
        rules_path = config.YARA_RULES_PATH
        if not os.path.exists(rules_path):
            return {"available": False, "reason": f"Rules file not found at: {rules_path}"}
        try:
            rules = yara.compile(filepath=rules_path)
        except yara.SyntaxError as e:
            return {"available": False, "reason": f"YARA syntax error: {e}"}
        try:
            matches = rules.match(self.file_path, timeout=30)
        except yara.TimeoutError:
            return {"available": False, "reason": "YARA scan timed out"}
        except Exception as e:
            return {"available": False, "reason": f"YARA scan error: {e}"}
        matched_rules = []
        for match in matches:
            meta = match.meta if hasattr(match, "meta") else {}
            matched_rules.append({
                "rule":        match.rule,
                "description": meta.get("description", match.rule),
                "severity":    meta.get("severity",    "medium"),
                "category":    meta.get("category",    "Unknown"),
                "tags":        list(match.tags) if match.tags else [],
            })
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        highest   = "none"
        for m in matched_rules:
            s = m["severity"].lower()
            if sev_order.get(s, 0) > sev_order.get(highest, 0):
                highest = s
        return {
            "available":        True,
            "matched":          matched_rules,
            "total_matches":    len(matched_rules),
            "highest_severity": highest,
        }

    # ── 7. SUSPICIOUS INDICATORS ──────────────────────────────────────────────

    def _check_suspicious_indicators(self):
        """
        Build the list of human-readable threat indicators shown in the report.

        ── FIX (BUG 1): Entropy indicators now check file_type first.
        Previously this method added a CRITICAL entropy indicator for EVERY
        file with very_high entropy, including JPEG, PNG, GIF, PDF, ZIP etc.
        That caused false positives on every compressed image or archive.

        Now: entropy is only flagged as suspicious for file types where high
        entropy is genuinely meaningful — executables and unknown binaries.
        Compressed/encoded formats are skipped entirely.
        """
        indicators = []
        entropy   = self._entropy   or self._calculate_entropy()
        file_type = self._file_type or self._detect_file_type()

        # ── Entropy — only flag for file types where it is actually suspicious ──
        # Skip formats that ALWAYS have high entropy by design (JPEG, PNG, ZIP, PDF…)
        if file_type not in _NATURALLY_HIGH_ENTROPY_TYPES:
            if entropy["level"] == "very_high":
                indicators.append({
                    "severity":  "critical",
                    "indicator": "Very high entropy",
                    "detail":    f"Entropy {entropy['value']} — file is likely encrypted or packed",
                })
            elif entropy["level"] == "high":
                indicators.append({
                    "severity":  "high",
                    "indicator": "High entropy",
                    "detail":    f"Entropy {entropy['value']} — file may be compressed or packed",
                })

        # ── File type ─────────────────────────────────────────────────────────
        if file_type in ("executable", "elf_linux_executable"):
            indicators.append({
                "severity":  "medium",
                "indicator": "Executable file",
                "detail":    f"Detected type: {file_type}",
            })
            if self.file_size < 10_000:
                indicators.append({
                    "severity":  "high",
                    "indicator": "Very small executable",
                    "detail":    f"Only {self.file_size} bytes — possible dropper or shellcode",
                })

        # ── PE-specific checks ────────────────────────────────────────────────
        if PEFILE_AVAILABLE and file_type == "executable":
            try:
                import pefile as _pefile
                pe = _pefile.PE(data=self._raw_data, fast_load=False)

                for section in getattr(pe, "sections", []):
                    try:
                        sec_ent  = round(section.get_entropy(), 2)
                        sec_name = section.Name.decode("utf-8", errors="replace").strip("\x00").strip()
                        if sec_ent > 7.0:
                            indicators.append({
                                "severity":  "high",
                                "indicator": f"High-entropy PE section: {sec_name or '[unnamed]'}",
                                "detail":    f"Section entropy {sec_ent} — packed or encrypted code region",
                            })
                    except Exception:
                        continue

                _BAD_SECTIONS = {".upx0", ".upx1", ".aspack", ".adata",
                                 ".nsp0", ".nsp1", ".nsp2", "upack",
                                 ".themida", ".winlicence"}
                for section in getattr(pe, "sections", []):
                    try:
                        sec_name = section.Name.decode("utf-8", errors="replace")\
                                       .strip("\x00").strip().lower()
                        if sec_name in _BAD_SECTIONS:
                            indicators.append({
                                "severity":  "high",
                                "indicator": f"Known packer section: {sec_name}",
                                "detail":    f"Section name '{sec_name}' is associated with packers/protectors",
                            })
                    except Exception:
                        continue

                if not getattr(pe, "DIRECTORY_ENTRY_IMPORT", None):
                    indicators.append({
                        "severity":  "high",
                        "indicator": "No PE imports",
                        "detail":    "Executable has no import table — typical of shellcode, loaders, or packed malware",
                    })

                pe.close()
            except Exception:
                pass

        return indicators

    # ── 8. MITRE ATT&CK MAPPING ───────────────────────────────────────────────

    def _map_mitre_attack(self):
        """Map all collected results to MITRE ATT&CK Enterprise techniques."""
        try:
            rules    = _build_mitre_rules()
            seen     = {}
            matched  = []
            sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}

            for tid, sub, name, tactic, sev, desc, check_fn in rules:
                try:
                    triggered, evidence, source = check_fn(self.results)
                except Exception:
                    continue
                if not triggered:
                    continue

                full_id = f"{tid}.{sub}" if sub else tid

                if full_id in seen:
                    if sev_rank.get(sev, 0) <= sev_rank.get(seen[full_id], 0):
                        continue
                    matched = [m for m in matched if m["technique_id"] != full_id]

                seen[full_id] = sev
                matched.append({
                    "technique_id": full_id,
                    "base_id":      tid,
                    "sub_id":       sub,
                    "name":         name,
                    "tactic":       tactic,
                    "severity":     sev,
                    "description":  desc,
                    "evidence":     evidence,
                    "source":       source,
                    "url": (
                        f"https://attack.mitre.org/techniques/{tid}/{sub}/"
                        if sub else
                        f"https://attack.mitre.org/techniques/{tid}/"
                    ),
                })

            matched.sort(key=lambda m: (-sev_rank.get(m["severity"], 0), m["tactic"]))

            sev_counts    = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            tactic_counts = {}
            for m in matched:
                s = m["severity"]
                if s in sev_counts:
                    sev_counts[s] += 1
                tactic_counts[m["tactic"]] = tactic_counts.get(m["tactic"], 0) + 1

            tactics_map = {}
            for m in matched:
                t    = m["tactic"]
                sev  = m["severity"]
                conf = "high" if sev in ("critical", "high") else ("medium" if sev == "medium" else "low")
                tactics_map.setdefault(t, []).append({
                    "id":         m["technique_id"],
                    "name":       m["name"],
                    "url":        m["url"],
                    "evidence":   m["evidence"],
                    "confidence": conf,
                    "severity":   sev,
                })

            return {
                "available":      True,
                "techniques":     matched,
                "total":          len(matched),
                "tactic_count":   len(tactics_map),
                "high_count":     sev_counts["critical"] + sev_counts["high"],
                "medium_count":   sev_counts["medium"],
                "low_count":      sev_counts["low"],
                "critical_count": sev_counts["critical"],
                "sev_counts":     sev_counts,
                "tactic_counts":  tactic_counts,
                "tactics_map":    tactics_map,
                "version":        "ATT&CK v15 · Enterprise",
            }

        except Exception as e:
            return {"available": False, "reason": str(e)}

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _detect_file_type(self):
        data = self._raw_data or b""
        h    = data[:16]
        if h[:2]  == b"MZ":                 return "executable"
        if h[:2]  == b"PK":                 return "zip_archive"
        if h[:4]  == b"%PDF":               return "pdf"
        if h[:3]  == b"GIF":                return "gif_image"
        if h[:8]  == b"\x89PNG\r\n\x1a\n":  return "png_image"
        if h[:2]  == b"\xff\xd8":           return "jpeg_image"
        if h[:4]  == b"\x7fELF":            return "elf_linux_executable"
        if h[:6]  == b"7z\xbc\xaf'\x1c":   return "7zip_archive"
        if h[:7]  == b"Rar!\x1a\x07\x00":  return "rar_archive"
        return "unknown"

    def _human_readable_size(self, size):
        if size == 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB"]
        i, s  = 0, float(size)
        while s >= 1024 and i < len(units) - 1:
            s /= 1024
            i += 1
        return f"{s:.1f} {units[i]}"

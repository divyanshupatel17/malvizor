import os
import json
import datetime

import config


# ── IST Timezone — UTC+5:30 ───────────────────────────────────────────────────
_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))


# ── File types that are ALWAYS high-entropy by design ─────────────────────────
# JPEG/PNG/GIF use compression. PDF uses internal flate streams.
# ZIP/7Z/RAR are compressed archives. All produce entropy 7.0–8.0 naturally.
# Flagging these as "packed/suspicious" is always a false positive.
# Entropy scoring is only meaningful for: executable, elf_linux_executable, unknown
_NATURALLY_HIGH_ENTROPY_TYPES = frozenset({
    "jpeg_image",    # DCT + Huffman  → always 7.5–8.0
    "png_image",     # DEFLATE        → always 7.0–8.0
    "gif_image",     # LZW            → always 7.0–8.0
    "pdf",           # flate streams  → typically 7.0–8.0
    "zip_archive",   # DEFLATE        → always ≈ 8.0
    "7zip_archive",  # LZMA           → always ≈ 8.0
    "rar_archive",   # proprietary    → always ≈ 8.0
})


class ReportGenerator:
    """
    Scores static analysis results and generates the final report.
    Includes: entropy, file type, PE imports, strings,
              VirusTotal, YARA, and Cyclomatic Complexity scoring.
    All timestamps are in IST (UTC+5:30).
    """

    def __init__(self, static_results):
        self.static       = static_results or {}
        self.threat_score = 0
        self.indicators   = []

    def generate(self):
        self.threat_score = 0
        self.indicators   = []

        self._score_entropy()
        self._score_file_type()
        self._score_pe_imports()
        self._score_strings()
        self._score_virustotal()
        self._score_yara()
        self._score_cyclomatic_complexity()

        self.threat_score = min(self.threat_score, 100)
        classification    = self._classify()

        # ── Timestamp in IST (UTC+5:30) ───────────────────────────────────────
        # Changed from datetime.datetime.now() [system/UTC]
        # to datetime.datetime.now(_IST) [India Standard Time]
        ts = datetime.datetime.now(_IST).strftime("%Y-%m-%dT%H:%M:%S")

        report = {
            "summary": {
                "file_name"      : self.static.get("file_name",  "unknown"),
                "file_size"      : self.static.get("file_size_human", "unknown"),
                "file_type"      : self.static.get("file_type",  None),
                "sha256"         : self.static.get("hashes", {}).get("sha256", ""),
                "threat_score"   : self.threat_score,
                "classification" : classification,
                "timestamp"      : ts,
            },
            "threat_score"   : self.threat_score,
            "classification" : classification,
            "indicators"     : self.indicators,
            "static_analysis": self.static,
        }

        report["report_path"] = self._save_report(report)
        return report

    # ── SCORING ────────────────────────────────────────────────────────────────

    def _score_entropy(self):
        """
        Score file entropy ONLY for file types where high entropy is suspicious.

        Compressed/encoded formats (JPEG, PNG, ZIP, PDF etc.) always have
        high entropy by design — scoring them produces false positives on
        every image and archive scanned.

        Entropy scoring is only meaningful for executables and unknown binaries,
        where a spike above 7.5 genuinely indicates packing or encryption.
        """
        file_type = self.static.get("file_type", "unknown")
        if file_type in _NATURALLY_HIGH_ENTROPY_TYPES:
            return  # skip — high entropy is normal for this format

        e     = self.static.get("entropy", {})
        level = e.get("level", "normal")
        value = e.get("value", 0)

        if level == "very_high":
            self._add(20, "critical", f"Very high entropy ({value}) — packed/encrypted file")
        elif level == "high":
            self._add(10, "high",     f"High entropy ({value}) — possibly packed")

    def _score_file_type(self):
        ft = self.static.get("file_type", "")
        if ft in ["executable", "elf_linux_executable"]:
            self._add(10, "medium", f"Executable file detected ({ft})")

    def _score_pe_imports(self):
        pe   = self.static.get("pe_info", {})
        imps = pe.get("suspicious_imports", [])
        for imp in imps[:5]:
            self._add(5, "high",
                      f"Suspicious API: {imp.get('function')} from {imp.get('dll')}")

    def _score_strings(self):
        interesting = self.static.get("strings", {}).get("interesting", {})
        urls = interesting.get("urls", [])
        if urls:
            self._add(20, "high", f"{len(urls)} URL(s) found")
        reg = interesting.get("registry_keys", [])
        if reg:
            self._add(5, "medium", f"{len(reg)} registry key reference(s)")
        kws = interesting.get("suspicious_keywords", [])
        if len(kws) > 3:
            self._add(15, "high",   f"{len(kws)} suspicious keywords found")
        elif kws:
            self._add(10, "medium", f"{len(kws)} suspicious keyword(s)")

    def _score_virustotal(self):
        vt = self.static.get("virustotal", {})
        if not vt.get("available") or not vt.get("found"):
            return
        malicious = vt.get("malicious", 0)
        total     = vt.get("total_engines", 0)
        if total == 0 or malicious == 0:
            return
        ratio = malicious / total
        if ratio > 0.5:
            self._add(25, "critical", f"VirusTotal: {malicious}/{total} engines flagged as malicious")
        elif ratio > 0.2:
            self._add(20, "high",     f"VirusTotal: {malicious}/{total} engines flagged as malicious")
        else:
            self._add(10, "medium",   f"VirusTotal: {malicious}/{total} engines flagged as malicious")

    def _score_yara(self):
        """
        Score YARA matches. Points per severity:
          critical → 20, high → 15, medium → 10, low → 5
        Total YARA contribution capped at 30 to keep scoring balanced.
        (Without cap: 3 critical matches = 60 pts, pushing other signals off the scale.)
        """
        yara_result = self.static.get("yara", {})
        if not yara_result.get("available"):
            return
        matched = yara_result.get("matched", [])
        if not matched:
            return

        severity_points = {"critical": 20, "high": 15, "medium": 10, "low": 5}
        yara_total = 0
        YARA_CAP   = 30  # max points YARA can contribute to the threat score

        for match in matched:
            if yara_total >= YARA_CAP:
                break
            severity = match.get("severity", "medium").lower()
            points   = min(severity_points.get(severity, 10), YARA_CAP - yara_total)
            category = match.get("category", "Unknown")
            rule     = match.get("rule", "Unknown")
            self._add(points, severity,
                      f"YARA match: {category} — {match.get('description', rule)}")
            yara_total += points

    def _score_cyclomatic_complexity(self):
        """
        Score Cyclomatic Complexity — high CC in a binary suggests obfuscation.

          CC ≤ 300  (binary) / ≤ 10  (source) → no points, normal
          CC ≤ 800  (binary) / ≤ 25  (source) → +5  medium
          CC ≤ 2000 (binary) / ≤ 75  (source) → +10 high
          CC > 2000 (binary) / > 75  (source) → +15 critical
        """
        cc = self.static.get("cyclomatic_complexity", {})
        if not cc.get("available"):
            return

        value     = cc.get("value", 1)
        level     = cc.get("level", "low")
        is_binary = cc.get("method", "") == "binary_opcodes"

        if level == "low":
            return  # normal complexity — no indicator

        if level == "moderate":
            self._add(5,  "medium",   f"Cyclomatic complexity {value} — moderately complex code structure")
        elif level == "high":
            self._add(10, "high",     f"Cyclomatic complexity {value} — high complexity, possible obfuscation")
        elif level == "very_high":
            self._add(15, "critical", f"Cyclomatic complexity {value} — extreme complexity, strong obfuscation indicator")

    # ── HELPERS ────────────────────────────────────────────────────────────────

    def _add(self, points, severity, description):
        self.threat_score += points
        self.indicators.append({
            "points"      : points,
            "severity"    : severity,
            "description" : description,
        })

    def _classify(self):
        if self.threat_score <= 20:   return "BENIGN"
        elif self.threat_score <= 50: return "SUSPICIOUS"
        else:                         return "MALICIOUS"

    def _save_report(self, report):
        os.makedirs(config.REPORTS_FOLDER, exist_ok=True)
        # Use IST time for the report filename too
        ts        = datetime.datetime.now(_IST).strftime("%Y%m%d_%H%M%S")
        file_name = self.static.get("file_name", "unknown")
        safe      = "".join(c if c.isalnum() or c in "._-" else "_" for c in file_name)
        path      = os.path.join(config.REPORTS_FOLDER, f"report_{safe}_{ts}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        return path

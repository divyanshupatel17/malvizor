# 🛡️ MalVizar — Static Threat Analysis Tool

> A self-hosted, browser-based malware static analysis engine built with Python & Flask.
> Analyze suspicious files **without executing them** — designed for security researchers,
> CTF players, and students on Kali Linux.

---

## ✅ Features

| Feature | Description |
|---|---|
| **Static Analysis** | Deep file inspection — zero execution |
| **PE Header Parsing** | Architecture, compile time, entry point, sections |
| **Suspicious Imports** | Flags dangerous Windows APIs with A/W-suffix variant matching |
| **File Hashes** | MD5, SHA1, SHA256 — one-click copy |
| **Entropy Analysis** | 5-level rating — skips false positives on images/archives |
| **YARA Scanning** | Custom `.yar` rules with severity + category metadata |
| **VirusTotal Lookup** | Hash-only lookup via VT API v3 — file never uploaded |
| **MITRE ATT&CK Mapping** | 30 techniques across 9 tactics, auto-mapped from findings |
| **Reverse String Detection** | Catches evasion like `"tpircSrewoP"` = PowerScript |
| **Wide-String Extraction** | Detects UTF-16LE strings malware uses to bypass ASCII scanners |
| **Dynamic String Limit** | Scales extraction depth by file size (5k–80k strings) |
| **Benign API Allowlist** | Prevents false positives from Windows runtime API names |
| **PE Section Checks** | High-entropy sections + known packer names (UPX, Themida, etc.) |
| **ZIP Archive Support** | Extracts and analyses PE files found inside ZIP archives |
| **Cyclomatic Complexity** | Branch complexity for binaries and source scripts |
| **Interesting Strings** | URLs, IPs (validated), emails, registry keys, paths, mutex/GUIDs |
| **PDF Export** | Download full analysis as PDF |
| **Analysis History Dashboard** | Searchable + filterable history table with overview chart |
| **Threat Summary** | Plain-English classification reasoning |
| **Login System** | Supabase email/password authentication with guest mode |
| **Dark Aurora UI** | Professional dark-themed interface — spotlight cards, animated bugs |
| **IST Timestamps** | All report timestamps in India Standard Time (UTC+5:30) |

---

## 🗂️ Project Structure

```
malware-behavior-analyzer/
│
├── app.py                        ← Flask app: all routes, login, PDF export,
│                                   Jinja2 filters (format_datetime, clean_file_type)
├── config.py                     ← All settings via environment variables
├── supabase_client.py            ← Supabase auth + analyses database operations
├── database.py                   ← SQLite (analyzer.db): init, save, fetch analyses
├── requirements.txt              ← Python dependencies
├── Dockerfile                    ← Render container image (YARA + WeasyPrint libs)
├── render.yaml                   ← Render infrastructure configuration
│
├── analyzer/
│   ├── static_analysis.py        ← Core engine: all detection + MITRE ATT&CK mapping
│   └── report_generator.py       ← Threat scoring, classification, IST timestamps
│
├── templates/
│   ├── login.html                ← Login page (Dark Aurora theme)
│   ├── index.html                ← Dashboard with history + overview chart
│   ├── report.html               ← Full analysis report
│   └── pdf_report.html           ← PDF-optimised report template
│
├── static/
│   └── images/
│       └── logo.png              ← Tool logo shown in header
│
├── rules/
│   └── malware_rules.yar         ← Your YARA rules file (you place here)
│
├── uploads/                      ← Auto-created on startup (config.py)
├── reports/                      ← Auto-created on startup — JSON reports saved here
├── sandbox_env/                  ← Auto-created on startup (reserved for future use)
└── analyzer.db                   ← SQLite database (auto-created on first run)
```

---

## ⚙️ Installation

### Step 1 — System packages (Kali Linux, run once)

```bash
sudo apt update
sudo apt install -y yara libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0
```

### Step 2 — Create virtual environment

```bash
cd ~/Desktop/malware-behavior-analyzer
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install Python dependencies

```bash
pip install -r requirements.txt --break-system-packages
```

### Step 4 — Create `.env`

Configure runtime values in `.env`:

```env
# Supabase
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOi...
SUPABASE_SERVICE_KEY=eyJhbGciOi...

# Flask
SECRET_KEY=change-this-in-production
PORT=5000
DEBUG=true

# VirusTotal (optional)
VIRUSTOTAL_API_KEY=your_key_here
```

### Step 5 — Add YARA rules (optional but recommended)

Place your `.yar` rule files at:
```
rules/malware_rules.yar
```

Free community rules: [https://github.com/Yara-Rules/rules](https://github.com/Yara-Rules/rules)

---

## 🚀 Running the Tool

```bash
cd ~/Desktop/malware-behavior-analyzer
source venv/bin/activate
python3 app.py
```

Open browser at:
```
http://localhost:5000
```

Login with your Supabase email/password.

---

## Render Deployment (Render-only)

This project is configured for Render using Docker (recommended).

### 1. Render service settings

- **Environment**: `Docker`
- **Branch**: `main`
- **Root Directory**: leave empty
- **Instance type**: Free (or higher)

If Render asks for commands:
- **Build Command**: leave empty (Docker handles build)
- **Start Command**: leave empty (Docker CMD handles startup)

### 2. Environment variables in Render

Set these in Render Web Service:

```env
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_KEY=your_service_role_key
SECRET_KEY=your_long_random_secret
VIRUSTOTAL_API_KEY=your_virustotal_key
DEBUG=false
PORT=5000
```

### 3. Deploy and validate

After deploy:
1. Sign up / sign in
2. Upload sample
3. Check history + report view
4. Delete a report
5. Verify guest mode still works

> Note: Render free tier spins down when idle and has ephemeral filesystem. Logged-in report data is stored in Supabase.

---

## ♻️ If You Rename the Project Folder

The virtual environment stores the absolute path — renaming breaks it silently.
Fix it in 30 seconds:

```bash
cd ~/Desktop/malware-behavior-analyzer   # ← new folder name
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt --break-system-packages
python3 app.py
```

Your analyses, database, and reports are **not touched** — only the venv is recreated.

---

## 📁 Supported File Types

| Type | Analysis |
|---|---|
| `.exe` `.dll` `.sys` `.drv` `.ocx` `.scr` `.cpl` `.efi` | Full PE analysis: headers, sections, imports, packer detection |
| `.zip` containing PE | Extracts up to 5 inner executables and analyses each |
| `.ps1` `.bat` `.cmd` `.vbs` | String analysis + cyclomatic complexity |
| `.py` `.js` `.ts` `.sh` `.rb` `.php` `.c` `.cpp` `.cs` `.java` | Source-level CC + full string analysis |
| `.elf` | ELF binary detection, entropy, strings, YARA |
| `.pdf` `.png` `.jpg` `.gif` | Entropy (without false-positive scoring), strings, YARA, hashes |
| `.7z` `.rar` `.zip` | Archive detection, entropy, YARA |
| Any other file | MD5/SHA1/SHA256, entropy, YARA, strings |

**Max upload size:** 50 MB (set in `config.py` → `MAX_FILE_SIZE`)

---

## 🧠 Analysis Engine — `static_analysis.py`

| Method | What it does |
|---|---|
| `_detect_file_type()` | Magic byte detection (MZ, ELF, ZIP, PDF, PNG, JPEG, GIF, 7z, RAR) |
| `_compute_hashes()` | MD5, SHA1, SHA256 |
| `_calculate_entropy()` | Shannon entropy with 5-tier level rating |
| `_dynamic_string_limit()` | Scales extraction count by file size (5k–80k) |
| `_extract_strings()` | ASCII + **UTF-16LE wide strings** — deduped, combined |
| `_find_interesting_strings()` | 100+ keyword list, benign API allowlist, base64 blob filter, **reverse string detection**, validated IPs, emails, mutex/GUIDs |
| `_parse_pe_header()` | Full PE parse — sections, imports, compile time, architecture |
| `_parse_pe_from_archive()` | Extracts and analyses PE files inside ZIP archives |
| `_check_suspicious_indicators()` | Entropy heuristics, small executable check, **high-entropy PE sections**, **known packer section names** (UPX, Themida, ASPack…), no-import-table detection |
| `_run_yara_scan()` | YARA match with rule name, severity, category, tags |
| `_check_virustotal()` | VT API v3 hash lookup — engine breakdown, detection ratio |
| `_map_mitre_attack()` | 30 ATT&CK v15 techniques, A/W variant matching, dedup by highest severity |

---

## 📊 Scoring Engine — `report_generator.py`

| Module | Points | Notes |
|---|---|---|
| Entropy (very high) | +20 critical | Skipped for JPEG/PNG/GIF/PDF/ZIP/7z/RAR (natural high entropy) |
| Entropy (high) | +10 high | Same skip logic |
| Executable file type | +10 medium | .exe, .elf |
| Suspicious PE import | +5 high each | Capped at 5 imports |
| URLs found | +20 high | |
| Registry key refs | +5 medium | |
| Suspicious keywords (>3) | +15 high | |
| Suspicious keywords (1–3) | +10 medium | |
| VirusTotal >50% detection | +25 critical | |
| VirusTotal >20% detection | +20 high | |
| VirusTotal any detection | +10 medium | |
| YARA critical match | +20 | Capped at 30 pts total from YARA |
| YARA high match | +15 | |
| YARA medium match | +10 | |
| YARA low match | +5 | |
| CC very high | +15 critical | |
| CC high | +10 high | |
| CC moderate | +5 medium | |

**Classification thresholds:**
- Score ≤ 20 → `BENIGN`
- Score 21–50 → `SUSPICIOUS`
- Score ≥ 51 → `MALICIOUS`
- Score capped at 100

---

## 🔍 MITRE ATT&CK Coverage (30 Techniques)

| Tactic | Techniques |
|---|---|
| Defense Evasion | T1027 Obfuscation, T1055.002 PE Injection, T1055 Process Injection, T1497.001 Sandbox Evasion, T1036 Masquerading, T1564.001 Hidden Files, T1070.004 File Deletion |
| Execution | T1059.001 PowerShell, T1059.003 CMD Shell, T1106 Native API |
| Privilege Escalation | T1134 Token Manipulation, T1055.004 APC Injection |
| Persistence | T1547.001 Registry Run Keys, T1112 Modify Registry, T1053.005 Scheduled Tasks |
| Discovery | T1057 Process Discovery, T1082 System Info, T1083 File Discovery |
| Command & Control | T1071.001 HTTP/S, T1071.004 DNS, T1132 Data Encoding, T1095 Raw Sockets |
| Collection | T1056.001 Keylogging, T1113 Screen Capture |
| Impact | T1486 Data Encrypted for Impact, T1486.001 Symmetric Cryptography, T1490 Inhibit System Recovery |

**A/W suffix matching:** searching for `InternetOpen` automatically matches `InternetOpenA`, `InternetOpenW`, `InternetOpenUrlA`, `InternetOpenUrlW` etc.

---

## 🗄️ Database — `database.py`

- Engine: **SQLite** (stdlib `sqlite3` — no ORM, no SQLAlchemy)
- File: `analyzer.db` (in project root, auto-created)
- Table: `analyses` with columns: `id`, `filename`, `sha256`, `file_size`, `file_type`, `threat_score`, `classification`, `report_path`, `timestamp`
- Safe migration: adds `file_type` column to old databases automatically

---

## 🔒 Security Notes

- Designed for **local use only** — do not expose port 5000 to the internet
- VirusTotal lookups are **hash-only** — your files are never sent to VT
- Uploaded files are **deleted from disk** immediately after analysis (`app.py` → `os.remove(file_path)`)
- Report data is saved as JSON in `reports/` for viewing later
- Change `SECRET_KEY` in `config.py` before any shared use

---

## 🐛 Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: pefile` | `pip install pefile --break-system-packages` |
| `ModuleNotFoundError: yara` | `sudo apt install yara && pip install yara-python --break-system-packages` |
| `PDF export fails / WeasyPrint error` | `sudo apt install libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0` |
| `venv/bin/activate: No such file` | Folder renamed — recreate venv (see above) |
| `Network error on upload` | Check `uploads/` folder exists (auto-created by `config.py` on startup) |
| `YARA rules not loading` | Confirm file exists at `rules/malware_rules.yar` — check `YARA_RULES_PATH` in `config.py` |
| `VirusTotal returns 401` | Invalid API key — update `VIRUSTOTAL_API_KEY` in `config.py` |
| `VirusTotal returns 404` | Hash not in VT database — file has never been submitted |
| `Port 5000 in use` | Change `PORT = 5001` in `config.py` |
| `Database errors` | Delete `analyzer.db` — it will be recreated automatically on next run |
| `PDF says "Unavailable"` | WeasyPrint not installed — `pip install weasyprint --break-system-packages` |

---

## 📦 Dependencies (5 pip packages)

| Package | Version | Used in | Purpose |
|---|---|---|---|
| `Flask` | ≥3.0.0 | `app.py` | Web framework — routing, sessions, templates, flash |
| `pefile` | ≥2023.2.7 | `static_analysis.py` | PE binary parsing |
| `yara-python` | ≥4.3.1 | `static_analysis.py` | YARA signature scanning |
| `requests` | ≥2.31.0 | `static_analysis.py` | VirusTotal API v3 |
| `weasyprint` | ≥60.0 | `app.py` | PDF report generation |

**Auto-installed with Flask** (no need to list separately):
`Jinja2`, `Werkzeug`, `click`, `itsdangerous`, `MarkupSafe`

**Standard library** (no pip needed):
`os`, `re`, `math`, `hashlib`, `datetime`, `zipfile`, `tempfile`, `shutil`, `json`, `sqlite3`, `base64`, `functools`

> **Note on `pytz`:** NOT used. IST timestamps are handled natively via
> `datetime.timezone(datetime.timedelta(hours=5, minutes=30))` in `report_generator.py`.

---

## 📋 Version History

| Version | What was added |
|---|---|
| v1.0 | Core engine: PE analysis, entropy, hashes, YARA, VT, history dashboard, login |
| v1.1 | Cyclomatic complexity — binary opcode scan + source branch counting |
| v1.2 | MITRE ATT&CK mapping — 26 techniques, 8 tactics, confidence scoring |
| v1.3 | Reverse string detection — catches evasion like `"tpircSrewoP"` |
| v1.4 | Wide-string (UTF-16LE) extraction, dynamic string limit, benign API allowlist, base64 blob filter, PE section packer detection, no-import-table detection |
| v1.5 | Dark Aurora UI, equal-height cards, spotlight hover, bug canvas animation |
| v1.6 | IST timestamps, entropy false-positive fix for images/archives, 30 ATT&CK techniques |

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**.
Only analyse files you have explicit permission to examine.
The author is not responsible for any misuse.

---

*MalVizar — Static Threat Analysis Engine · v1.0*

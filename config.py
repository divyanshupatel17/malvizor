import os
from dotenv import load_dotenv

# ──────────────────────────────────────────────
#  MalVizor — Configuration
# ──────────────────────────────────────────────

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env_bool(name, default):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")

# ─── File Paths ──────────────────────────────
UPLOAD_FOLDER  = os.path.join(BASE_DIR, "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "reports")
DATABASE_PATH  = os.path.join(BASE_DIR, "analyzer.db")

# ─── Supabase ────────────────────────────────
SUPABASE_URL         = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_ANON_KEY    = os.getenv("SUPABASE_ANON_KEY", "").strip()
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "").strip()

# ─── YARA Rules ──────────────────────────────
YARA_RULES_PATH = os.path.join(BASE_DIR, "rules", "malware_rules.yar")

# ─── Upload Limits ───────────────────────────
MAX_FILE_SIZE = 100 * 1024 * 1024   # 100 MB

# ─── VirusTotal API ──────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

# ─── Flask Settings ──────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "mba-secret-key-change-me-2024")
DEBUG = _env_bool("DEBUG", True)
PORT  = int(os.getenv("PORT", "5000"))

# ─── Auto-create required folders ────────────
for folder in [UPLOAD_FOLDER, REPORTS_FOLDER]:
    os.makedirs(folder, exist_ok=True)

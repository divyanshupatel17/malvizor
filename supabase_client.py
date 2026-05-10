import datetime
import json
from typing import Optional

from supabase import Client, create_client

import config

_service_client: Optional[Client] = None
_auth_client: Optional[Client] = None


def _ensure_env():
    if not config.SUPABASE_URL:
        raise RuntimeError("SUPABASE_URL is not configured.")
    if not config.SUPABASE_SERVICE_KEY:
        raise RuntimeError("SUPABASE_SERVICE_KEY is not configured.")
    if not config.SUPABASE_ANON_KEY:
        raise RuntimeError("SUPABASE_ANON_KEY is not configured.")


def get_service_client() -> Client:
    global _service_client
    _ensure_env()
    if _service_client is None:
        _service_client = create_client(config.SUPABASE_URL, config.SUPABASE_SERVICE_KEY)
    return _service_client


def get_auth_client() -> Client:
    global _auth_client
    _ensure_env()
    if _auth_client is None:
        _auth_client = create_client(config.SUPABASE_URL, config.SUPABASE_ANON_KEY)
    return _auth_client


def _extract_auth(auth_response) -> dict:
    session_data = getattr(auth_response, "session", None)
    user_data = getattr(auth_response, "user", None)
    user_id = getattr(user_data, "id", None) if user_data else None
    email = getattr(user_data, "email", "") if user_data else ""
    access_token = getattr(session_data, "access_token", "") if session_data else ""

    return {
        "user_id": user_id,
        "email": email or "",
        "access_token": access_token or "",
    }


def authenticate_user(email: str, password: str) -> dict:
    if not email or not password:
        raise ValueError("Email and password are required.")
    auth = get_auth_client().auth.sign_in_with_password({"email": email, "password": password})
    data = _extract_auth(auth)
    if not data["user_id"]:
        raise RuntimeError("Authentication failed.")
    return data


def signup_user(email: str, password: str) -> dict:
    if not email or not password:
        raise ValueError("Email and password are required.")
    auth = get_auth_client().auth.sign_up({"email": email, "password": password})
    data = _extract_auth(auth)
    if not data["user_id"]:
        raise RuntimeError("Signup failed. Check Supabase auth settings.")
    return data


def _resolve_file_type(report: dict):
    summary = report.get("summary", {})
    static_results = report.get("static_analysis", {})
    raw_ft = str(static_results.get("file_type", "") or "").strip()
    summary_ft = str(summary.get("file_type", "") or "").strip()

    def valid(v):
        return bool(v) and v.lower() not in ("unknown", "n/a", "none")

    if valid(raw_ft):
        return raw_ft
    if valid(summary_ft):
        return summary_ft
    return None


def save_analysis(user_id: str, report: dict) -> int:
    if not user_id:
        raise ValueError("user_id is required.")

    summary = report.get("summary", {})
    static_results = report.get("static_analysis", {})
    timestamp = summary.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat()

    payload = {
        "user_id": user_id,
        "filename": summary.get("file_name", "unknown"),
        "sha256": summary.get("sha256", ""),
        "file_size": static_results.get("file_size", summary.get("file_size", 0)),
        "file_type": _resolve_file_type(report),
        "threat_score": summary.get("threat_score", report.get("threat_score", 0)),
        "classification": summary.get("classification", report.get("classification", "unknown")),
        "report_json": report,
        "timestamp": timestamp,
    }

    result = get_service_client().table("analyses").insert(payload).execute()
    if not result.data:
        raise RuntimeError("Failed to save analysis in Supabase.")
    return int(result.data[0]["id"])


def get_all_analyses(user_id: str) -> list:
    result = (
        get_service_client()
        .table("analyses")
        .select("id, filename, sha256, file_size, file_type, threat_score, classification, timestamp")
        .eq("user_id", user_id)
        .order("timestamp", desc=True)
        .execute()
    )
    return result.data or []


def get_analysis(analysis_id: int, user_id: str) -> Optional[dict]:
    result = (
        get_service_client()
        .table("analyses")
        .select("*")
        .eq("id", analysis_id)
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    if not result.data:
        return None

    row = result.data[0]
    report_json = row.get("report_json")
    if isinstance(report_json, str):
        try:
            row["report_json"] = json.loads(report_json)
        except json.JSONDecodeError:
            row["report_json"] = {}
    return row


def delete_analysis(analysis_id: int, user_id: str) -> bool:
    result = (
        get_service_client()
        .table("analyses")
        .delete()
        .eq("id", analysis_id)
        .eq("user_id", user_id)
        .execute()
    )
    return bool(result.data)

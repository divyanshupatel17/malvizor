import os
import re
import json
import datetime
import tempfile
import base64
from functools import wraps

from flask import Flask, request, render_template, jsonify, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename

import config
import database
import supabase_client
from analyzer.static_analysis import StaticAnalyzer
from analyzer.report_generator import ReportGenerator

# Optional WeasyPrint for PDF
try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError):
    WEASYPRINT_AVAILABLE = False

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE

database.init_db()


# ── Auth helpers ──────────────────────────────────────────────────────────────

def is_logged_in():
    return bool(session.get('logged_in') and session.get('user_id'))

def is_guest():
    return bool(session.get('guest_mode'))

def has_access():
    """True if the user is either logged in or in guest mode."""
    return is_logged_in() or is_guest()


def _session_name_from_email(email):
    if not email:
        return "USER"
    return email.split("@", 1)[0].strip() or "USER"


def _set_logged_in_session(auth_data):
    session.clear()
    session['logged_in'] = True
    session['guest_mode'] = False
    session['user_id'] = auth_data.get('user_id')
    session['email'] = auth_data.get('email', '')
    session['username'] = _session_name_from_email(auth_data.get('email', ''))
    session['access_token'] = auth_data.get('access_token', '')


def _build_fallback_report(analysis):
    return {
        "summary": {
            "file_name": analysis.get("filename", "unknown"),
            "file_size": analysis.get("file_size", "unknown"),
            "file_type": analysis.get("file_type") or None,
            "sha256": analysis.get("sha256", ""),
            "threat_score": analysis.get("threat_score", 0),
            "classification": analysis.get("classification", "unknown"),
            "timestamp": analysis.get("timestamp", "")
        },
        "threat_score": analysis.get("threat_score", 0),
        "classification": analysis.get("classification", "unknown"),
        "indicators": [],
        "static_analysis": {}
    }


def _get_report_payload(analysis_id):
    if is_logged_in():
        analysis = supabase_client.get_analysis(analysis_id, session.get('user_id'))
        if not analysis:
            return None, None
        report_data = analysis.get("report_json") or {}
        if not isinstance(report_data, dict):
            report_data = {}
        if not report_data:
            report_data = _build_fallback_report(analysis)
        return analysis, report_data

    analysis = database.get_analysis(analysis_id)
    if not analysis:
        return None, None

    report_data = {}
    report_path = analysis.get("report_path", "")
    if report_path and os.path.exists(report_path):
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                report_data = json.load(f)
        except (OSError, json.JSONDecodeError):
            report_data = {}

    if not report_data:
        report_data = _build_fallback_report(analysis)
    return analysis, report_data


def login_required(f):
    """Require full login (not guest) — used for DB-write routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def access_required(f):
    """Allow both logged-in users AND guests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not has_access():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ── Jinja2 filters ────────────────────────────────────────────────────────────

@app.template_filter('format_datetime')
def format_datetime_filter(value):
    if not value:
        return '—'
    s = str(value).strip()
    MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']

    def fmt(dt):
        hh = dt.hour
        ampm = 'PM' if hh >= 12 else 'AM'
        hh = hh % 12 or 12
        return (f"{dt.day:02d} {MONTHS[dt.month-1]} {dt.year}, "
                f"{hh:02d}:{dt.minute:02d} {ampm}")

    m = re.match(
        r'^(\d{2})-(\d{2})-(\d{4})[T\s,]+(\d{1,2}):(\d{2})(?::\d{2})?\s*(AM|PM)?$',
        s, re.IGNORECASE
    )
    if m:
        dd, mo, yyyy, hh, mi, ampm = m.groups()
        h = int(hh)
        if ampm:
            if ampm.upper() == 'PM' and h != 12: h += 12
            if ampm.upper() == 'AM' and h == 12: h = 0
        try:
            return fmt(datetime.datetime(int(yyyy), int(mo), int(dd), h, int(mi)))
        except ValueError:
            pass

    norm = s.replace(' ', 'T')
    norm = re.sub(r'(\.\d{3})\d+', r'\1', norm).rstrip('Z')
    for fmt_str in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M'):
        try:
            return fmt(datetime.datetime.strptime(norm, fmt_str))
        except ValueError:
            continue

    return s


@app.template_filter('clean_file_type')
def clean_file_type_filter(value):
    if not value:
        return '—'
    v = str(value).strip()
    return '—' if v.lower() in ('unknown', 'n/a', '') else v


# ── Jinja2 globals — expose session state to all templates ───────────────────

@app.context_processor
def inject_session_info():
    return {
        'user_logged_in': is_logged_in(),
        'user_is_guest':  is_guest(),
        'session_username': session.get('username', ''),
    }


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_logged_in():
        return redirect(url_for('index'))

    if is_guest():
        session.clear()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        auth_action = request.form.get("auth_action", "login").strip().lower()

        try:
            if auth_action == "signup":
                auth_data = supabase_client.signup_user(email, password)
                flash("Account created successfully.", "success")
            else:
                auth_data = supabase_client.authenticate_user(email, password)
            _set_logged_in_session(auth_data)
            return redirect(url_for('index'))
        except Exception as e:
            flash(str(e), "error")

    return render_template("login.html")


@app.route("/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    try:
        auth_data = supabase_client.authenticate_user(email, password)
        _set_logged_in_session(auth_data)
        return jsonify({"success": True, "user_id": auth_data.get("user_id"), "email": auth_data.get("email", "")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/auth/signup", methods=["POST"])
def auth_signup():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))
    try:
        auth_data = supabase_client.signup_user(email, password)
        _set_logged_in_session(auth_data)
        return jsonify({"success": True, "user_id": auth_data.get("user_id"), "email": auth_data.get("email", "")})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/guest")
def guest_login():
    """Start a guest session — no credentials required."""
    session.clear()
    session['guest_mode'] = True
    session['logged_in']  = False
    return redirect(url_for('index'))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))


# ── Protected routes ──────────────────────────────────────────────────────────

@app.route("/")
@access_required
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
@access_required
def upload():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "No file selected"}), 400
    try:
        filename  = secure_filename(file.filename)
        if not filename:
            filename = "uploaded_sample"
        file_path = os.path.join(config.UPLOAD_FOLDER, filename)
        file.save(file_path)

        static_analyzer = StaticAnalyzer(file_path)
        static_results  = static_analyzer.run()

        report_gen = ReportGenerator(static_results)
        report     = report_gen.generate()

        # Only persist to DB for logged-in users; guests get ephemeral reports
        if is_logged_in():
            analysis_id = supabase_client.save_analysis(session.get('user_id'), report)
            guest_mode  = False
        else:
            analysis_id = database.save_analysis(report, guest=True)
            guest_mode  = True

        try:
            os.remove(file_path)
        except OSError:
            pass

        return jsonify({
            "success"        : True,
            "report_id"      : analysis_id,
            "threat_score"   : report.get("threat_score", 0),
            "classification" : report.get("classification", "unknown"),
            "guest_mode"     : guest_mode,
            "filename"       : report.get("summary", {}).get("file_name", filename),
            "file_type"      : report.get("static_analysis", {}).get("file_type") or
                               report.get("summary", {}).get("file_type", ""),
            "timestamp"      : report.get("summary", {}).get("timestamp", datetime.datetime.now().isoformat()),
            "report_json"    : report if guest_mode else None,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/report/<int:analysis_id>")
@access_required
def report(analysis_id):
    analysis, report_data = _get_report_payload(analysis_id)
    if not analysis:
        return render_template("index.html"), 404

    summary = report_data.setdefault("summary", {})
    ft = summary.get("file_type")
    if not ft or str(ft).strip().lower() in ('unknown', 'n/a', ''):
        summary["file_type"] = analysis.get("file_type") or None

    return render_template("report.html", report=report_data, weasyprint_available=WEASYPRINT_AVAILABLE)


@app.route("/report/<int:analysis_id>/pdf")
@access_required
def download_pdf(analysis_id):
    """Generate and serve a clean PDF of the analysis report."""
    if not WEASYPRINT_AVAILABLE:
        return jsonify({"error": "WeasyPrint not installed. Run: pip install weasyprint"}), 500

    analysis, report_data = _get_report_payload(analysis_id)
    if not analysis:
        return jsonify({"error": "Report not found"}), 404

    try:
        IST_OFFSET   = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
        now_ist      = datetime.datetime.now(IST_OFFSET)
        generated_at = now_ist.strftime("%d %b %Y, %I:%M %p IST")

        logo_b64 = ""
        logo_path = os.path.join(app.static_folder, "images", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as lf:
                logo_b64 = "data:image/png;base64," + base64.b64encode(lf.read()).decode("utf-8")

        html_content = render_template(
            "pdf_report.html",
            report=report_data,
            generated_at=generated_at,
            logo_b64=logo_b64
        )

        pdf_bytes = HTML(string=html_content, base_url=request.host_url).write_pdf()

        fname   = report_data.get("summary", {}).get("file_name", "report")
        safe    = "".join(c if c.isalnum() or c in "._-" else "_" for c in fname)
        cls     = report_data.get("classification", "UNKNOWN").upper()
        dl_name = f"MBA_Report_{safe}_{cls}.pdf"

        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        tmp.write(pdf_bytes)
        tmp.close()

        return send_file(
            tmp.name,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=dl_name
        )

    except Exception as e:
        return jsonify({"error": f"PDF generation failed: {str(e)}"}), 500


@app.route("/api/delete/<int:analysis_id>", methods=["DELETE"])
@login_required   # only logged-in users have DB records to delete
def delete_analysis(analysis_id):
    try:
        analysis = supabase_client.get_analysis(analysis_id, session.get('user_id'))
        if not analysis:
            return jsonify({"success": False, "error": "Not found"}), 404
        supabase_client.delete_analysis(analysis_id, session.get('user_id'))
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/history")
@login_required   # guests load history from localStorage, not this endpoint
def api_history():
    analyses = supabase_client.get_all_analyses(session.get('user_id'))
    return jsonify({"analyses": analyses})


@app.route("/api/session-info")
def api_session_info():
    """Lightweight endpoint so JS can know the current session type."""
    return jsonify({
        "logged_in": is_logged_in(),
        "guest":     is_guest(),
        "username":  session.get('username', session.get('email', '')),
    })


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  Static Malware Analyzer — MalVizor")
    print(f"  Running on http://127.0.0.1:{config.PORT}")
    if not WEASYPRINT_AVAILABLE:
        print("  ⚠  WeasyPrint not found — PDF export disabled")
        print("     Run: pip install weasyprint --break-system-packages")
    print("=" * 50 + "\n")
    app.run(host="127.0.0.1", port=config.PORT, debug=config.DEBUG)

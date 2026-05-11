import os
import hmac
import ipaddress
import secrets
import socket
import sqlite3
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, abort, g, redirect, render_template, request, session, url_for


DATABASE = os.environ.get("DATABASE_PATH", "watchtower.db")
REQUEST_TIMEOUT_SECONDS = 8
MAX_REDIRECTS = 3
MAX_NAME_LENGTH = 120
ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
BLOCKED_HOST_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER") == "true",
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS monitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            expected_status INTEGER NOT NULL DEFAULT 200,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            status_code INTEGER,
            response_time_ms INTEGER,
            message TEXT NOT NULL,
            checked_at TEXT NOT NULL,
            FOREIGN KEY (monitor_id) REFERENCES monitors (id) ON DELETE CASCADE
        );
        """
    )
    db.commit()


@app.before_request
def before_request():
    init_db()
    if request.method == "POST":
        validate_csrf_token()


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf_token():
    expected = session.get("_csrf_token")
    supplied = request.form.get("_csrf_token", "")
    if not expected or not hmac.compare_digest(expected, supplied):
        abort(400)


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_url(raw_url):
    url = raw_url.strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    return url


def validate_public_http_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        return False, "Only http and https URLs can be monitored."

    if parsed.username or parsed.password:
        return False, "URLs with embedded credentials are not allowed."

    try:
        port = parsed.port
    except ValueError:
        return False, "The URL port is invalid."

    if port and port not in ALLOWED_PORTS:
        return False, "Only standard web ports 80 and 443 are allowed."

    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(BLOCKED_HOST_SUFFIXES):
        return False, "Local and internal hostnames are not allowed."

    try:
        addresses = socket.getaddrinfo(hostname, port or default_port(parsed.scheme), type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False, "The hostname could not be resolved."

    if not addresses:
        return False, "The hostname could not be resolved."

    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not is_public_ip(ip):
            return False, "Private, local, reserved, and metadata network addresses are not allowed."

    return True, ""


def default_port(scheme):
    return 443 if scheme == "https" else 80


def is_public_ip(ip):
    return all(
        not flag
        for flag in (
            ip.is_loopback,
            ip.is_link_local,
            ip.is_private,
            ip.is_reserved,
            ip.is_multicast,
            ip.is_unspecified,
        )
    )


def safe_get(url):
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        is_valid, message = validate_public_http_url(current_url)
        if not is_valid:
            raise ValueError(message)

        response = requests.get(
            current_url,
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=False,
            headers={"User-Agent": "Watchtower-MVP/1.0"},
        )

        if response.is_redirect and response.headers.get("Location"):
            current_url = urljoin(current_url, response.headers["Location"])
            continue

        return response

    raise ValueError("Too many redirects.")


def classify_check(status_code, expected_status):
    if status_code == expected_status:
        return "up", "Website returned the expected status code."
    if status_code and 200 <= status_code < 400:
        return "warning", f"Website responded, but expected {expected_status}."
    return "down", f"Website returned HTTP {status_code} instead of {expected_status}."


def run_check(monitor):
    started = time.perf_counter()
    try:
        response = safe_get(monitor["url"])
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        status, message = classify_check(response.status_code, monitor["expected_status"])
        save_check(monitor["id"], status, response.status_code, elapsed_ms, message)
    except ValueError as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        save_check(monitor["id"], "down", None, elapsed_ms, f"Blocked unsafe target: {exc}")
    except requests.RequestException as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        save_check(monitor["id"], "down", None, elapsed_ms, f"Request failed: {exc}")


def save_check(monitor_id, status, status_code, response_time_ms, message):
    db = get_db()
    db.execute(
        """
        INSERT INTO checks (monitor_id, status, status_code, response_time_ms, message, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (monitor_id, status, status_code, response_time_ms, message, now_iso()),
    )
    db.commit()


def fetch_dashboard_data():
    db = get_db()
    monitors = db.execute(
        """
        SELECT
            monitors.*,
            latest.status AS latest_status,
            latest.status_code AS latest_status_code,
            latest.response_time_ms AS latest_response_time_ms,
            latest.message AS latest_message,
            latest.checked_at AS latest_checked_at
        FROM monitors
        LEFT JOIN checks AS latest
            ON latest.id = (
                SELECT id FROM checks
                WHERE checks.monitor_id = monitors.id
                ORDER BY checked_at DESC
                LIMIT 1
            )
        ORDER BY monitors.created_at DESC
        """
    ).fetchall()

    checks = db.execute(
        """
        SELECT checks.*, monitors.name AS monitor_name, monitors.url AS monitor_url
        FROM checks
        JOIN monitors ON monitors.id = checks.monitor_id
        ORDER BY checks.checked_at DESC
        LIMIT 12
        """
    ).fetchall()

    total = len(monitors)
    up = sum(1 for monitor in monitors if monitor["latest_status"] == "up")
    warning = sum(1 for monitor in monitors if monitor["latest_status"] == "warning")
    down = sum(1 for monitor in monitors if monitor["latest_status"] == "down")

    return monitors, checks, {"total": total, "up": up, "warning": warning, "down": down}


@app.route("/")
def index():
    monitors, checks, stats = fetch_dashboard_data()
    return render_template("index.html", monitors=monitors, checks=checks, stats=stats)


@app.post("/monitors")
def create_monitor():
    name = request.form.get("name", "").strip()[:MAX_NAME_LENGTH]
    url = normalize_url(request.form.get("url", ""))
    expected_status = request.form.get("expected_status", "200").strip()

    if not name or not url:
        return redirect(url_for("index"))

    is_valid, _message = validate_public_http_url(url)
    if not is_valid:
        return redirect(url_for("index"))

    try:
        expected_status_int = int(expected_status)
    except ValueError:
        expected_status_int = 200

    if not 100 <= expected_status_int <= 599:
        expected_status_int = 200

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO monitors (name, url, expected_status, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (name, url, expected_status_int, now_iso()),
    )
    db.commit()

    monitor = db.execute("SELECT * FROM monitors WHERE id = ?", (cursor.lastrowid,)).fetchone()
    run_check(monitor)
    return redirect(url_for("index"))


@app.post("/monitors/<int:monitor_id>/check")
def check_monitor(monitor_id):
    monitor = get_db().execute("SELECT * FROM monitors WHERE id = ?", (monitor_id,)).fetchone()
    if monitor is not None:
        run_check(monitor)
    return redirect(url_for("index"))


@app.post("/monitors/check-all")
def check_all_monitors():
    monitors = get_db().execute("SELECT * FROM monitors ORDER BY created_at DESC").fetchall()
    for monitor in monitors:
        run_check(monitor)
    return redirect(url_for("index"))


@app.post("/monitors/<int:monitor_id>/delete")
def delete_monitor(monitor_id):
    db = get_db()
    db.execute("DELETE FROM checks WHERE monitor_id = ?", (monitor_id,))
    db.execute("DELETE FROM monitors WHERE id = ?", (monitor_id,))
    db.commit()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)

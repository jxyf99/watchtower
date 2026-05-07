import os
import sqlite3
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from flask import Flask, g, redirect, render_template, request, url_for


DATABASE = os.environ.get("DATABASE_PATH", "watchtower.db")
REQUEST_TIMEOUT_SECONDS = 8

app = Flask(__name__)


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


def classify_check(status_code, expected_status):
    if status_code == expected_status:
        return "up", "Website returned the expected status code."
    if status_code and 200 <= status_code < 400:
        return "warning", f"Website responded, but expected {expected_status}."
    return "down", f"Website returned HTTP {status_code} instead of {expected_status}."


def run_check(monitor):
    started = time.perf_counter()
    try:
        response = requests.get(
            monitor["url"],
            timeout=REQUEST_TIMEOUT_SECONDS,
            allow_redirects=True,
            headers={"User-Agent": "Watchtower-MVP/1.0"},
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        status, message = classify_check(response.status_code, monitor["expected_status"])
        save_check(monitor["id"], status, response.status_code, elapsed_ms, message)
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
    name = request.form.get("name", "").strip()
    url = normalize_url(request.form.get("url", ""))
    expected_status = request.form.get("expected_status", "200").strip()

    if not name or not url:
        return redirect(url_for("index"))

    try:
        expected_status_int = int(expected_status)
    except ValueError:
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

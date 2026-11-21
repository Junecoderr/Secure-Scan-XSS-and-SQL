from flask import Flask, render_template, request
from markupsafe import escape
from detector import detect_xss, detect_sqli
import sqlite3
from datetime import datetime

app = Flask(__name__)

DB_NAME = "detection_logs.db"


# -------------------------------
# Initialize Database
# -------------------------------

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submitted_input TEXT,
            attack_type TEXT,
            xss_detected INTEGER,
            sql_detected INTEGER,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()


# -------------------------------
# Home Page
# -------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------
# XSS and SQL Injection Detection
# -------------------------------

@app.route("/test", methods=["POST"])
def test():

    user_input = request.form.get("user_input", "")

    xss_detected = detect_xss(user_input)
    sql_detected = detect_sqli(user_input)

    safe_input = escape(user_input)

    if xss_detected and sql_detected:
        attack_type = "XSS and SQL Injection"

    elif xss_detected:
        attack_type = "XSS"

    elif sql_detected:
        attack_type = "SQL Injection"

    else:
        attack_type = "Safe"

    suspicious = xss_detected or sql_detected

    # Save detection record in SQLite

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO detection_logs
        (submitted_input, attack_type, xss_detected,
         sql_detected, timestamp)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_input,
        attack_type,
        int(xss_detected),
        int(sql_detected),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return render_template(
        "result.html",
        user_input=safe_input,
        suspicious=suspicious,
        xss_detected=xss_detected,
        sql_detected=sql_detected
    )


# -------------------------------
# Detection Logs
# -------------------------------

@app.route("/logs")
def logs():

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    records = conn.execute(
        "SELECT * FROM detection_logs ORDER BY id DESC"
    ).fetchall()

    conn.close()

    return render_template(
        "logs.html",
        records=records
    )


# -------------------------------
# Security Dashboard
# -------------------------------

@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    # Total scans

    total_scans = conn.execute(
        "SELECT COUNT(*) FROM detection_logs"
    ).fetchone()[0]

    # Safe scans

    safe_scans = conn.execute("""
        SELECT COUNT(*)
        FROM detection_logs
        WHERE xss_detected = 0
        AND sql_detected = 0
    """).fetchone()[0]

    # XSS detections

    xss_count = conn.execute("""
        SELECT COUNT(*)
        FROM detection_logs
        WHERE xss_detected = 1
    """).fetchone()[0]

    # SQL Injection detections

    sql_count = conn.execute("""
        SELECT COUNT(*)
        FROM detection_logs
        WHERE sql_detected = 1
    """).fetchone()[0]

    # Scans detecting both attacks

    combined_count = conn.execute("""
        SELECT COUNT(*)
        FROM detection_logs
        WHERE xss_detected = 1
        AND sql_detected = 1
    """).fetchone()[0]

    # Individual attack categories for chart

    xss_only = xss_count - combined_count

    sql_only = sql_count - combined_count

    safe_count = safe_scans

    # Recent detection activity

    recent_records = conn.execute("""
        SELECT *
        FROM detection_logs
        ORDER BY id DESC
        LIMIT 5
    """).fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        safe_scans=safe_scans,
        xss_count=xss_count,
        sql_count=sql_count,
        safe_count=safe_count,
        xss_only=xss_only,
        sql_only=sql_only,
        combined_count=combined_count,
        recent_records=recent_records
    )


# -------------------------------
# Run Flask Application
# -------------------------------

if __name__ == "__main__":

    init_db()

    app.run(debug=True)
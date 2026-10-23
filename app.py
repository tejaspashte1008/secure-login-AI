"""
SecureLogin AI – Intelligent Login Theft Detection and Alert System
===================================================================
A College Project for Third Year Artificial Intelligence & Machine Learning (TY AIML)
Integrates:
- Flask Web Application & Session Security
- SQLite Database & SQLAlchemy ORM
- Application-Level Security Firewall & Rule Engine (INS)
- Scikit-learn Isolation Forest ML Anomaly Detection (MLF)
- Real SMTP Email Alerts & WhatsApp Notification Services
- Data Analysis & Visualization (DAV) CSV Pipeline for Tableau
"""

import os
import re
import io
import pandas as pd
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, make_response
)

from config import Config
from models import db, User, LoginLog
from security.firewall import firewall
from services.email_service import send_security_alert_email
from services.whatsapp_service import send_whatsapp_security_alert
from ml.model import detector

# Initialize Flask Application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize Database
db.init_app(app)

# Helper: Email format validator regex
EMAIL_REGEX = r"^[\w\.-]+@[\w\.-]+\.\w+$"

def login_required(f):
    """Decorator to enforce session authentication on protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access the Security Operations Center.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def anonymize_email(email_str: str) -> str:
    """Mask email for privacy in Tableau CSV exports (e.g. j***e@domain.com)."""
    if not email_str or "@" not in email_str:
        return "anonymous_actor"
    parts = email_str.split("@")
    user_part = parts[0]
    domain_part = parts[1]
    if len(user_part) <= 2:
        masked_user = user_part[0] + "***"
    else:
        masked_user = user_part[0] + "***" + user_part[-1]
    return f"{masked_user}@{domain_part}"

# ============================================================
# 1. AUTHENTICATION & REGISTRATION ROUTES
# ============================================================

@app.route("/")
def index():
    """Root redirect: to dashboard if logged in, else to login page."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    """Handle new user account registration."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        whatsapp_number = request.form.get("whatsapp_number", "").strip()

        # Input Validations
        if not full_name or not email or not password or not whatsapp_number:
            flash("All fields are required.", "danger")
            return render_template("register.html")

        if not re.match(EMAIL_REGEX, email):
            flash("Invalid email address format.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters long for security compliance.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html")

        # Check for existing user
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("An account is already registered with this email address. Please sign in.", "warning")
            return redirect(url_for("login"))

        # Create new user with securely hashed password (scrypt)
        new_user = User(
            full_name=full_name,
            email=email,
            whatsapp_number=whatsapp_number
        )
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! You may now sign in with your credentials.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Handle user authentication with:
    - Layer 7 Application Firewall Rate Limiting
    - Scikit-Learn Isolation Forest Anomaly Risk Scoring
    - 3-Attempt Lockout Enforcement
    - Instant Dual-Channel Alerts (SMTP + WhatsApp)
    """
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        client_ip = firewall.get_client_ip()
        user_agent = request.headers.get("User-Agent", "Unknown")

        # 1. Application-Level Rate Limiter Check (INS concept)
        is_allowed, rate_msg = firewall.check_ip_rate_limit(client_ip)
        if not is_allowed:
            flash(rate_msg, "danger")
            return render_template("login.html")

        # 2. Query target user account
        user = User.query.filter_by(email=email).first()

        # 3. Verify password if user exists
        is_password_correct = False
        if user:
            is_password_correct = user.check_password(password)

        # 4. Calculate Machine Learning Anomaly Risk Score (MLF concept)
        recent_failures = user.failed_attempts if user else 1
        risk_score, risk_label = detector.predict_risk(failed_attempts=recent_failures)

        # 5. Evaluate authentication against Security Firewall Rule Engine
        result = firewall.evaluate_login_attempt(
            user=user,
            email=email,
            is_password_correct=is_password_correct,
            ml_risk_score=risk_score
        )

        # 6. Trigger Security Alerts if 3-attempt threshold breached
        if result.get("trigger_alerts") and user:
            # Trigger Real SMTP Email Alert
            send_security_alert_email(
                recipient_email=user.email,
                recipient_name=user.full_name,
                failed_count=user.failed_attempts,
                ip_address=client_ip,
                user_agent=user_agent
            )

            # Trigger Real WhatsApp Alert
            send_whatsapp_security_alert(
                recipient_number=user.whatsapp_number,
                failed_count=user.failed_attempts,
                ip_address=client_ip
            )

        # 7. Route according to authentication result
        if result["allowed"]:
            # Successful Authentication
            session.clear()
            session["user_id"] = user.id
            session["user_name"] = user.full_name
            session["user_email"] = user.email
            session.permanent = True

            flash(f"Welcome back, {user.full_name}! Authenticated securely.", "success")
            return redirect(url_for("dashboard"))
        else:
            # Authentication Denied
            flash(result["message"], "danger")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/logout")
def logout():
    """Clear session and log out user."""
    session.clear()
    flash("You have been signed out safely.", "info")
    return redirect(url_for("login"))

# ============================================================
# 2. SOC DASHBOARD & TELEMETRY ROUTES
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():
    """SOC Executive Dashboard with live telemetry cards and Chart.js feeds."""
    total_logins = LoginLog.query.count()
    success_count = LoginLog.query.filter_by(success=True).count()
    failed_count = LoginLog.query.filter_by(success=False).count()
    suspicious_count = LoginLog.query.filter(
        (LoginLog.status == "SUSPICIOUS") | (LoginLog.risk_score >= 0.70)
    ).count()
    blocked_count = LoginLog.query.filter_by(status="BLOCKED").count()

    stats = {
        "total_logins": total_logins,
        "success_count": success_count,
        "failed_count": failed_count,
        "suspicious_count": suspicious_count,
        "blocked_count": blocked_count,
    }

    # Recent 10 login telemetry logs
    recent_logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(10).all()

    # Aggregate Hourly Telemetry for Chart.js
    hourly_success = [0] * 24
    hourly_failed = [0] * 24
    all_logs = LoginLog.query.all()
    for l in all_logs:
        h = l.timestamp.hour
        if l.success:
            hourly_success[h] += 1
        else:
            hourly_failed[h] += 1

    chart_hourly_labels = [f"{h:02d}:00" for h in range(24)]

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_logs=recent_logs,
        chart_hourly_labels=chart_hourly_labels,
        chart_hourly_success=hourly_success,
        chart_hourly_failed=hourly_failed
    )

@app.route("/login-activity")
@login_required
def login_activity():
    """Audit log view of all recorded authentication events."""
    logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).all()
    return render_template("login_activity.html", logs=logs)

@app.route("/security-alerts")
@login_required
def security_alerts():
    """View triggered security incidents (theft attempts and account lockouts)."""
    alert_events = LoginLog.query.filter(
        (LoginLog.status == "BLOCKED") | (LoginLog.failed_attempt_count >= 3)
    ).order_by(LoginLog.timestamp.desc()).all()

    email_configured = bool(Config.SMTP_USERNAME and Config.SMTP_PASSWORD)
    whatsapp_configured = bool(
        Config.CALLMEBOT_API_KEY or
        (Config.TWILIO_ACCOUNT_SID and Config.TWILIO_AUTH_TOKEN) or
        (Config.WHATSAPP_API_URL and Config.WHATSAPP_API_TOKEN)
    )

    return render_template(
        "security_alerts.html",
        alert_events=alert_events,
        email_configured=email_configured,
        whatsapp_configured=whatsapp_configured
    )

@app.route("/firewall")
@login_required
def firewall_status():
    """INS Academic View: Application Firewall details and rule configurations."""
    client_ip = firewall.get_client_ip()
    return render_template("firewall.html", client_ip=client_ip)

@app.route("/firewall/reset", methods=["POST"])
@login_required
def reset_lockouts():
    """Lab Utility: Reset all account lockouts and failed attempts for demonstration."""
    users = User.query.all()
    for u in users:
        u.reset_failed_attempts()
    db.session.commit()
    flash("Demo Reset Complete: All user account lockouts have been released.", "success")
    return redirect(url_for("firewall_status"))

@app.route("/ml-detection")
@login_required
def ml_detection():
    """MLF Academic View: Scikit-learn Isolation Forest model inspection and live test."""
    return render_template("ml_detection.html")

# ============================================================
# 3. TABLEAU / DAV INTEGRATION ROUTES
# ============================================================

@app.route("/tableau")
@login_required
def tableau_view():
    """DAV Academic View: Tableau integration instructions and schema documentation."""
    return render_template("tableau.html")

@app.route("/export-tableau-csv")
@login_required
def export_tableau_csv():
    """
    DAV Subject: Safe CSV export for Tableau.
    Omits passwords, password hashes, and sensitive personal information.
    Includes anonymized identifiers, risk scores, and hourly metrics.
    """
    logs = LoginLog.query.order_by(LoginLog.timestamp.asc()).all()

    # Build safe data structure
    records = []
    for log in logs:
        records.append({
            "log_id": log.id,
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "",
            "login_hour": log.timestamp.hour if log.timestamp else 0,
            "anonymized_user": anonymize_email(log.email_attempted),
            "success_flag": 1 if log.success else 0,
            "failed_attempt_count": log.failed_attempt_count,
            "risk_score": round(log.risk_score, 3),
            "security_status": log.status
        })

    # If no logs exist yet, provide representative demo rows so Tableau opens with clean columns
    if not records:
        records = [
            {
                "log_id": 1,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "login_hour": 14,
                "anonymized_user": "demo***r@college.edu",
                "success_flag": 1,
                "failed_attempt_count": 0,
                "risk_score": 0.08,
                "security_status": "SUCCESS"
            }
        ]

    df = pd.DataFrame(records)
    csv_output = io.StringIO()
    df.to_csv(csv_output, index=False)

    # Save a physical copy to exports folder as required by project structure
    export_dir = os.path.join(os.path.dirname(__file__), "exports")
    os.makedirs(export_dir, exist_ok=True)
    csv_path = os.path.join(export_dir, "tableau_login_data.csv")
    df.to_csv(csv_path, index=False)

    # Return as downloadable browser file attachment
    response = make_response(csv_output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=tableau_login_data.csv"
    response.headers["Content-type"] = "text/csv"
    return response

# ============================================================
# 4. USER PROFILE & ALERT TESTING ROUTES
# ============================================================

@app.route("/profile")
@login_required
def profile():
    """User profile and credential security overview."""
    user = User.query.get(session["user_id"])
    return render_template("profile.html", user=user)

@app.route("/test-email", methods=["POST"])
@login_required
def test_email_dispatch():
    """Manual dispatch of a mock security alert email to verify SMTP."""
    user = User.query.get(session["user_id"])
    client_ip = firewall.get_client_ip()
    user_agent = request.headers.get("User-Agent", "Test Browser")

    success = send_security_alert_email(
        recipient_email=user.email,
        recipient_name=user.full_name,
        failed_count=3,
        ip_address=client_ip,
        user_agent=user_agent
    )
    if success:
        flash(f"Success! Mock security alert email sent to {user.email}.", "success")
    else:
        flash("Email dispatch failed or SMTP credentials not configured in .env. Check console logs.", "warning")
    return redirect(url_for("profile"))

@app.route("/test-whatsapp", methods=["POST"])
@login_required
def test_whatsapp_dispatch():
    """Manual dispatch of a mock WhatsApp security alert to verify API."""
    user = User.query.get(session["user_id"])
    client_ip = firewall.get_client_ip()

    success = send_whatsapp_security_alert(
        recipient_number=user.whatsapp_number,
        failed_count=3,
        ip_address=client_ip
    )
    if success:
        flash(f"Success! Mock WhatsApp security alert sent to {user.whatsapp_number}.", "success")
    else:
        flash("WhatsApp dispatch failed or API credentials not configured in .env. Check console logs.", "warning")
    return redirect(url_for("profile"))

# ============================================================
# INITIALIZATION & SEEDING UTILITY
# ============================================================

def initialize_database():
    """Creates database tables and seeds initial demo account if empty."""
    with app.app_context():
        db.create_all()
        # Seed initial demo student user if database is new
        if User.query.count() == 0:
            demo_user = User(
                full_name="Tejas Student (TY AIML)",
                email="student@college.edu",
                whatsapp_number="+919876543210"
            )
            demo_user.set_password("Student@123")
            db.session.add(demo_user)
            db.session.commit()
            print("[+] Initialized database with demo user: student@college.edu / Student@123")

# Initialize database on startup
initialize_database()

if __name__ == "__main__":
    print("[*] SecureLogin AI Server starting on http://127.0.0.1:5000 ...")
    app.run(debug=True, port=5000)

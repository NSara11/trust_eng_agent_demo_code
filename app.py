"""
Vulnerable Flask Application — AI-SSDLC Test Target
====================================================
Intentionally contains flaws across multiple categories:

  SAST  S1: SQL injection via string formatting (CWE-89)
  SAST  S2: OS command injection via shell=True (CWE-78)
  SAST  S3: Reflected XSS via Markup() bypass (CWE-79)

  Privacy / DT&P:
  A1  — SSN, biometric, DOB, racial origin collected without minimisation
  A2  — No consent checkbox, no privacy-policy link
  A3  — No cookie consent banner
  A4  — Analytics loads unconditionally (not opt-in)
  A6  — Outbound HTTP (not HTTPS) to third party
  A7  — Passwords stored in plaintext; private key in source
  A10 — PII (email, SSN, password) written to logs
  A11 — Hardcoded AWS key; no CSRF protection; no CSP; DEBUG=True
  A12 — Raw exception returned to client; stack trace in response
  A13 — Stripe/SendGrid integration without DPA reference
  B3  — Race/ethnicity filter in query without justification
  B8  — Rate limiting explicitly disabled; no CAPTCHA
  B13 — Session permanence enabled; session flag set from request; no MFA
"""
from __future__ import annotations

import os
import subprocess
import sqlite3
import logging

from flask import Flask, request, jsonify, session, render_template_string
from markupsafe import Markup

# ── A11 / A7: hardcoded credentials and private key material ─────────────────
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"            # CWE-798
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY     = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
SENDGRID_API_KEY      = "SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ.abc123def456"
DB_PASSWORD           = "Sup3rS3cr3tP@ssw0rd!"           # CWE-256

# ── A12: DEBUG=True exposes stack traces ──────────────────────────────────────
DEBUG = True

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29YQDA21mVSPAU
njMGNg5LdOJRHfNwPEfCDFh5DxcBtPBMEECr7RtpWPQ2C4/SJzDzGDmn8GnG8Bx4
EXAMPLE_KEY_CONTENT_NOT_REAL
-----END RSA PRIVATE KEY-----"""

# ── A13: third-party integrations — no DPA/sub-processor reference ────────────
import stripe   # noqa: E402  (import after credentials defined)
import sendgrid

stripe.api_key = STRIPE_SECRET_KEY

app = Flask(__name__)
app.secret_key = "hardcoded_flask_secret_12345"   # CWE-798

# ── B8: rate limiting explicitly disabled ─────────────────────────────────────
RATE_LIMIT_ENABLED = False   # never throttle — "too much friction"

# ── B13: permanent sessions with no expiry ───────────────────────────────────
app.config["PERMANENT_SESSION_LIFETIME"] = None
# session.permanent = True set per-request below

log = logging.getLogger(__name__)


def get_db():
    return sqlite3.connect("users.db")


# ─────────────────────────────────────────────────────────────────────────────
# SAST S1: SQL injection
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/user/search")
def user_search():
    """SAST S1 — SQL injection via f-string query (CWE-89)."""
    username = request.args.get("username", "")
    db = get_db()
    # VULNERABLE: user input concatenated directly into SQL
    query = f"SELECT * FROM users WHERE username = '{username}'"
    results = db.execute(query).fetchall()
    return jsonify({"users": [dict(r) for r in results]})


# ─────────────────────────────────────────────────────────────────────────────
# SAST S2: OS command injection
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/admin/ping")
def admin_ping():
    """SAST S2 — Command injection via shell=True (CWE-78)."""
    host = request.args.get("host", "localhost")
    # VULNERABLE: shell=True with user-controlled input
    output = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return output.stdout


# ─────────────────────────────────────────────────────────────────────────────
# SAST S3: Reflected XSS
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/greet")
def greet():
    """SAST S3 — Reflected XSS via Markup() unescaped injection (CWE-79)."""
    name = request.args.get("name", "Guest")
    # VULNERABLE: wrapping user input in Markup() disables auto-escaping
    return render_template_string(
        "<h1>Hello {{ name }}!</h1>",
        name=Markup(name),
    )


# ─────────────────────────────────────────────────────────────────────────────
# A1: Excessive PII collection (SSN, biometric, race/ethnicity, DOB)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register():
    """
    Collects government IDs, biometric, special-category data — far beyond
    what a standard registration requires (A1 violation).
    """
    data = request.json or {}

    first_name          = data.get("first_name")
    last_name           = data.get("last_name")
    email               = data.get("email")
    dob                 = data.get("dob")            # A1 — DOB without justification
    ssn                 = data.get("ssn")            # A1 — government ID
    national_id         = data.get("national_id")   # A1 — national identity
    passport_no         = data.get("passport_no")
    biometric_hash      = data.get("biometric")     # A1 CRITICAL — biometric
    facial_recognition  = data.get("facial_recog")  # A1 CRITICAL — biometric
    race                = data.get("race")           # Art. 9 special-category
    ethnicity           = data.get("ethnicity")      # Art. 9 special-category
    religion            = data.get("religion")       # Art. 9 special-category
    political_opinion   = data.get("political")      # Art. 9 special-category
    health_data         = data.get("health_data")    # Art. 9 special-category
    credit_card         = data.get("credit_card")
    bank_account        = data.get("bank_account")

    # A7: password stored in plaintext — no hashing
    password            = data.get("password")

    # A10: PII written directly to application log
    log.info(
        "register: email=%s ssn=%s password=%s credit_card=%s",
        email, ssn, password, credit_card,
    )

    db = get_db()
    # A7: storing plaintext password column as TEXT
    db.execute(
        "INSERT INTO users (email, password TEXT, ssn, dob, biometric, race) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (email, password, ssn, dob, biometric_hash, race),
    )
    db.commit()

    # B13: session flag set directly from request data
    session["is_admin"] = request.json.get("is_admin", False)
    session.permanent = True   # B13 — permanent session, no expiry

    # A13: sending PII to SendGrid without data-minimisation
    import requests as _req
    _req.post(
        "http://api.sendgrid.com/v3/mail/send",   # A6 — http not https
        headers={"Authorization": f"Bearer {SENDGRID_API_KEY}"},
        json={"to": email, "subject": "Welcome", "body": f"Hi {first_name}"},
    )

    return jsonify({"status": "registered"})


# ─────────────────────────────────────────────────────────────────────────────
# A12: Raw exception / stack trace returned to client
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/profile/<user_id>")
def profile(user_id):
    """A12 — exception information leaked in API response (CWE-209)."""
    try:
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return jsonify(dict(row))
    except Exception as e:
        # VULNERABLE: raw exception string returned to client
        return jsonify({"error": str(e), "trace": __import__("traceback").format_exc()}), 500


# ─────────────────────────────────────────────────────────────────────────────
# B3: Anti-discrimination — demographic filter without justification
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/offers")
def offers():
    """B3 — race/ethnicity/gender used in query filter (CWE-359)."""
    race      = request.args.get("race")
    ethnicity = request.args.get("ethnicity")
    gender    = request.args.get("gender")
    sex       = request.args.get("sex")

    db = get_db()
    # VULNERABLE: demographic fields used as query discriminators
    rows = db.execute(
        "SELECT * FROM offers WHERE race = ? AND ethnicity = ? AND sex = ?",
        (race, ethnicity, sex),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


# ─────────────────────────────────────────────────────────────────────────────
# A6: Insecure outbound HTTP to Stripe — plaintext payment data
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/charge", methods=["POST"])
def charge():
    """A6/A13 — outbound HTTP to payment processor; no TLS (CWE-319)."""
    import requests as _req
    _req.post(
        "http://api.stripe.com/v1/charges",   # http:// — not encrypted
        data={"amount": request.form.get("amount"), "currency": "usd"},
        headers={"Authorization": f"Bearer {STRIPE_SECRET_KEY}"},
    )
    return jsonify({"charged": True})


# ─────────────────────────────────────────────────────────────────────────────
# A11: No CSRF, no CSP, debug mode
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)  # A11/A12 — debug=True

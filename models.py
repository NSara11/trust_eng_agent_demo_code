"""
models.py — SQLAlchemy data models
===================================
A1  — excessive PII fields (biometric, government IDs, health, special-category)
A7  — password column is VARCHAR/TEXT (plaintext storage)
A9  — no created_at / retention / TTL fields; no audit logging hooks
A11 — no CSRF token model; no consent fields
B11 — no KYC / age-verification field
B19 — no consent_given, consent_at, legal_basis, processing_basis columns
"""
from __future__ import annotations

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id              = db.Column(db.Integer, primary_key=True)
    email           = db.Column(db.String(254), unique=True, nullable=False)

    # A7: password stored as plaintext string — CWE-256
    password        = db.Column(db.String(128), nullable=False)      # PASSWORD TEXT — no hash

    # A1: excessive PII — government identifiers
    ssn             = db.Column(db.String(11))                       # Social Security Number
    national_id     = db.Column(db.String(20))                       # National ID / Aadhaar
    passport_no     = db.Column(db.String(20))
    dob             = db.Column(db.Date)                             # Date of birth

    # A1 CRITICAL: biometric data stored directly in DB
    biometric_hash  = db.Column(db.LargeBinary)                      # fingerprint
    facial_recog    = db.Column(db.LargeBinary)                      # facial recognition template
    iris_scan       = db.Column(db.LargeBinary)                      # iris scan

    # Art. 9 special-category data — requires explicit consent and strict legal basis
    race            = db.Column(db.String(64))
    ethnicity       = db.Column(db.String(64))
    religion        = db.Column(db.String(64))
    political_opinion = db.Column(db.String(256))
    health_data     = db.Column(db.Text)
    sexual_orientation = db.Column(db.String(64))

    # Financial
    credit_card     = db.Column(db.String(19))                       # raw PAN — not tokenised
    bank_account    = db.Column(db.String(34))                       # IBAN in plaintext

    # Contact
    phone           = db.Column(db.String(20))
    address         = db.Column(db.Text)
    city            = db.Column(db.String(100))
    pincode         = db.Column(db.String(10))
    country         = db.Column(db.String(64))

    # B19 MISSING: no consent_given, consent_at, legal_basis, consent_version
    # A9  MISSING: no created_at, updated_at, retention TTL, soft-delete flag


class PaymentTransaction(db.Model):
    __tablename__ = "transactions"

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey("users.id"))
    amount      = db.Column(db.Numeric(10, 2))

    # B23/B26: no velocity/risk scoring fields; no fraud-flag column
    # B25: no AML/sanctions screening flag
    card_number = db.Column(db.String(19))   # raw card number — not tokenised


class AuditEvent(db.Model):
    """Stub — A9 violation: no actual audit logging is wired up in app.py."""
    __tablename__ = "audit_events"

    id        = db.Column(db.Integer, primary_key=True)
    # A9: no actor, no entity_id, no action, no timestamp columns defined

"""
config.py — Application configuration
=======================================
A11 — hardcoded API keys and secrets (CWE-798)
A12 — DEBUG=True in config file (CWE-209)
A4  — no privacy-by-default flags; analytics enabled unconditionally
A6  — no HSTS / HTTPS enforcement
B8  — rate limiting disabled
"""

# ── A11: hardcoded secrets ────────────────────────────────────────────────────
SECRET_KEY              = "my_super_secret_flask_key_12345"
DATABASE_URL            = "sqlite:///users.db"
DB_PASSWORD             = "admin123"                         # CWE-256

# AWS credentials in config
AWS_ACCESS_KEY_ID       = "AKIAIOSFODNN7EXAMPLE"             # CWE-798
AWS_SECRET_ACCESS_KEY   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_DEFAULT_REGION      = "us-east-1"

# Stripe live secret key
STRIPE_SECRET_KEY       = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
STRIPE_WEBHOOK_SECRET   = "whsec_xxxxxxxxxxxxxxxxxxx"

# SendGrid
SENDGRID_API_KEY        = "SG.aBcDeFgHiJkLmNoPqRsTuVwXyZ.abc123def456"
SENDGRID_FROM_EMAIL     = "noreply@myapp.com"

# Twilio
TWILIO_ACCOUNT_SID      = "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
TWILIO_AUTH_TOKEN       = "your_auth_token_here"

# Mixpanel / Amplitude — loads unconditionally (A4 violation)
MIXPANEL_TOKEN          = "abcdef1234567890abcdef1234567890"
AMPLITUDE_API_KEY       = "1234567890abcdef"

# ── A12: DEBUG mode ───────────────────────────────────────────────────────────
DEBUG                   = True                               # CWE-209 — stack traces exposed
TESTING                 = True

# ── A6: no HTTPS enforcement ──────────────────────────────────────────────────
# PREFERRED_URL_SCHEME is not set → no HSTS enforcement
# SERVER_NAME              = None

# ── B8: rate limiting disabled ────────────────────────────────────────────────
RATE_LIMIT_ENABLED      = False
RATELIMIT_DEFAULT       = 0    # 0 = unlimited

# ── B13: permanent sessions — no expiry ───────────────────────────────────────
PERMANENT_SESSION_LIFETIME = None

# ── A4: analytics enabled by default (no opt-in) ─────────────────────────────
ANALYTICS_ENABLED       = True   # should default False
TRACKING_ENABLED        = True   # should default False

"""Regex patterns for extracting secrets, endpoints, and URLs from JavaScript."""

import re

from jsminer.core.models import SecretType, Severity

# Type alias for pattern tuple: (pattern, secret_type, severity, confidence)
PatternDef = tuple[re.Pattern[str], SecretType, Severity, float]


# =============================================================================
# API KEY PATTERNS
# =============================================================================

API_KEY_PATTERNS: list[PatternDef] = [
    # AWS
    (
        re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        SecretType.AWS_ACCESS_KEY,
        Severity.CRITICAL,
        0.95,
    ),
    (
        re.compile(
            r"(?:aws.?secret|secret.?key)[\"'`]?\s*[:=]\s*[\"'`]([A-Za-z0-9/+=]{40})[\"'`]",
            re.IGNORECASE,
        ),
        SecretType.AWS_SECRET_KEY,
        Severity.CRITICAL,
        0.9,
    ),
    # Google
    (
        re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        SecretType.GCP_API_KEY,
        Severity.HIGH,
        0.95,
    ),
    (
        re.compile(
            r"(?:google|gcp|firebase).?api.?key[\"'`]?\s*[:=]\s*[\"'`]([A-Za-z0-9_-]{39})[\"'`]",
            re.IGNORECASE,
        ),
        SecretType.GOOGLE_API_KEY,
        Severity.HIGH,
        0.85,
    ),
    # Stripe
    (
        re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
        SecretType.STRIPE_SECRET,
        Severity.CRITICAL,
        0.95,
    ),
    (
        re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
        SecretType.STRIPE_KEY,
        Severity.MEDIUM,
        0.95,
    ),
    (
        re.compile(r"sk_test_[0-9a-zA-Z]{24,}"),
        SecretType.STRIPE_SECRET,
        Severity.LOW,
        0.95,
    ),
    # GitHub
    (
        re.compile(r"ghp_[0-9a-zA-Z]{36}"),
        SecretType.GITHUB_TOKEN,
        Severity.HIGH,
        0.95,
    ),
    (
        re.compile(r"gho_[0-9a-zA-Z]{36}"),
        SecretType.GITHUB_TOKEN,
        Severity.HIGH,
        0.95,
    ),
    (
        re.compile(r"ghu_[0-9a-zA-Z]{36}"),
        SecretType.GITHUB_TOKEN,
        Severity.HIGH,
        0.95,
    ),
    # Slack
    (
        re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"),
        SecretType.SLACK_TOKEN,
        Severity.HIGH,
        0.95,
    ),
    (
        re.compile(
            r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"
        ),
        SecretType.SLACK_WEBHOOK,
        Severity.HIGH,
        0.95,
    ),
    # Discord
    (
        re.compile(r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+"),
        SecretType.DISCORD_WEBHOOK,
        Severity.MEDIUM,
        0.95,
    ),
    (
        re.compile(r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"),
        SecretType.DISCORD_TOKEN,
        Severity.HIGH,
        0.8,
    ),
    # Twilio
    (
        re.compile(r"SK[0-9a-fA-F]{32}"),
        SecretType.TWILIO_KEY,
        Severity.HIGH,
        0.85,
    ),
    # SendGrid
    (
        re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
        SecretType.SENDGRID_KEY,
        Severity.HIGH,
        0.95,
    ),
    # Mailgun
    (
        re.compile(r"key-[0-9a-zA-Z]{32}"),
        SecretType.MAILGUN_KEY,
        Severity.HIGH,
        0.8,
    ),
    # Mailchimp
    (
        re.compile(r"[0-9a-f]{32}-us[0-9]{1,2}"),
        SecretType.MAILCHIMP_KEY,
        Severity.HIGH,
        0.8,
    ),
    # Facebook
    (
        re.compile(r"EAACEdEose0cBA[0-9A-Za-z]+"),
        SecretType.FACEBOOK_TOKEN,
        Severity.HIGH,
        0.9,
    ),
    # Twitter
    (
        re.compile(
            r"(?:twitter|tw).?(?:api|consumer|access).?(?:key|token|secret)[\"'`]?\s*[:=]\s*[\"'`]([A-Za-z0-9]{25,50})[\"'`]",
            re.IGNORECASE,
        ),
        SecretType.TWITTER_TOKEN,
        Severity.HIGH,
        0.7,
    ),
    # Generic API key patterns
    (
        re.compile(
            r"(?:api[_-]?key|apikey|api[_-]?secret)[\"'`]?\s*[:=]\s*[\"'`]([A-Za-z0-9_-]{20,64})[\"'`]",
            re.IGNORECASE,
        ),
        SecretType.API_KEY_GENERIC,
        Severity.MEDIUM,
        0.6,
    ),
]


# =============================================================================
# SECRET PATTERNS
# =============================================================================

SECRET_PATTERNS: list[PatternDef] = [
    # JWT Tokens
    (
        re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
        SecretType.JWT_TOKEN,
        Severity.HIGH,
        0.95,
    ),
    # Bearer tokens
    (
        re.compile(r"[Bb]earer\s+[A-Za-z0-9_-]{20,}"),
        SecretType.BEARER_TOKEN,
        Severity.HIGH,
        0.8,
    ),
    # Basic auth (base64)
    (
        re.compile(r"[Bb]asic\s+[A-Za-z0-9+/=]{20,}"),
        SecretType.BASIC_AUTH,
        Severity.HIGH,
        0.8,
    ),
    # Private keys
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        SecretType.PRIVATE_KEY,
        Severity.CRITICAL,
        0.95,
    ),
    # MongoDB connection strings
    (
        re.compile(r"mongodb(?:\+srv)?://[^\s\"'`<>]+"),
        SecretType.MONGODB_URI,
        Severity.HIGH,
        0.9,
    ),
    # PostgreSQL connection strings
    (
        re.compile(r"postgres(?:ql)?://[^\s\"'`<>]+"),
        SecretType.POSTGRES_URI,
        Severity.HIGH,
        0.9,
    ),
    # MySQL connection strings
    (
        re.compile(r"mysql://[^\s\"'`<>]+"),
        SecretType.MYSQL_URI,
        Severity.HIGH,
        0.9,
    ),
    # Redis connection strings
    (
        re.compile(r"redis://[^\s\"'`<>]+"),
        SecretType.REDIS_URI,
        Severity.HIGH,
        0.9,
    ),
    # Password patterns
    (
        re.compile(
            r"(?:password|passwd|pwd)[\"'`]?\s*[:=]\s*[\"'`]([^\"'`\s]{8,64})[\"'`]", re.IGNORECASE
        ),
        SecretType.PASSWORD,
        Severity.HIGH,
        0.6,
    ),
    # Secret patterns
    (
        re.compile(
            r"(?:secret|token|auth)[\"'`]?\s*[:=]\s*[\"'`]([A-Za-z0-9_-]{16,64})[\"'`]",
            re.IGNORECASE,
        ),
        SecretType.SECRET_GENERIC,
        Severity.MEDIUM,
        0.5,
    ),
]


# =============================================================================
# ENDPOINT PATTERNS
# =============================================================================

ENDPOINT_PATTERNS: list[re.Pattern[str]] = [
    # Absolute API paths
    re.compile(r"[\"'`](/api/v?\d*/[a-zA-Z0-9_/-]+)[\"'`]"),
    re.compile(r"[\"'`](/v\d+/[a-zA-Z0-9_/-]+)[\"'`]"),
    # Relative paths
    re.compile(r"[\"'`](/[a-zA-Z0-9_-]+/[a-zA-Z0-9_/-]+)[\"'`]"),
    # Common API endpoints
    re.compile(
        r"[\"'`](/(?:admin|auth|user|users|login|logout|register|signup|reset|verify|confirm|account|profile|settings|dashboard|api|graphql|webhook|callback|oauth|token|upload|download|export|import|search|query)[a-zA-Z0-9_/-]*)[\"'`]",
        re.IGNORECASE,
    ),
    # REST-like paths with IDs
    re.compile(r"[\"'`](/[a-zA-Z0-9_-]+/:\w+(?:/[a-zA-Z0-9_-]+)*)[\"'`]"),
    re.compile(r"[\"'`](/[a-zA-Z0-9_-]+/\{[^}]+\}(?:/[a-zA-Z0-9_-]+)*)[\"'`]"),
    # Fetch/axios patterns
    re.compile(
        r"(?:fetch|axios|get|post|put|delete|patch)\s*\(\s*[\"'`]([^\"'`]+)[\"'`]", re.IGNORECASE
    ),
    # URL patterns in code
    re.compile(
        r"(?:url|endpoint|path|route|href|src)\s*[:=]\s*[\"'`](/[^\"'`\s]+)[\"'`]", re.IGNORECASE
    ),
]


# =============================================================================
# URL PATTERNS
# =============================================================================

URL_PATTERNS: list[re.Pattern[str]] = [
    # Full URLs
    re.compile(
        r"https?://[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+(?::[0-9]+)?(?:/[^\s\"'`<>]*)?"
    ),
    # Internal/staging/dev URLs
    re.compile(
        r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|staging|dev|test|uat|qa|preprod|admin|api|cdn|static)(?::[0-9]+)?[^\s\"'`<>]*",
        re.IGNORECASE,
    ),
    # IP addresses with ports
    re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::[0-9]+)?[^\s\"'`<>]*"),
    # Subdomains patterns
    re.compile(
        r"https?://[a-zA-Z0-9-]+\.(?:internal|local|corp|intranet|staging|dev|test)\.[a-zA-Z]{2,}[^\s\"'`<>]*",
        re.IGNORECASE,
    ),
]


# =============================================================================
# CREDENTIAL PATTERNS
# =============================================================================

CREDENTIAL_PATTERNS: list[PatternDef] = [
    # Hardcoded credentials
    (
        re.compile(
            r"(?:admin|root|user|guest)[\"'`]?\s*[:=]\s*[\"'`]([^\"'`\s]{4,32})[\"'`]",
            re.IGNORECASE,
        ),
        SecretType.PASSWORD,
        Severity.HIGH,
        0.5,
    ),
    # Email:password patterns
    (
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[:;][^\s\"'`]{4,32}"),
        SecretType.PASSWORD,
        Severity.HIGH,
        0.7,
    ),
]

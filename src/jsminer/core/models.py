"""Data models for JSMiner."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class FindingType(str, Enum):
    """Types of findings."""

    ENDPOINT = "endpoint"
    API_KEY = "api_key"
    SECRET = "secret"
    URL = "url"
    COMMENT = "comment"
    CREDENTIAL = "credential"


class SecretType(str, Enum):
    """Types of secrets/API keys."""

    # Cloud providers
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GCP_API_KEY = "gcp_api_key"
    AZURE_KEY = "azure_key"

    # Payment
    STRIPE_KEY = "stripe_key"
    STRIPE_SECRET = "stripe_secret"
    PAYPAL_KEY = "paypal_key"

    # Social/Auth
    GOOGLE_API_KEY = "google_api_key"
    GOOGLE_OAUTH = "google_oauth"
    FACEBOOK_TOKEN = "facebook_token"
    TWITTER_TOKEN = "twitter_token"
    GITHUB_TOKEN = "github_token"
    SLACK_TOKEN = "slack_token"
    SLACK_WEBHOOK = "slack_webhook"
    DISCORD_TOKEN = "discord_token"
    DISCORD_WEBHOOK = "discord_webhook"

    # Messaging
    TWILIO_KEY = "twilio_key"
    SENDGRID_KEY = "sendgrid_key"
    MAILGUN_KEY = "mailgun_key"
    MAILCHIMP_KEY = "mailchimp_key"

    # Database
    MONGODB_URI = "mongodb_uri"
    POSTGRES_URI = "postgres_uri"
    MYSQL_URI = "mysql_uri"
    REDIS_URI = "redis_uri"

    # Auth tokens
    JWT_TOKEN = "jwt_token"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    API_KEY_GENERIC = "api_key_generic"

    # Other
    PRIVATE_KEY = "private_key"
    SSH_KEY = "ssh_key"
    PASSWORD = "password"
    SECRET_GENERIC = "secret_generic"


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    """A single finding from JavaScript analysis."""

    type: FindingType
    value: str
    secret_type: SecretType | None = None
    severity: Severity = Severity.INFO
    source_file: str
    line_number: int | None = None
    context: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)

    def __hash__(self) -> int:
        return hash((self.type, self.value, self.source_file))


class JSFile(BaseModel):
    """Represents a JavaScript file."""

    url: str
    content: str | None = None
    size: int = 0
    status_code: int | None = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.content is not None and self.status_code == 200


class ScanResult(BaseModel):
    """Results from scanning a target."""

    target: str
    scan_time: datetime = Field(default_factory=datetime.now)
    js_files: list[JSFile] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def endpoints(self) -> list[Finding]:
        return [f for f in self.findings if f.type == FindingType.ENDPOINT]

    @property
    def api_keys(self) -> list[Finding]:
        return [f for f in self.findings if f.type == FindingType.API_KEY]

    @property
    def secrets(self) -> list[Finding]:
        return [f for f in self.findings if f.type == FindingType.SECRET]

    @property
    def urls(self) -> list[Finding]:
        return [f for f in self.findings if f.type == FindingType.URL]

    @property
    def credentials(self) -> list[Finding]:
        return [f for f in self.findings if f.type == FindingType.CREDENTIAL]

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def stats(self) -> dict[str, int]:
        return {
            "js_files": len(self.js_files),
            "js_files_success": len([f for f in self.js_files if f.success]),
            "total_findings": len(self.findings),
            "endpoints": len(self.endpoints),
            "api_keys": len(self.api_keys),
            "secrets": len(self.secrets),
            "urls": len(self.urls),
            "credentials": len(self.credentials),
            "critical": len(self.critical_findings),
            "high": len(self.high_findings),
        }

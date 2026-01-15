# JSMiner

JavaScript security mining tool for bug bounty and security assessments. Extract API endpoints, API keys, secrets, and sensitive URLs from JavaScript files.

## Features

- **Endpoint Extraction**: Find hidden API endpoints, admin panels, and internal routes
- **Secret Detection**: Detect 40+ types of API keys and secrets (AWS, Stripe, GitHub, etc.)
- **URL Discovery**: Find internal, staging, and development URLs
- **Async Architecture**: Fast concurrent scanning with aiohttp
- **Rich CLI**: Beautiful terminal output with progress indicators
- **Multiple Outputs**: JSON and HTML report export
- **Flexible Input**: Single URL, URL list, or local files

## Installation

### Quick Install (from GitHub)

```bash
pip install git+https://github.com/cereZ23/jsminer.git
```

### Using Virtual Environment (Recommended)

```bash
# Clone the repository
git clone https://github.com/cereZ23/jsminer.git
cd jsminer

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate  # Linux/macOS
# or
.venv\Scripts\activate     # Windows

# Install the package
pip install -e .

# Run jsminer
jsminer --help
```

### Using Docker

```bash
# Build the image
docker build -t jsminer .

# Run with a URL
docker run --rm -v $(pwd)/output:/app/output jsminer -u https://example.com -o /app/output/report.html
```

## Usage

```bash
# Analyze a website (crawls for JS files)
jsminer -u https://example.com -o report.html

# Analyze a JavaScript file directly
jsminer -u https://example.com/static/app.js -o report.json

# Analyze multiple URLs from a file
jsminer -l urls.txt -o report.html

# Analyze a local JavaScript file
jsminer -f ./app.bundle.js -o report.json

# Verbose output with custom settings
jsminer -u https://example.com -v --concurrent 20 --delay 0.2 -o report.html
```

## Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Single URL to analyze (webpage or .js file) |
| `-l, --list` | File containing list of URLs (one per line) |
| `-f, --file` | Local JavaScript file to analyze |
| `-o, --output` | Output file (JSON or HTML based on extension) |
| `--json` | Force JSON output format |
| `-c, --concurrent` | Maximum concurrent requests (default: 10) |
| `--delay` | Delay between requests in seconds (default: 0.5) |
| `--timeout` | Request timeout in seconds (default: 30) |
| `--no-endpoints` | Disable endpoint extraction |
| `--no-secrets` | Disable secret/API key extraction |
| `--no-urls` | Disable URL extraction |
| `-v, --verbose` | Verbose output |

## Detected Secrets

JSMiner detects 40+ types of secrets and API keys:

### Cloud Providers
- AWS Access Keys & Secret Keys
- Google Cloud API Keys
- Azure Keys

### Payment
- Stripe Live/Test Keys
- PayPal Keys

### Social & Auth
- GitHub Tokens (PAT, OAuth, App)
- Slack Tokens & Webhooks
- Discord Tokens & Webhooks
- Facebook Access Tokens
- Twitter API Keys

### Messaging
- Twilio API Keys
- SendGrid API Keys
- Mailgun API Keys
- Mailchimp API Keys

### Databases
- MongoDB Connection Strings
- PostgreSQL Connection Strings
- MySQL Connection Strings
- Redis Connection Strings

### Auth Tokens
- JWT Tokens
- Bearer Tokens
- Basic Auth Credentials
- Private Keys (RSA, EC, SSH)

## Output

### HTML Report
Interactive HTML report with:
- Summary statistics
- Severity-based color coding
- Sortable findings table
- Source file links

### JSON Report
Machine-readable JSON with:
- Complete findings data
- Source file mapping
- Confidence scores
- Context snippets

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/

# Type checking
mypy src/jsminer
```

## License

GPL-2.0


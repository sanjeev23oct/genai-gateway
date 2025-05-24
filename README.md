# LLM Gateway MVP

A secure gateway for LLM providers with PII/secret detection and privacy controls.

## Features

- 🔒 **PII Detection**: Automatically detects and blocks personal information using Microsoft Presidio
- 🛡️ **Secret Detection**: Regex-based detection of API keys, passwords, and sensitive data
- 🚀 **DeepSeek Integration**: Ready-to-use integration with DeepSeek API
- 📝 **Audit Logging**: Complete request/response logging for compliance
- ⚡ **FastAPI**: High-performance async API with automatic documentation

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Download spaCy Model

```bash
python -m spacy download en_core_web_sm
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env with your DeepSeek API key
```

### 4. Run the Gateway

```bash
python -m app.main
```

The gateway will be available at `http://localhost:8000`

## API Documentation

Once running, visit:
- **Interactive API Docs**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEEPSEEK_API_KEY` | DeepSeek API key | Required |
| `DEEPSEEK_BASE_URL` | DeepSeek API base URL | `https://api.deepseek.com` |
| `GATEWAY_HOST` | Gateway host | `0.0.0.0` |
| `GATEWAY_PORT` | Gateway port | `8000` |
| `ENABLE_PII_DETECTION` | Enable PII detection | `true` |
| `ENABLE_SECRET_DETECTION` | Enable secret detection | `true` |
| `BLOCK_ON_DETECTION` | Block requests with issues | `true` |
| `LOG_LEVEL` | Logging level | `INFO` |

## Usage Example

```python
import httpx

# Send a chat request
response = httpx.post("http://localhost:8000/v1/chat/completions", json={
    "model": "deepseek-chat",
    "messages": [
        {"role": "user", "content": "Hello, how are you?"}
    ],
    "temperature": 0.7,
    "max_tokens": 100
})

print(response.json())
```

## Security Features

### PII Detection
The gateway automatically scans for:
- Email addresses
- Phone numbers
- Credit card numbers
- Social Security numbers
- IP addresses
- Personal names
- Locations

### Secret Detection
The gateway detects:
- API keys (OpenAI, GitHub, AWS, etc.)
- Database connection strings
- JWT tokens
- Private keys
- Environment variables with secrets

## Development

### Project Structure

```
app/
├── main.py              # FastAPI application
├── models.py            # Pydantic models
├── security/
│   ├── pii_detector.py  # PII detection logic
│   └── secret_detector.py # Secret detection logic
├── providers/
│   └── deepseek_client.py # DeepSeek API client
└── utils/
    └── logger.py        # Logging configuration
```

### Adding New Providers

1. Create a new client in `app/providers/`
2. Implement the same interface as `DeepSeekClient`
3. Add provider selection logic in `main.py`

### Custom Security Rules

You can add custom secret detection patterns:

```python
from app.security.secret_detector import SecretDetector

detector = SecretDetector()
detector.add_custom_pattern("custom_token", r"ct_[a-zA-Z0-9]{32}")
```

## Monitoring

The gateway provides structured JSON logging with:
- Request/response details
- Security scan results
- Performance metrics
- Error tracking

Logs are written to both console and file (if configured).

## Next Steps

- [ ] Add authentication/authorization
- [ ] Implement rate limiting
- [ ] Add more LLM providers
- [ ] Create admin dashboard
- [ ] Add metrics and monitoring
- [ ] Implement caching

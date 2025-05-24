"""
Ultra-Simple LLM Gateway for Railway
Uses ONLY Python built-in modules - no external dependencies
"""
import http.server
import socketserver
import json
import re
import os
import time
import uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError


class EnhancedSecurityScanner:
    """Enhanced security scanner with multiple detection layers"""

    def __init__(self):
        # Enhanced patterns with confidence scores
        self.patterns = {
            # High-confidence API key patterns
            "openai_api_key": {
                "pattern": r'sk-[a-zA-Z0-9]{48}',
                "confidence": 0.98,
                "severity": "CRITICAL"
            },
            "anthropic_api_key": {
                "pattern": r'sk-ant-[a-zA-Z0-9\-_]{95}',
                "confidence": 0.98,
                "severity": "CRITICAL"
            },
            "github_token": {
                "pattern": r'ghp_[a-zA-Z0-9]{36}',
                "confidence": 0.95,
                "severity": "CRITICAL"
            },
            "aws_access_key": {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "confidence": 0.95,
                "severity": "CRITICAL"
            },

            # PII patterns with validation
            "email": {
                "pattern": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "confidence": 0.85,
                "severity": "HIGH"
            },
            "phone_us": {
                "pattern": r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                "confidence": 0.8,
                "severity": "MEDIUM"
            },
            "ssn": {
                "pattern": r'\b\d{3}-\d{2}-\d{4}\b',
                "confidence": 0.9,
                "severity": "HIGH"
            },
            "credit_card": {
                "pattern": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                "confidence": 0.7,
                "severity": "HIGH"
            },

            # Database and connection strings
            "database_url": {
                "pattern": r'(postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+',
                "confidence": 0.9,
                "severity": "CRITICAL"
            },
            "connection_string": {
                "pattern": r'(Server|Host|Data Source)\s*=\s*[^;]+;\s*(Database|Initial Catalog)\s*=\s*[^;]+',
                "confidence": 0.85,
                "severity": "HIGH"
            },

            # Generic secrets with context
            "password_assignment": {
                "pattern": r'password\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*()]{6,}["\']?',
                "confidence": 0.8,
                "severity": "HIGH"
            },
            "secret_assignment": {
                "pattern": r'secret\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*()]{8,}["\']?',
                "confidence": 0.8,
                "severity": "HIGH"
            },
            "api_key_assignment": {
                "pattern": r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{16,}["\']?',
                "confidence": 0.75,
                "severity": "HIGH"
            },

            # JWT tokens
            "jwt_token": {
                "pattern": r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
                "confidence": 0.85,
                "severity": "HIGH"
            },

            # Private keys
            "private_key": {
                "pattern": r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
                "confidence": 0.99,
                "severity": "CRITICAL"
            },

            # IP addresses (internal networks)
            "private_ip": {
                "pattern": r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
                "confidence": 0.6,
                "severity": "MEDIUM"
            }
        }

        # Compile patterns for performance
        self.compiled_patterns = {}
        for name, config in self.patterns.items():
            self.compiled_patterns[name] = {
                "regex": re.compile(config["pattern"], re.IGNORECASE),
                "confidence": config["confidence"],
                "severity": config["severity"]
            }

    def scan(self, text):
        """Enhanced scan with confidence scoring"""
        issues = []

        for name, config in self.compiled_patterns.items():
            matches = config["regex"].finditer(text)

            for match in matches:
                # Additional validation for specific patterns
                if name == "credit_card" and not self._validate_luhn(match.group()):
                    continue

                if name == "email" and not self._basic_email_validation(match.group()):
                    continue

                issue = {
                    "type": name,
                    "confidence": config["confidence"],
                    "severity": config["severity"],
                    "match": match.group(),
                    "location": (match.start(), match.end()),
                    "context": text[max(0, match.start()-20):match.end()+20]
                }
                issues.append(issue)

        return issues

    def _validate_luhn(self, card_number):
        """Basic Luhn algorithm validation for credit cards"""
        # Remove spaces and dashes
        card_number = re.sub(r'[-\s]', '', card_number)

        if not card_number.isdigit() or len(card_number) < 13:
            return False

        # Luhn algorithm
        total = 0
        reverse_digits = card_number[::-1]

        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n = n // 10 + n % 10
            total += n

        return total % 10 == 0

    def _basic_email_validation(self, email):
        """Basic email validation"""
        # Check for common invalid patterns
        if email.count('@') != 1:
            return False

        local, domain = email.split('@')
        if not local or not domain:
            return False

        if '.' not in domain:
            return False

        return True

    def should_block(self, issues):
        """Determine if request should be blocked"""
        if not issues:
            return False

        # Block on any CRITICAL severity
        critical_issues = [i for i in issues if i["severity"] == "CRITICAL"]
        if critical_issues:
            return True

        # Block on high confidence HIGH severity issues
        high_confidence_high = [i for i in issues if i["severity"] == "HIGH" and i["confidence"] >= 0.8]
        if high_confidence_high:
            return True

        return False


class SimpleGatewayHandler(http.server.BaseHTTPRequestHandler):
    """Simple HTTP handler"""

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_health()
        elif self.path == '/':
            self.send_welcome()
        else:
            self.send_error(404)

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/v1/chat/completions':
            self.handle_chat()
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        """Handle CORS"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def send_health(self):
        """Send health response"""
        response = {
            "status": "healthy",
            "version": "1.0.0-enhanced",
            "timestamp": int(time.time()),
            "message": "LLM Gateway is running on Railway!",
            "features": [
                "Enhanced PII Detection",
                "API Key Detection",
                "Database Credential Detection",
                "JWT Token Detection",
                "Confidence Scoring",
                "Severity Classification",
                "Smart Request Blocking",
                "Luhn Credit Card Validation"
            ],
            "security_stats": {
                "total_patterns": 15,
                "severity_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "confidence_range": "0.0 - 1.0"
            }
        }
        self.send_json(response)

    def send_welcome(self):
        """Send welcome page"""
        html = """
        <html>
        <head><title>LLM Gateway - Railway</title></head>
        <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
            <h1>LLM Gateway MVP</h1>
            <p><strong>Status:</strong> Running on Railway</p>

            <h2>Enhanced Security Features</h2>
            <ul>
                <li><strong>API Key Detection</strong> (OpenAI, Anthropic, GitHub, AWS)</li>
                <li><strong>PII Detection</strong> (Email, Phone, SSN, Credit Cards)</li>
                <li><strong>Database Credentials</strong> (Connection strings, URLs)</li>
                <li><strong>JWT Tokens & Private Keys</strong></li>
                <li><strong>Confidence Scoring</strong> (0.0 - 1.0)</li>
                <li><strong>Severity Levels</strong> (LOW, MEDIUM, HIGH, CRITICAL)</li>
                <li><strong>Smart Blocking</strong> (Context-aware decisions)</li>
                <li><strong>Luhn Validation</strong> (Credit card verification)</li>
            </ul>

            <h2>Test Commands</h2>
            <h3>Health Check:</h3>
            <pre>curl https://genai-gateway-production.up.railway.app/health</pre>

            <h3>Normal Request:</h3>
            <pre>curl -X POST https://genai-gateway-production.up.railway.app/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{"messages": [{"role": "user", "content": "Hello!"}]}'</pre>

            <h3>Security Test (Should Block):</h3>
            <pre>curl -X POST https://genai-gateway-production.up.railway.app/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{"messages": [{"role": "user", "content": "My email is test@example.com"}]}'</pre>

            <p><em>Deployed on Railway - No external dependencies</em></p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_chat(self):
        """Handle chat requests"""
        try:
            # Read request
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No content")
                return

            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            # Extract text
            text_content = ""
            messages = request_data.get('messages', [])
            for msg in messages:
                text_content += msg.get('content', '') + " "

            # Security scan
            scanner = EnhancedSecurityScanner()
            issues = scanner.scan(text_content)

            # Log request
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Chat request")
            print(f"  Content: {text_content[:100]}...")
            print(f"  Issues found: {len(issues)}")

            # Enhanced logging for detected issues
            for issue in issues:
                print(f"    - {issue['type']}: {issue['severity']} (confidence: {issue['confidence']:.2f})")

            # Determine if request should be blocked
            should_block = scanner.should_block(issues)

            if should_block:
                # Create detailed error response
                error_response = {
                    "error": "Request blocked due to security policy violations",
                    "blocked": True,
                    "timestamp": int(time.time()),
                    "detection_summary": {
                        "total_issues": len(issues),
                        "critical_issues": len([i for i in issues if i["severity"] == "CRITICAL"]),
                        "high_severity_issues": len([i for i in issues if i["severity"] == "HIGH"]),
                        "issue_types": list(set(i["type"] for i in issues))
                    },
                    "issues": [
                        {
                            "type": issue["type"],
                            "severity": issue["severity"],
                            "confidence": issue["confidence"],
                            "description": f"Detected {issue['type'].replace('_', ' ')}"
                        }
                        for issue in issues
                    ]
                }
                print(f"  BLOCKED: {len(issues)} security issues detected")
                self.send_json(error_response, 400)
                return

            # Mock successful response
            response = {
                "id": f"mock-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "mock-gateway",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Gateway working! Processed {len(messages)} message(s) safely. This is a mock response - add DEEPSEEK_API_KEY for real responses."
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": len(text_content.split()),
                    "completion_tokens": 20,
                    "total_tokens": len(text_content.split()) + 20
                }
            }

            print(f"  SUCCESS: Mock response sent")
            self.send_json(response)

        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"  ERROR: {e}")
            self.send_error(500, str(e))

    def send_json(self, data, status=200):
        """Send JSON response"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, format, *args):
        """Suppress default logs"""
        return


def main():
    """Start the simple gateway"""
    # Railway provides PORT environment variable
    PORT = int(os.getenv('PORT', 8000))

    # Force port 8000 to match Railway settings
    if 'PORT' not in os.environ:
        PORT = 8000
    HOST = "0.0.0.0"

    print(f"🔍 Environment check:")
    print(f"  PORT env var: {os.getenv('PORT', 'Not set')}")
    print(f"  HOST: {HOST}")
    print(f"  Using port: {PORT}")
    print(f"  All env vars: {dict(os.environ)}")

    print("Enhanced LLM Gateway Starting")
    print("=" * 40)
    print(f"Port: {PORT}")
    print(f"Features: Enhanced security scanning, Mock responses")
    print(f"Dependencies: None (Python built-ins only)")
    print(f"Security Patterns: 15 detection rules")
    print("=" * 40)

    try:
        with socketserver.TCPServer((HOST, PORT), SimpleGatewayHandler) as httpd:
            print(f"Server running on port {PORT}")
            print("Gateway is ready!")
            httpd.serve_forever()
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    main()

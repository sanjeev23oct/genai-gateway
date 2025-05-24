"""
Railway-optimized LLM Gateway
Simplified version for Railway deployment
"""
import json
import os
import time
import uuid
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from urllib.parse import urlparse, parse_qs


class SecurityScanner:
    """Security scanner for PII and secrets"""

    def __init__(self):
        self.patterns = {
            # API Keys
            "openai_api_key": r'sk-[a-zA-Z0-9]{48}',
            "anthropic_api_key": r'sk-ant-[a-zA-Z0-9\-_]{95}',
            "github_token": r'ghp_[a-zA-Z0-9]{36}',
            "aws_access_key": r'AKIA[0-9A-Z]{16}',

            # PII
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone_us": r'\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "credit_card": r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',

            # Generic secrets
            "generic_api_key": r'["\']?[a-z_]*api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{20,}["\']?',
            "password": r'["\']?password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_!@#$%^&*()]{8,}["\']?',
            "jwt_token": r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
            "private_key": r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
        }

        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.patterns.items()
        }

    def scan(self, text):
        """Scan text for security issues"""
        issues = []
        for name, pattern in self.compiled_patterns.items():
            if pattern.search(text):
                issues.append(name)
        return issues


class DeepSeekClient:
    """DeepSeek API client"""

    def __init__(self):
        self.api_key = os.getenv('DEEPSEEK_API_KEY')
        self.base_url = os.getenv('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')

    def chat_completion(self, messages, model="deepseek-chat", **kwargs):
        """Send request to DeepSeek API"""
        if not self.api_key:
            # Return mock response if no API key
            return {
                "id": f"mock-{uuid.uuid4().hex[:8]}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": model,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Mock response: Gateway is working! Configure DEEPSEEK_API_KEY environment variable for real DeepSeek responses."
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 25,
                    "total_tokens": 35
                }
            }

        # Real API call
        payload = {
            "model": model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.7),
            "max_tokens": kwargs.get("max_tokens", 1000),
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        try:
            req = Request(
                f"{self.base_url}/v1/chat/completions",
                data=json.dumps(payload).encode(),
                headers=headers
            )

            with urlopen(req, timeout=30) as response:
                return json.loads(response.read().decode())

        except HTTPError as e:
            error_msg = e.read().decode() if e.fp else str(e)
            raise Exception(f"DeepSeek API error {e.code}: {error_msg}")
        except Exception as e:
            raise Exception(f"DeepSeek API error: {str(e)}")


class GatewayHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the gateway"""

    def __init__(self, *args, **kwargs):
        self.scanner = SecurityScanner()
        self.deepseek = DeepSeekClient()
        self.block_on_detection = os.getenv('BLOCK_ON_DETECTION', 'true').lower() == 'true'
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_health_response()
        elif self.path == '/':
            self.send_welcome_response()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/v1/chat/completions':
            self.handle_chat_completion()
        else:
            self.send_error(404, "Not Found")

    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def send_health_response(self):
        """Send health check response"""
        response = {
            "status": "healthy",
            "version": "1.0.0-railway",
            "timestamp": int(time.time()),
            "components": {
                "security_scanner": True,
                "deepseek_client": bool(self.deepseek.api_key),
                "blocking_enabled": self.block_on_detection
            },
            "environment": {
                "platform": "Railway",
                "python_version": "3.11+",
                "deployment": "production"
            }
        }
        self.send_json_response(response)

    def send_welcome_response(self):
        """Send welcome page"""
        html = f"""
        <html>
        <head><title>🚀 LLM Gateway - Railway</title></head>
        <body style="font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px;">
            <h1>🚀 LLM Gateway MVP</h1>
            <p><strong>Status:</strong> ✅ Running on Railway</p>
            <p><strong>Version:</strong> 1.0.0-railway</p>

            <h2>🔒 Security Features</h2>
            <ul>
                <li>✅ PII Detection (emails, phones, SSNs)</li>
                <li>✅ Secret Detection (API keys, passwords)</li>
                <li>✅ Request Blocking: {'Enabled' if self.block_on_detection else 'Disabled'}</li>
                <li>✅ DeepSeek Integration: {'Configured' if self.deepseek.api_key else 'Mock Mode'}</li>
            </ul>

            <h2>📡 API Endpoints</h2>
            <ul>
                <li><a href="/health">GET /health</a> - Health check</li>
                <li>POST /v1/chat/completions - Chat completions</li>
            </ul>

            <h2>🧪 Test with curl</h2>
            <pre style="background: #f5f5f5; padding: 15px; border-radius: 5px;">
curl -X POST {os.getenv('RAILWAY_PUBLIC_DOMAIN', 'your-app.railway.app')}/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "deepseek-chat",
    "messages": [{{"role": "user", "content": "Hello!"}}]
  }}'
            </pre>

            <h2>🚨 Security Test (Should Block)</h2>
            <pre style="background: #fff5f5; padding: 15px; border-radius: 5px;">
curl -X POST {os.getenv('RAILWAY_PUBLIC_DOMAIN', 'your-app.railway.app')}/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{{
    "model": "deepseek-chat",
    "messages": [{{"role": "user", "content": "My email is test@example.com"}}]
  }}'
            </pre>

            <p><em>Deployed on Railway • <a href="https://github.com/your-repo">Source Code</a></em></p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    def handle_chat_completion(self):
        """Handle chat completion requests"""
        request_id = uuid.uuid4().hex[:8]

        try:
            # Read request body
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))

            # Extract text content from messages
            text_content = ""
            messages = request_data.get('messages', [])
            for message in messages:
                text_content += message.get('content', '') + "\n"

            # Security scanning
            security_issues = self.scanner.scan(text_content)

            # Log the request
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Request {request_id}")
            print(f"  Messages: {len(messages)}")
            print(f"  Security issues: {security_issues}")

            # Block if security issues found
            if security_issues and self.block_on_detection:
                error_response = {
                    "error": "Request blocked due to security policy violations",
                    "issues": [f"Detected: {issue}" for issue in security_issues],
                    "request_id": request_id,
                    "blocked": True
                }
                print(f"  ❌ Request {request_id} blocked: {security_issues}")
                self.send_json_response(error_response, status_code=400)
                return

            # Forward to DeepSeek
            response = self.deepseek.chat_completion(
                messages=messages,
                model=request_data.get('model', 'deepseek-chat'),
                temperature=request_data.get('temperature', 0.7),
                max_tokens=request_data.get('max_tokens', 1000)
            )

            print(f"  ✅ Request {request_id} processed successfully")
            self.send_json_response(response)

        except json.JSONDecodeError:
            print(f"  ❌ Request {request_id} failed: Invalid JSON")
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"  ❌ Request {request_id} failed: {str(e)}")
            self.send_error(500, f"Internal server error: {str(e)}")

    def send_json_response(self, data, status_code=200):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())

    def log_message(self, format, *args):
        """Override to customize logging"""
        return  # Suppress default HTTP logs


def main():
    """Start the gateway server"""
    PORT = int(os.getenv('PORT', 8000))
    HOST = "0.0.0.0"

    print("🚀 LLM Gateway Starting on Railway")
    print("=" * 50)
    print(f"Host: {HOST}")
    print(f"Port: {PORT}")
    print(f"DeepSeek API: {'Configured' if os.getenv('DEEPSEEK_API_KEY') else 'Mock Mode'}")
    print(f"Security Blocking: {os.getenv('BLOCK_ON_DETECTION', 'true')}")
    print("=" * 50)

    try:
        # Create server
        server = HTTPServer((HOST, PORT), GatewayHandler)
        print(f"✅ Server created on {HOST}:{PORT}")

        # Start server
        print("🚀 Starting server...")
        server.serve_forever()

    except OSError as e:
        print(f"❌ Port binding error: {e}")
        print(f"   Trying to bind to {HOST}:{PORT}")
        print("   This might be a Railway configuration issue")
    except KeyboardInterrupt:
        print("\n🛑 Gateway stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

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


class SimpleSecurityScanner:
    """Simple security scanner using only regex"""
    
    def __init__(self):
        self.patterns = {
            # Simple patterns that work without spaCy
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "api_key": r'sk-[a-zA-Z0-9]{20,}',
            "password": r'password\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*()]{6,}["\']?',
            "secret": r'secret\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*()]{6,}["\']?',
        }
    
    def scan(self, text):
        """Scan text for security issues"""
        issues = []
        for name, pattern in self.patterns.items():
            if re.search(pattern, text, re.IGNORECASE):
                issues.append(name)
        return issues


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
            "version": "1.0.0-simple",
            "timestamp": int(time.time()),
            "message": "LLM Gateway is running on Railway!",
            "features": [
                "PII Detection",
                "Secret Detection", 
                "Request Blocking",
                "Mock Responses"
            ]
        }
        self.send_json(response)
    
    def send_welcome(self):
        """Send welcome page"""
        html = """
        <html>
        <head><title>🚀 LLM Gateway - Railway</title></head>
        <body style="font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px;">
            <h1>🚀 LLM Gateway MVP</h1>
            <p><strong>Status:</strong> ✅ Running on Railway</p>
            
            <h2>🔒 Security Features</h2>
            <ul>
                <li>✅ Email Detection</li>
                <li>✅ Phone Number Detection</li>
                <li>✅ API Key Detection</li>
                <li>✅ Password Detection</li>
                <li>✅ Request Blocking</li>
            </ul>
            
            <h2>🧪 Test Commands</h2>
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
            
            <p><em>✨ Deployed on Railway • No external dependencies</em></p>
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
            scanner = SimpleSecurityScanner()
            issues = scanner.scan(text_content)
            
            # Log request
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Chat request")
            print(f"  Content: {text_content[:100]}...")
            print(f"  Issues: {issues}")
            
            # Block if issues found
            if issues:
                error_response = {
                    "error": "Request blocked due to security violations",
                    "issues": issues,
                    "blocked": True,
                    "timestamp": int(time.time())
                }
                print(f"  ❌ BLOCKED: {issues}")
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
                        "content": f"✅ Gateway working! Processed {len(messages)} message(s) safely. This is a mock response - add DEEPSEEK_API_KEY for real responses."
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": len(text_content.split()),
                    "completion_tokens": 20,
                    "total_tokens": len(text_content.split()) + 20
                }
            }
            
            print(f"  ✅ SUCCESS: Mock response sent")
            self.send_json(response)
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
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
    PORT = int(os.getenv('PORT', 8000))
    
    print("🚀 Simple LLM Gateway Starting")
    print("=" * 40)
    print(f"Port: {PORT}")
    print(f"Features: Security scanning, Mock responses")
    print(f"Dependencies: None (Python built-ins only)")
    print("=" * 40)
    
    try:
        with socketserver.TCPServer(("0.0.0.0", PORT), SimpleGatewayHandler) as httpd:
            print(f"✅ Server running on port {PORT}")
            print("🌐 Gateway is ready!")
            httpd.serve_forever()
    except Exception as e:
        print(f"❌ Server error: {e}")


if __name__ == "__main__":
    main()

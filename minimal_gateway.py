"""
Minimal LLM Gateway using only built-in Python modules
This version demonstrates the core concepts without external dependencies
"""
import http.server
import socketserver
import json
import re
import urllib.request
import urllib.parse
import urllib.error
import os
import time
import uuid
from typing import List, Dict, Any


class SecretDetector:
    """Simple secret detection using regex patterns"""
    
    def __init__(self):
        self.patterns = {
            "openai_api_key": re.compile(r'sk-[a-zA-Z0-9]{48}', re.IGNORECASE),
            "generic_api_key": re.compile(r'["\']?[a-z_]*api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{20,}["\']?', re.IGNORECASE),
            "generic_secret": re.compile(r'["\']?[a-z_]*secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{20,}["\']?', re.IGNORECASE),
            "email": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "phone": re.compile(r'\b\d{3}-\d{3}-\d{4}\b|\b\(\d{3}\)\s*\d{3}-\d{4}\b'),
        }
    
    def detect(self, text: str) -> List[str]:
        """Detect secrets/PII in text"""
        detected = []
        for name, pattern in self.patterns.items():
            if pattern.search(text):
                detected.append(name)
        return detected


class MockDeepSeekClient:
    """Mock DeepSeek client for testing"""
    
    def chat_completion(self, messages: List[Dict], model: str = "deepseek-chat") -> Dict:
        """Mock chat completion"""
        return {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Mock response: I received {len(messages)} message(s). This is a test response from the minimal gateway."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30
            }
        }


class GatewayHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler for the gateway"""
    
    def __init__(self, *args, **kwargs):
        self.secret_detector = SecretDetector()
        self.deepseek_client = MockDeepSeekClient()
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
    
    def send_health_response(self):
        """Send health check response"""
        response = {
            "status": "healthy",
            "version": "0.1.0-minimal",
            "components": {
                "secret_detection": True,
                "pii_detection": True,
                "mock_provider": True
            }
        }
        self.send_json_response(response)
    
    def send_welcome_response(self):
        """Send welcome page"""
        html = """
        <html>
        <head><title>LLM Gateway MVP</title></head>
        <body>
            <h1>🚀 LLM Gateway MVP</h1>
            <p>Gateway is running successfully!</p>
            <h2>Available Endpoints:</h2>
            <ul>
                <li><a href="/health">GET /health</a> - Health check</li>
                <li>POST /v1/chat/completions - Chat completions</li>
            </ul>
            <h2>Test with curl:</h2>
            <pre>
curl -X POST http://localhost:8000/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "deepseek-chat",
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
            </pre>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_chat_completion(self):
        """Handle chat completion requests"""
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
            security_issues = self.secret_detector.detect(text_content)
            
            # Log the request
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Chat request received")
            print(f"  Messages: {len(messages)}")
            print(f"  Security issues: {security_issues}")
            
            # Block if security issues found
            if security_issues:
                error_response = {
                    "error": "Request blocked due to security policy violations",
                    "issues": [f"Detected: {issue}" for issue in security_issues]
                }
                print(f"  ❌ Request blocked: {security_issues}")
                self.send_json_response(error_response, status_code=400)
                return
            
            # Forward to mock provider
            response = self.deepseek_client.chat_completion(
                messages=messages,
                model=request_data.get('model', 'deepseek-chat')
            )
            
            print(f"  ✅ Request processed successfully")
            self.send_json_response(response)
            
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"  ❌ Error: {e}")
            self.send_error(500, f"Internal server error: {e}")
    
    def send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def do_OPTIONS(self):
        """Handle CORS preflight requests"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        return  # Suppress default HTTP logs


def main():
    """Start the minimal gateway server"""
    PORT = 8000
    
    print("🚀 Starting LLM Gateway MVP (Minimal Version)")
    print("=" * 50)
    print(f"Server starting on http://localhost:{PORT}")
    print("Features:")
    print("  ✅ Secret/PII detection")
    print("  ✅ Mock DeepSeek integration")
    print("  ✅ Security blocking")
    print("  ✅ Audit logging")
    print("\nPress Ctrl+C to stop")
    print("=" * 50)
    
    try:
        with socketserver.TCPServer(("", PORT), GatewayHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Gateway stopped")


if __name__ == "__main__":
    main()

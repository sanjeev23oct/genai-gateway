"""
Cloud-Ready LLM Gateway
This version can be deployed to any cloud platform that supports Python
"""
import json
import os
import time
import uuid
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import re


class SecurityScanner:
    """Combined PII and Secret detection"""
    
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
            "generic_secret": r'["\']?[a-z_]*secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{20,}["\']?',
            "password": r'["\']?password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_!@#$%^&*()]{8,}["\']?',
            
            # Database URLs
            "database_url": r'[a-z]+://[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_!@#$%^&*()]+@[a-zA-Z0-9\-_.]+:[0-9]+/[a-zA-Z0-9\-_]+',
            
            # JWT tokens
            "jwt_token": r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
            
            # Private keys
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
    """Real DeepSeek API client"""
    
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
                        "content": "Mock response: This is a test response from the gateway. Configure DEEPSEEK_API_KEY for real responses."
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


class LLMGateway:
    """Main gateway class"""
    
    def __init__(self):
        self.scanner = SecurityScanner()
        self.deepseek = DeepSeekClient()
        self.block_on_detection = os.getenv('BLOCK_ON_DETECTION', 'true').lower() == 'true'
    
    def process_request(self, request_data):
        """Process a chat completion request"""
        request_id = uuid.uuid4().hex[:8]
        
        # Log request
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Request {request_id} received")
        
        try:
            # Extract messages
            messages = request_data.get('messages', [])
            if not messages:
                return self._error_response("No messages provided", 400)
            
            # Extract text content
            text_content = ""
            for msg in messages:
                text_content += msg.get('content', '') + "\n"
            
            # Security scan
            security_issues = self.scanner.scan(text_content)
            
            if security_issues:
                print(f"  Security issues detected: {security_issues}")
                
                if self.block_on_detection:
                    return self._error_response({
                        "error": "Request blocked due to security policy violations",
                        "issues": security_issues,
                        "request_id": request_id
                    }, 400)
                else:
                    print(f"  Warning: Security issues detected but not blocking")
            
            # Forward to DeepSeek
            response = self.deepseek.chat_completion(
                messages=messages,
                model=request_data.get('model', 'deepseek-chat'),
                temperature=request_data.get('temperature', 0.7),
                max_tokens=request_data.get('max_tokens', 1000)
            )
            
            print(f"  Request {request_id} processed successfully")
            return self._success_response(response)
            
        except Exception as e:
            print(f"  Request {request_id} failed: {str(e)}")
            return self._error_response(f"Internal error: {str(e)}", 500)
    
    def health_check(self):
        """Health check endpoint"""
        return self._success_response({
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": int(time.time()),
            "components": {
                "security_scanner": True,
                "deepseek_client": bool(self.deepseek.api_key),
                "blocking_enabled": self.block_on_detection
            }
        })
    
    def _success_response(self, data):
        """Create success response"""
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Authorization"
            },
            "body": json.dumps(data)
        }
    
    def _error_response(self, error, status_code):
        """Create error response"""
        return {
            "statusCode": status_code,
            "headers": {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*"
            },
            "body": json.dumps({"error": error} if isinstance(error, str) else error)
        }


# AWS Lambda handler
def lambda_handler(event, context):
    """AWS Lambda entry point"""
    gateway = LLMGateway()
    
    method = event.get('httpMethod', 'GET')
    path = event.get('path', '/')
    
    if method == 'GET' and path == '/health':
        return gateway.health_check()
    
    elif method == 'POST' and path == '/v1/chat/completions':
        try:
            body = json.loads(event.get('body', '{}'))
            return gateway.process_request(body)
        except json.JSONDecodeError:
            return gateway._error_response("Invalid JSON", 400)
    
    elif method == 'OPTIONS':
        return gateway._success_response({})
    
    else:
        return gateway._error_response("Not found", 404)


# For local testing
def local_test():
    """Test the gateway locally"""
    print("🧪 Testing Cloud Gateway Locally")
    print("=" * 40)
    
    gateway = LLMGateway()
    
    # Test health check
    print("\n1. Health Check:")
    health = gateway.health_check()
    print(f"Status: {health['statusCode']}")
    print(f"Body: {health['body']}")
    
    # Test normal request
    print("\n2. Normal Request:")
    normal_request = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": "Hello!"}]
    }
    response = gateway.process_request(normal_request)
    print(f"Status: {response['statusCode']}")
    print(f"Body: {response['body'][:200]}...")
    
    # Test blocked request
    print("\n3. Blocked Request:")
    blocked_request = {
        "model": "deepseek-chat", 
        "messages": [{"role": "user", "content": "My email is test@example.com"}]
    }
    response = gateway.process_request(blocked_request)
    print(f"Status: {response['statusCode']}")
    print(f"Body: {response['body']}")
    
    print("\n" + "=" * 40)
    print("✅ Cloud Gateway Test Complete!")


if __name__ == "__main__":
    local_test()

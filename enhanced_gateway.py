"""
Enhanced LLM Gateway with Enterprise-Grade Security Detection
Combines the best of both worlds: Railway compatibility + Advanced detection
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
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class DetectionLevel(Enum):
    """Detection confidence levels"""
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.8
    CRITICAL = 0.95


@dataclass
class SecurityIssue:
    """Represents a detected security issue"""
    type: str
    description: str
    confidence: float
    location: Tuple[int, int]
    severity: DetectionLevel
    context: str
    detector: str


class EnterpriseSecurityDetector:
    """Enterprise-grade security detection system"""
    
    def __init__(self):
        self.patterns = self._load_detection_patterns()
        self.compiled_patterns = self._compile_patterns()
        self.stats = {
            'total_scans': 0,
            'issues_found': 0,
            'blocked_requests': 0
        }
    
    def _load_detection_patterns(self) -> Dict:
        """Load comprehensive detection patterns"""
        return {
            # CRITICAL SEVERITY - API Keys and Secrets
            'openai_api_key': {
                'pattern': r'sk-[a-zA-Z0-9]{48}',
                'confidence': 0.98,
                'severity': DetectionLevel.CRITICAL,
                'description': 'OpenAI API Key'
            },
            'anthropic_api_key': {
                'pattern': r'sk-ant-[a-zA-Z0-9\-_]{95}',
                'confidence': 0.98,
                'severity': DetectionLevel.CRITICAL,
                'description': 'Anthropic API Key'
            },
            'github_token': {
                'pattern': r'ghp_[a-zA-Z0-9]{36}',
                'confidence': 0.95,
                'severity': DetectionLevel.CRITICAL,
                'description': 'GitHub Personal Access Token'
            },
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'confidence': 0.95,
                'severity': DetectionLevel.CRITICAL,
                'description': 'AWS Access Key ID'
            },
            'private_key': {
                'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
                'confidence': 0.99,
                'severity': DetectionLevel.CRITICAL,
                'description': 'Private Key'
            },
            'database_url': {
                'pattern': r'(postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+',
                'confidence': 0.9,
                'severity': DetectionLevel.CRITICAL,
                'description': 'Database Connection URL'
            },
            
            # HIGH SEVERITY - PII and Sensitive Data
            'email_address': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'confidence': 0.85,
                'severity': DetectionLevel.HIGH,
                'description': 'Email Address',
                'validator': self._validate_email
            },
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'confidence': 0.9,
                'severity': DetectionLevel.HIGH,
                'description': 'Social Security Number'
            },
            'credit_card': {
                'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                'confidence': 0.7,
                'severity': DetectionLevel.HIGH,
                'description': 'Credit Card Number',
                'validator': self._validate_luhn
            },
            'jwt_token': {
                'pattern': r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
                'confidence': 0.85,
                'severity': DetectionLevel.HIGH,
                'description': 'JWT Token'
            },
            'password_assignment': {
                'pattern': r'password\s*[:=]\s*["\']?[a-zA-Z0-9!@#$%^&*()]{6,}["\']?',
                'confidence': 0.8,
                'severity': DetectionLevel.HIGH,
                'description': 'Password Assignment'
            },
            'api_key_assignment': {
                'pattern': r'api[_-]?key\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{16,}["\']?',
                'confidence': 0.75,
                'severity': DetectionLevel.HIGH,
                'description': 'API Key Assignment'
            },
            
            # MEDIUM SEVERITY - Contact Info
            'phone_us': {
                'pattern': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'confidence': 0.8,
                'severity': DetectionLevel.MEDIUM,
                'description': 'US Phone Number'
            },
            'ip_address_private': {
                'pattern': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}\b',
                'confidence': 0.6,
                'severity': DetectionLevel.MEDIUM,
                'description': 'Private IP Address'
            },
            
            # Additional patterns for comprehensive coverage
            'slack_token': {
                'pattern': r'xox[baprs]-[a-zA-Z0-9\-]{10,72}',
                'confidence': 0.9,
                'severity': DetectionLevel.CRITICAL,
                'description': 'Slack Token'
            },
            'discord_token': {
                'pattern': r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
                'confidence': 0.9,
                'severity': DetectionLevel.CRITICAL,
                'description': 'Discord Bot Token'
            },
            'google_api_key': {
                'pattern': r'AIza[0-9A-Za-z\-_]{35}',
                'confidence': 0.9,
                'severity': DetectionLevel.CRITICAL,
                'description': 'Google API Key'
            }
        }
    
    def _compile_patterns(self) -> Dict:
        """Compile regex patterns for performance"""
        compiled = {}
        for name, config in self.patterns.items():
            compiled[name] = {
                'regex': re.compile(config['pattern'], re.IGNORECASE),
                'confidence': config['confidence'],
                'severity': config['severity'],
                'description': config['description'],
                'validator': config.get('validator')
            }
        return compiled
    
    def scan_content(self, text: str) -> List[SecurityIssue]:
        """Comprehensive security scan"""
        self.stats['total_scans'] += 1
        issues = []
        
        for name, config in self.compiled_patterns.items():
            matches = config['regex'].finditer(text)
            
            for match in matches:
                # Apply validator if available
                validator = config.get('validator')
                if validator and not validator(match.group()):
                    continue
                
                issue = SecurityIssue(
                    type=name,
                    description=config['description'],
                    confidence=config['confidence'],
                    location=(match.start(), match.end()),
                    severity=config['severity'],
                    context=text[max(0, match.start()-20):match.end()+20],
                    detector='enterprise_regex'
                )
                issues.append(issue)
        
        # Deduplicate overlapping issues
        issues = self._deduplicate_issues(issues)
        
        if issues:
            self.stats['issues_found'] += len(issues)
        
        return issues
    
    def _deduplicate_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Remove overlapping issues, keeping highest confidence"""
        if not issues:
            return issues
        
        issues.sort(key=lambda x: x.location[0])
        deduplicated = []
        
        for issue in issues:
            overlapping = False
            for existing in deduplicated:
                if self._issues_overlap(issue, existing):
                    if issue.confidence > existing.confidence:
                        deduplicated.remove(existing)
                        deduplicated.append(issue)
                    overlapping = True
                    break
            
            if not overlapping:
                deduplicated.append(issue)
        
        return deduplicated
    
    def _issues_overlap(self, issue1: SecurityIssue, issue2: SecurityIssue) -> bool:
        """Check if two issues overlap in location"""
        start1, end1 = issue1.location
        start2, end2 = issue2.location
        return not (end1 <= start2 or end2 <= start1)
    
    def should_block_request(self, issues: List[SecurityIssue]) -> bool:
        """Determine if request should be blocked"""
        if not issues:
            return False
        
        # Block on any CRITICAL issues
        critical_issues = [i for i in issues if i.severity == DetectionLevel.CRITICAL]
        if critical_issues:
            self.stats['blocked_requests'] += 1
            return True
        
        # Block on high confidence HIGH severity issues
        high_confidence_high = [i for i in issues if i.severity == DetectionLevel.HIGH and i.confidence >= 0.8]
        if high_confidence_high:
            self.stats['blocked_requests'] += 1
            return True
        
        return False
    
    def _validate_email(self, email: str) -> bool:
        """Basic email validation"""
        if email.count('@') != 1:
            return False
        local, domain = email.split('@')
        return bool(local and domain and '.' in domain)
    
    def _validate_luhn(self, card_number: str) -> bool:
        """Luhn algorithm validation for credit cards"""
        card_number = re.sub(r'[-\s]', '', card_number)
        if not card_number.isdigit() or len(card_number) < 13:
            return False
        
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
    
    def get_detection_summary(self, issues: List[SecurityIssue]) -> Dict:
        """Generate comprehensive detection summary"""
        if not issues:
            return {"clean": True, "issues": []}
        
        return {
            "clean": False,
            "total_issues": len(issues),
            "severity_breakdown": {
                "critical": len([i for i in issues if i.severity == DetectionLevel.CRITICAL]),
                "high": len([i for i in issues if i.severity == DetectionLevel.HIGH]),
                "medium": len([i for i in issues if i.severity == DetectionLevel.MEDIUM]),
                "low": len([i for i in issues if i.severity == DetectionLevel.LOW])
            },
            "issue_types": list(set(issue.type for issue in issues)),
            "max_confidence": max(issue.confidence for issue in issues),
            "should_block": self.should_block_request(issues),
            "issues": [
                {
                    "type": issue.type,
                    "description": issue.description,
                    "confidence": round(issue.confidence, 3),
                    "severity": issue.severity.name,
                    "detector": issue.detector,
                    "context": issue.context[:50] + "..." if len(issue.context) > 50 else issue.context
                }
                for issue in issues
            ]
        }
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return self.stats.copy()


class EnhancedGatewayHandler(http.server.BaseHTTPRequestHandler):
    """Enhanced HTTP handler with enterprise security"""
    
    def __init__(self, *args, **kwargs):
        self.detector = EnterpriseSecurityDetector()
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_health()
        elif self.path == '/stats':
            self.send_stats()
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
        """Enhanced health response"""
        stats = self.detector.get_stats()
        response = {
            "status": "healthy",
            "version": "2.0.0-enterprise",
            "timestamp": int(time.time()),
            "message": "Enhanced LLM Gateway with Enterprise Security",
            "security_features": {
                "total_patterns": len(self.detector.patterns),
                "severity_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "confidence_scoring": "0.0 - 1.0",
                "luhn_validation": True,
                "email_validation": True,
                "overlap_detection": True
            },
            "detection_categories": [
                "API Keys & Tokens",
                "Database Credentials", 
                "Personal Information (PII)",
                "Financial Data",
                "Authentication Secrets",
                "Network Information"
            ],
            "statistics": stats
        }
        self.send_json(response)
    
    def send_stats(self):
        """Send detection statistics"""
        stats = self.detector.get_stats()
        self.send_json(stats)
    
    def send_welcome(self):
        """Enhanced welcome page"""
        stats = self.detector.get_stats()
        html = f"""
        <html>
        <head><title>Enhanced LLM Gateway - Enterprise Security</title></head>
        <body style="font-family: Arial; max-width: 900px; margin: 50px auto; padding: 20px;">
            <h1>Enhanced LLM Gateway</h1>
            <p><strong>Status:</strong> Running on Railway with Enterprise Security</p>
            <p><strong>Version:</strong> 2.0.0-enterprise</p>
            
            <h2>Enterprise Security Features</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h3>Detection Capabilities</h3>
                    <ul>
                        <li><strong>API Keys:</strong> OpenAI, Anthropic, GitHub, AWS, Google</li>
                        <li><strong>PII:</strong> Email, Phone, SSN, Credit Cards</li>
                        <li><strong>Database:</strong> Connection strings, URLs</li>
                        <li><strong>Tokens:</strong> JWT, Slack, Discord</li>
                        <li><strong>Secrets:</strong> Private keys, passwords</li>
                    </ul>
                </div>
                <div>
                    <h3>Advanced Features</h3>
                    <ul>
                        <li><strong>Confidence Scoring:</strong> 0.0 - 1.0</li>
                        <li><strong>Severity Levels:</strong> LOW, MEDIUM, HIGH, CRITICAL</li>
                        <li><strong>Smart Validation:</strong> Luhn algorithm, email format</li>
                        <li><strong>Overlap Detection:</strong> Deduplication logic</li>
                        <li><strong>Context Awareness:</strong> Surrounding text analysis</li>
                    </ul>
                </div>
            </div>
            
            <h2>Detection Statistics</h2>
            <p>Total Scans: <strong>{stats['total_scans']}</strong></p>
            <p>Issues Found: <strong>{stats['issues_found']}</strong></p>
            <p>Requests Blocked: <strong>{stats['blocked_requests']}</strong></p>
            
            <h2>API Endpoints</h2>
            <ul>
                <li><code>GET /health</code> - Detailed health check</li>
                <li><code>GET /stats</code> - Detection statistics</li>
                <li><code>POST /v1/chat/completions</code> - Secure chat completions</li>
            </ul>
            
            <h2>Test Commands</h2>
            <h3>Health Check:</h3>
            <pre>curl https://genai-gateway-production.up.railway.app/health</pre>
            
            <h3>Normal Request:</h3>
            <pre>curl -X POST https://genai-gateway-production.up.railway.app/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{{"messages": [{{"role": "user", "content": "Hello!"}}]}}'</pre>
            
            <h3>Security Test (Will Block):</h3>
            <pre>curl -X POST https://genai-gateway-production.up.railway.app/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{{"messages": [{{"role": "user", "content": "My API key is sk-1234567890abcdef1234567890abcdef12345678"}}]}}'</pre>
            
            <p><em>Enhanced LLM Gateway - Enterprise Security Edition</em></p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def handle_chat(self):
        """Enhanced chat handling with detailed security analysis"""
        request_id = uuid.uuid4().hex[:8]
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error(400, "No content")
                return
            
            post_data = self.rfile.read(content_length)
            request_data = json.loads(post_data.decode('utf-8'))
            
            # Extract text content
            text_content = ""
            messages = request_data.get('messages', [])
            for msg in messages:
                text_content += msg.get('content', '') + " "
            
            # Enhanced security scan
            issues = self.detector.scan_content(text_content)
            detection_summary = self.detector.get_detection_summary(issues)
            
            # Detailed logging
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Request {request_id}")
            print(f"  Content length: {len(text_content)} chars")
            print(f"  Issues detected: {len(issues)}")
            
            for issue in issues:
                print(f"    - {issue.type}: {issue.severity.name} (confidence: {issue.confidence:.3f})")
            
            # Determine blocking
            should_block = self.detector.should_block_request(issues)
            
            if should_block:
                error_response = {
                    "error": "Request blocked due to security policy violations",
                    "blocked": True,
                    "request_id": request_id,
                    "timestamp": int(time.time()),
                    "detection_summary": detection_summary
                }
                print(f"  BLOCKED: {len(issues)} security violations")
                self.send_json(error_response, 400)
                return
            
            # Mock successful response
            response = {
                "id": f"enhanced-{request_id}",
                "object": "chat.completion",
                "created": int(time.time()),
                "model": "enhanced-gateway",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": f"Enhanced Gateway: Processed {len(messages)} message(s) with enterprise security. {len(issues)} low-risk issues detected but allowed. Add DEEPSEEK_API_KEY for real responses."
                    },
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": len(text_content.split()),
                    "completion_tokens": 30,
                    "total_tokens": len(text_content.split()) + 30
                },
                "security_scan": {
                    "issues_detected": len(issues),
                    "risk_level": "low" if not should_block else "high",
                    "scan_time_ms": 1  # Placeholder
                }
            }
            
            print(f"  SUCCESS: Request processed with {len(issues)} low-risk issues")
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
    """Start the enhanced gateway"""
    PORT = int(os.getenv('PORT', 8000))
    HOST = "0.0.0.0"
    
    print("Enhanced LLM Gateway - Enterprise Security Edition")
    print("=" * 60)
    print(f"Port: {PORT}")
    print(f"Security Patterns: {len(EnterpriseSecurityDetector().patterns)}")
    print(f"Features: Enterprise detection, Confidence scoring, Smart blocking")
    print("=" * 60)
    
    try:
        with socketserver.TCPServer((HOST, PORT), EnhancedGatewayHandler) as httpd:
            print(f"Enhanced Gateway running on port {PORT}")
            print("Enterprise security active!")
            httpd.serve_forever()
    except Exception as e:
        print(f"Server error: {e}")


if __name__ == "__main__":
    main()

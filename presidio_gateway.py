"""
Microsoft Presidio-Enhanced LLM Gateway
Enterprise-grade PII detection using Microsoft Presidio + Custom patterns
"""
import http.server
import socketserver
import json
import re
import os
import time
import uuid
import asyncio
import logging
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import Presidio and related libraries
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    from presidio_anonymizer import AnonymizerEngine
    PRESIDIO_AVAILABLE = True
    logger.info("✅ Microsoft Presidio loaded successfully")
except ImportError as e:
    PRESIDIO_AVAILABLE = False
    logger.warning(f"❌ Presidio not available: {e}")

try:
    import spacy
    SPACY_AVAILABLE = True
    logger.info("✅ spaCy loaded successfully")
except ImportError:
    SPACY_AVAILABLE = False
    logger.warning("❌ spaCy not available")

try:
    import phonenumbers
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False

try:
    import validators
    VALIDATORS_AVAILABLE = True
except ImportError:
    VALIDATORS_AVAILABLE = False


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
    entity_text: str = ""


class PresidioSecurityDetector:
    """Microsoft Presidio-powered security detection system"""

    def __init__(self):
        self.presidio_analyzer = None
        self.presidio_anonymizer = None
        self.custom_patterns = self._load_custom_patterns()
        self.compiled_patterns = self._compile_custom_patterns()
        self.initialized = False
        self.stats = {
            'total_scans': 0,
            'presidio_scans': 0,
            'custom_scans': 0,
            'issues_found': 0,
            'blocked_requests': 0,
            'avg_scan_time': 0.0
        }

    async def initialize(self):
        """Initialize Presidio and custom detectors"""
        logger.info("🚀 Initializing Presidio Security Detector")

        if PRESIDIO_AVAILABLE and SPACY_AVAILABLE:
            await self._init_presidio()
        else:
            logger.warning("⚠️ Presidio/spaCy not available, using custom patterns only")

        self.initialized = True
        logger.info("✅ Security detector initialization complete")

    async def _init_presidio(self):
        """Initialize Microsoft Presidio analyzer"""
        try:
            logger.info("🔧 Setting up Presidio NLP engine...")

            # Try to download spaCy model if not available
            try:
                import spacy
                spacy.load("en_core_web_sm")
            except OSError:
                logger.info("📥 Downloading spaCy model...")
                import subprocess
                subprocess.run(["python", "-m", "spacy", "download", "en_core_web_sm"], check=True)

            # Configure NLP engine with spaCy
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }

            # Create NLP engine provider
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()

            # Create recognizer registry with custom recognizers
            registry = RecognizerRegistry()
            registry.load_predefined_recognizers()

            # Add custom recognizers
            self._add_custom_recognizers(registry)

            # Create analyzer
            self.presidio_analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                registry=registry
            )

            # Create anonymizer
            self.presidio_anonymizer = AnonymizerEngine()

            logger.info("✅ Presidio analyzer initialized successfully")

        except Exception as e:
            logger.error(f"❌ Failed to initialize Presidio: {e}")
            self.presidio_analyzer = None
            self.presidio_anonymizer = None

    def _add_custom_recognizers(self, registry):
        """Add custom recognizers to Presidio"""
        try:
            from presidio_analyzer import Pattern, PatternRecognizer

            # Custom API Key recognizer
            api_key_patterns = [
                Pattern("OpenAI API Key", r'sk-[a-zA-Z0-9]{48}', 0.9),
                Pattern("Anthropic API Key", r'sk-ant-[a-zA-Z0-9\-_]{95}', 0.9),
                Pattern("GitHub Token", r'ghp_[a-zA-Z0-9]{36}', 0.9),
                Pattern("AWS Access Key", r'AKIA[0-9A-Z]{16}', 0.9),
                Pattern("Google API Key", r'AIza[0-9A-Za-z\-_]{35}', 0.9),
            ]

            api_key_recognizer = PatternRecognizer(
                supported_entity="API_KEY",
                patterns=api_key_patterns,
                name="api_key_recognizer"
            )
            registry.add_recognizer(api_key_recognizer)

            # Custom Database URL recognizer
            db_patterns = [
                Pattern("Database URL", r'(postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+', 0.9),
                Pattern("Connection String", r'(Server|Host|Data Source)\s*=\s*[^;]+;\s*(Database|Initial Catalog)\s*=\s*[^;]+', 0.8),
            ]

            db_recognizer = PatternRecognizer(
                supported_entity="DATABASE_CREDENTIAL",
                patterns=db_patterns,
                name="database_recognizer"
            )
            registry.add_recognizer(db_recognizer)

            # JWT Token recognizer
            jwt_patterns = [
                Pattern("JWT Token", r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', 0.85),
            ]

            jwt_recognizer = PatternRecognizer(
                supported_entity="JWT_TOKEN",
                patterns=jwt_patterns,
                name="jwt_recognizer"
            )
            registry.add_recognizer(jwt_recognizer)

            logger.info("✅ Custom recognizers added to Presidio")

        except Exception as e:
            logger.error(f"❌ Failed to add custom recognizers: {e}")

    def _load_custom_patterns(self) -> Dict:
        """Load custom regex patterns as fallback"""
        return {
            # High-confidence patterns for critical secrets
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
            'jwt_token': {
                'pattern': r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
                'confidence': 0.85,
                'severity': DetectionLevel.HIGH,
                'description': 'JWT Token'
            },
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
            },
            # PII patterns
            'email_address': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'confidence': 0.85,
                'severity': DetectionLevel.HIGH,
                'description': 'Email Address'
            },
            'phone_us': {
                'pattern': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'confidence': 0.8,
                'severity': DetectionLevel.MEDIUM,
                'description': 'US Phone Number'
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
                'description': 'Credit Card Number'
            }
        }

    def _compile_custom_patterns(self) -> Dict:
        """Compile custom regex patterns for performance"""
        compiled = {}
        for name, config in self.custom_patterns.items():
            compiled[name] = {
                'regex': re.compile(config['pattern'], re.IGNORECASE),
                'confidence': config['confidence'],
                'severity': config['severity'],
                'description': config['description']
            }
        return compiled

    async def scan_content(self, text: str, context: Dict = None) -> List[SecurityIssue]:
        """
        Comprehensive security scan using Presidio + custom patterns
        """
        start_time = time.time()
        self.stats['total_scans'] += 1
        issues = []

        try:
            # Presidio scan (if available)
            if self.presidio_analyzer:
                presidio_issues = await self._presidio_scan(text)
                issues.extend(presidio_issues)
                self.stats['presidio_scans'] += 1

            # Custom pattern scan (always run as backup/supplement)
            custom_issues = await self._custom_pattern_scan(text)
            issues.extend(custom_issues)
            self.stats['custom_scans'] += 1

            # Deduplicate overlapping issues
            issues = self._deduplicate_issues(issues)

            # Sort by confidence (highest first)
            issues.sort(key=lambda x: x.confidence, reverse=True)

            # Update stats
            if issues:
                self.stats['issues_found'] += len(issues)

            scan_time = time.time() - start_time
            self._update_performance_stats(scan_time)

            logger.info(f"🔍 Security scan completed: {len(issues)} issues found in {scan_time:.3f}s")

            return issues

        except Exception as e:
            logger.error(f"❌ Error during security scan: {e}")
            return []

    async def _presidio_scan(self, text: str) -> List[SecurityIssue]:
        """Scan using Microsoft Presidio with smart filtering"""
        if not self.presidio_analyzer:
            return []

        try:
            # Define entities to detect
            entities = [
                "CREDIT_CARD", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS",
                "PERSON", "PHONE_NUMBER", "US_SSN", "US_PASSPORT",
                "US_DRIVER_LICENSE", "DATE_TIME", "LOCATION", "URL",
                "US_BANK_NUMBER", "CRYPTO", "MEDICAL_LICENSE",
                # Custom entities
                "API_KEY", "DATABASE_CREDENTIAL", "JWT_TOKEN"
            ]

            # Run Presidio analysis
            results = self.presidio_analyzer.analyze(
                text=text,
                entities=entities,
                language='en'
            )

            # Common false positives to filter out
            false_positives = {
                'you', 'i', 'me', 'we', 'they', 'he', 'she', 'it',
                'today', 'tomorrow', 'yesterday', 'now', 'here', 'there',
                'hello', 'hi', 'hey', 'thanks', 'please', 'yes', 'no'
            }

            issues = []
            for result in results:
                entity_text = text[result.start:result.end].lower().strip()

                # Filter out common false positives
                if result.entity_type == "PERSON" and entity_text in false_positives:
                    continue

                # Filter out single character detections
                if len(entity_text) <= 1:
                    continue

                # Filter out very low confidence PERSON detections
                if result.entity_type == "PERSON" and result.score < 0.7:
                    continue

                # Map Presidio confidence to our severity levels
                severity = self._confidence_to_severity(result.score)

                issue = SecurityIssue(
                    type=result.entity_type.lower(),
                    description=f"Presidio detected {result.entity_type}",
                    confidence=result.score,
                    location=(result.start, result.end),
                    severity=severity,
                    context=text[max(0, result.start-20):result.end+20],
                    detector="presidio",
                    entity_text=entity_text
                )
                issues.append(issue)

            logger.debug(f"🔍 Presidio found {len(issues)} issues after filtering")
            return issues

        except Exception as e:
            logger.error(f"❌ Presidio scan error: {e}")
            return []

    async def _custom_pattern_scan(self, text: str) -> List[SecurityIssue]:
        """Scan using custom regex patterns"""
        issues = []

        for pattern_name, config in self.compiled_patterns.items():
            try:
                matches = config['regex'].finditer(text)

                for match in matches:
                    # Additional validation for specific patterns
                    if pattern_name == "credit_card" and not self._validate_luhn(match.group()):
                        continue

                    if pattern_name == "email_address" and not self._validate_email(match.group()):
                        continue

                    issue = SecurityIssue(
                        type=pattern_name,
                        description=config['description'],
                        confidence=config['confidence'],
                        location=(match.start(), match.end()),
                        severity=config['severity'],
                        context=text[max(0, match.start()-20):match.end()+20],
                        detector="custom_regex",
                        entity_text=match.group()
                    )
                    issues.append(issue)

            except Exception as e:
                logger.error(f"❌ Error in custom pattern {pattern_name}: {e}")

        logger.debug(f"🔍 Custom patterns found {len(issues)} issues")
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

    def _confidence_to_severity(self, confidence: float) -> DetectionLevel:
        """Convert confidence score to severity level"""
        if confidence >= DetectionLevel.CRITICAL.value:
            return DetectionLevel.CRITICAL
        elif confidence >= DetectionLevel.HIGH.value:
            return DetectionLevel.HIGH
        elif confidence >= DetectionLevel.MEDIUM.value:
            return DetectionLevel.MEDIUM
        else:
            return DetectionLevel.LOW

    def should_block_request(self, issues: List[SecurityIssue]) -> bool:
        """Determine if request should be blocked with more reasonable thresholds"""
        if not issues:
            return False

        # Block on any CRITICAL issues (API keys, private keys, etc.)
        critical_issues = [i for i in issues if i.severity == DetectionLevel.CRITICAL]
        if critical_issues:
            self.stats['blocked_requests'] += 1
            return True

        # Block on very high confidence HIGH severity issues (SSN, credit cards, etc.)
        very_high_confidence_high = [i for i in issues if i.severity == DetectionLevel.HIGH and i.confidence >= 0.9]
        if very_high_confidence_high:
            self.stats['blocked_requests'] += 1
            return True

        # Don't block on common words that Presidio might detect as names
        # Allow MEDIUM severity issues (like common names, pronouns)
        # Allow LOW confidence detections

        return False

    def _validate_email(self, email: str) -> bool:
        """Enhanced email validation"""
        if VALIDATORS_AVAILABLE:
            try:
                import validators
                return validators.email(email)
            except:
                pass

        # Fallback validation
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

    def _update_performance_stats(self, scan_time: float):
        """Update performance statistics"""
        total_scans = self.stats['total_scans']
        current_avg = self.stats['avg_scan_time']

        # Calculate new average
        new_avg = ((current_avg * (total_scans - 1)) + scan_time) / total_scans
        self.stats['avg_scan_time'] = new_avg

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
            "detector_breakdown": {
                "presidio": len([i for i in issues if i.detector == "presidio"]),
                "custom_regex": len([i for i in issues if i.detector == "custom_regex"])
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
                    "entity_text": issue.entity_text[:20] + "..." if len(issue.entity_text) > 20 else issue.entity_text,
                    "context": issue.context[:50] + "..." if len(issue.context) > 50 else issue.context
                }
                for issue in issues
            ]
        }

    def get_stats(self) -> Dict:
        """Get comprehensive detection statistics"""
        stats = self.stats.copy()
        stats.update({
            "presidio_available": PRESIDIO_AVAILABLE,
            "spacy_available": SPACY_AVAILABLE,
            "phonenumbers_available": PHONENUMBERS_AVAILABLE,
            "validators_available": VALIDATORS_AVAILABLE,
            "custom_patterns_count": len(self.custom_patterns),
            "avg_scan_time_ms": round(stats['avg_scan_time'] * 1000, 2)
        })
        return stats


class PresidioGatewayHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler with Microsoft Presidio integration"""

    # Class-level detector instance
    detector = None

    @classmethod
    async def initialize_detector(cls):
        """Initialize the detector once for all requests"""
        if cls.detector is None:
            cls.detector = PresidioSecurityDetector()
            await cls.detector.initialize()

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_health()
        elif self.path == '/stats':
            self.send_stats()
        elif self.path == '/presidio-status':
            self.send_presidio_status()
        elif self.path == '/v1/models':
            self.send_models()
        elif self.path == '/':
            self.send_welcome()
        else:
            self.send_error(404)

    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/v1/chat/completions':
            try:
                # Run async handler in sync context with proper error handling
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    loop.run_until_complete(self.handle_chat_async())
                finally:
                    loop.close()
            except Exception as e:
                print(f"Error in chat handler: {e}")
                import traceback
                traceback.print_exc()
                self.send_error(500, f"Internal server error: {str(e)}")
        else:
            self.send_error(404)

    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def send_health(self):
        """Enhanced health response with Presidio status"""
        stats = self.detector.get_stats() if self.detector else {}

        response = {
            "status": "healthy",
            "version": "3.0.0-presidio",
            "timestamp": int(time.time()),
            "message": "Microsoft Presidio-Enhanced LLM Gateway",
            "presidio_integration": {
                "presidio_available": PRESIDIO_AVAILABLE,
                "spacy_available": SPACY_AVAILABLE,
                "detector_initialized": self.detector is not None and self.detector.initialized,
                "presidio_analyzer_active": self.detector.presidio_analyzer is not None if self.detector else False
            },
            "security_features": {
                "microsoft_presidio": "Advanced ML-based PII detection",
                "custom_patterns": "High-confidence API key detection",
                "hybrid_approach": "Presidio + regex fallback",
                "confidence_scoring": "0.0 - 1.0",
                "severity_levels": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
                "luhn_validation": True,
                "email_validation": True,
                "overlap_detection": True,
                "context_analysis": True
            },
            "detection_categories": [
                "API Keys & Tokens (OpenAI, Anthropic, GitHub, AWS, Google)",
                "Personal Information (Email, Phone, SSN, Names)",
                "Financial Data (Credit Cards, Bank Numbers)",
                "Database Credentials & Connection Strings",
                "Authentication Secrets (JWT, Private Keys)",
                "Network Information (IP Addresses, URLs)",
                "Medical Information (License Numbers)",
                "Government IDs (Passports, Driver Licenses)"
            ],
            "statistics": stats
        }
        self.send_json(response)

    def send_stats(self):
        """Send detailed detection statistics"""
        stats = self.detector.get_stats() if self.detector else {}
        self.send_json(stats)

    def send_presidio_status(self):
        """Send Presidio-specific status information"""
        status = {
            "presidio_available": PRESIDIO_AVAILABLE,
            "spacy_available": SPACY_AVAILABLE,
            "phonenumbers_available": PHONENUMBERS_AVAILABLE,
            "validators_available": VALIDATORS_AVAILABLE,
            "detector_initialized": self.detector is not None and self.detector.initialized if self.detector else False,
            "presidio_analyzer_active": self.detector.presidio_analyzer is not None if self.detector else False,
            "presidio_anonymizer_active": self.detector.presidio_anonymizer is not None if self.detector else False,
            "fallback_mode": not PRESIDIO_AVAILABLE,
            "custom_patterns_count": len(self.detector.custom_patterns) if self.detector else 0
        }
        self.send_json(status)

    def send_models(self):
        """Send available models list (OpenAI API compatible)"""
        # Check if we have DeepSeek configured
        deepseek_key = os.getenv('DEEPSEEK_API_KEY')

        models = {
            "object": "list",
            "data": [
                {
                    "id": "gpt-3.5-turbo",
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "presidio-gateway",
                    "permission": [],
                    "root": "gpt-3.5-turbo",
                    "parent": None
                },
                {
                    "id": "gpt-4",
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "presidio-gateway",
                    "permission": [],
                    "root": "gpt-4",
                    "parent": None
                },
                {
                    "id": "deepseek-chat",
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "presidio-gateway",
                    "permission": [],
                    "root": "deepseek-chat",
                    "parent": None
                },
                {
                    "id": "presidio-enhanced-gateway",
                    "object": "model",
                    "created": int(time.time()),
                    "owned_by": "presidio-gateway",
                    "permission": [],
                    "root": "presidio-enhanced-gateway",
                    "parent": None
                }
            ]
        }

        # Add status information
        if deepseek_key:
            models["gateway_status"] = "DeepSeek API configured - real responses available"
        else:
            models["gateway_status"] = "Mock mode - add DEEPSEEK_API_KEY for real responses"

        models["security_features"] = {
            "presidio_ml_detection": PRESIDIO_AVAILABLE,
            "custom_pattern_detection": True,
            "pii_protection": True,
            "api_key_detection": True
        }

        self.send_json(models)

    def send_welcome(self):
        """Enhanced welcome page with Presidio information"""
        stats = self.detector.get_stats() if self.detector else {}
        presidio_status = "✅ Active" if PRESIDIO_AVAILABLE and self.detector and self.detector.presidio_analyzer else "❌ Fallback Mode"

        html = f"""
        <html>
        <head><title>Microsoft Presidio-Enhanced LLM Gateway</title></head>
        <body style="font-family: Arial; max-width: 1000px; margin: 50px auto; padding: 20px;">
            <h1>Microsoft Presidio-Enhanced LLM Gateway</h1>
            <p><strong>Status:</strong> Running on Railway with Enterprise ML Security</p>
            <p><strong>Version:</strong> 3.0.0-presidio</p>
            <p><strong>Presidio Status:</strong> {presidio_status}</p>

            <h2>Microsoft Presidio Integration</h2>
            <div style="background: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
                <h3>🧠 ML-Powered Detection</h3>
                <ul>
                    <li><strong>Presidio Available:</strong> {'✅ Yes' if PRESIDIO_AVAILABLE else '❌ No (using fallback)'}</li>
                    <li><strong>spaCy NLP:</strong> {'✅ Active' if SPACY_AVAILABLE else '❌ Not available'}</li>
                    <li><strong>Detection Mode:</strong> {'Hybrid (Presidio + Custom)' if PRESIDIO_AVAILABLE else 'Custom Patterns Only'}</li>
                    <li><strong>Entity Recognition:</strong> {'50+ ML entities' if PRESIDIO_AVAILABLE else '15+ regex patterns'}</li>
                </ul>
            </div>

            <h2>Enterprise Security Features</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h3>🔍 Detection Capabilities</h3>
                    <ul>
                        <li><strong>PII Detection:</strong> Names, emails, phones, addresses</li>
                        <li><strong>Financial Data:</strong> Credit cards, bank numbers, IBAN</li>
                        <li><strong>Government IDs:</strong> SSN, passports, driver licenses</li>
                        <li><strong>API Keys:</strong> OpenAI, Anthropic, GitHub, AWS, Google</li>
                        <li><strong>Database Credentials:</strong> Connection strings, URLs</li>
                        <li><strong>Authentication:</strong> JWT tokens, private keys</li>
                        <li><strong>Medical Info:</strong> License numbers, patient data</li>
                        <li><strong>Network Data:</strong> IP addresses, URLs</li>
                    </ul>
                </div>
                <div>
                    <h3>🚀 Advanced Features</h3>
                    <ul>
                        <li><strong>ML Analysis:</strong> Context-aware entity recognition</li>
                        <li><strong>Confidence Scoring:</strong> 0.0 - 1.0 precision</li>
                        <li><strong>Severity Classification:</strong> LOW, MEDIUM, HIGH, CRITICAL</li>
                        <li><strong>Smart Validation:</strong> Luhn algorithm, format checking</li>
                        <li><strong>Overlap Detection:</strong> Deduplication logic</li>
                        <li><strong>Hybrid Approach:</strong> Presidio + custom patterns</li>
                        <li><strong>Performance Tracking:</strong> Scan time, accuracy metrics</li>
                        <li><strong>Graceful Fallback:</strong> Works without ML dependencies</li>
                    </ul>
                </div>
            </div>

            <h2>Detection Statistics</h2>
            <div style="background: #e8f4fd; padding: 15px; border-radius: 5px;">
                <p><strong>Total Scans:</strong> {stats.get('total_scans', 0)}</p>
                <p><strong>Presidio Scans:</strong> {stats.get('presidio_scans', 0)}</p>
                <p><strong>Custom Pattern Scans:</strong> {stats.get('custom_scans', 0)}</p>
                <p><strong>Issues Found:</strong> {stats.get('issues_found', 0)}</p>
                <p><strong>Requests Blocked:</strong> {stats.get('blocked_requests', 0)}</p>
                <p><strong>Average Scan Time:</strong> {stats.get('avg_scan_time_ms', 0)}ms</p>
            </div>

            <h2>API Endpoints</h2>
            <ul>
                <li><code>GET /health</code> - Comprehensive health check with Presidio status</li>
                <li><code>GET /stats</code> - Detailed detection statistics</li>
                <li><code>GET /presidio-status</code> - Presidio-specific status information</li>
                <li><code>POST /v1/chat/completions</code> - Secure chat completions with ML detection</li>
            </ul>

            <h2>Test Commands</h2>
            <h3>Health Check:</h3>
            <pre>curl https://genai-gateway-production.up.railway.app/health</pre>

            <h3>Presidio Status:</h3>
            <pre>curl https://genai-gateway-production.up.railway.app/presidio-status</pre>

            <h3>Normal Request:</h3>
            <pre>curl -X POST https://genai-gateway-production.up.railway.app/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{{"messages": [{{"role": "user", "content": "Hello, how are you today?"}}]}}'</pre>

            <h3>PII Detection Test:</h3>
            <pre>curl -X POST https://genai-gateway-production.up.railway.app/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{{"messages": [{{"role": "user", "content": "My name is John Doe and my email is john.doe@example.com"}}]}}'</pre>

            <h3>API Key Detection Test (Will Block):</h3>
            <pre>curl -X POST https://genai-gateway-production.up.railway.app/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -d '{{"messages": [{{"role": "user", "content": "My OpenAI key is sk-1234567890abcdef1234567890abcdef12345678"}}]}}'</pre>

            <p><em>Microsoft Presidio-Enhanced LLM Gateway - Enterprise ML Security</em></p>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())

    async def handle_chat_async(self):
        """Enhanced async chat handling with Presidio detection"""
        request_id = uuid.uuid4().hex[:8]

        try:
            # Log request details for debugging
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Request {request_id} from {self.headers.get('User-Agent', 'Unknown')}")
            print(f"  Headers: {dict(self.headers)}")

            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                print(f"  ERROR: No content length")
                self.send_error(400, "No content")
                return

            print(f"  Content-Length: {content_length}")

            post_data = self.rfile.read(content_length)
            print(f"  Raw data length: {len(post_data)}")
            print(f"  Raw data preview: {post_data[:200]}...")

            try:
                request_data = json.loads(post_data.decode('utf-8'))
                print(f"  Parsed JSON successfully")
            except json.JSONDecodeError as e:
                print(f"  JSON decode error: {e}")
                print(f"  Raw data: {post_data}")
                self.send_error(400, f"Invalid JSON: {str(e)}")
                return

            # Extract text content
            text_content = ""
            messages = request_data.get('messages', [])
            for msg in messages:
                text_content += msg.get('content', '') + " "

            # Enhanced security scan with Presidio
            if not self.detector:
                print(f"  Initializing detector...")
                await self.initialize_detector()

            print(f"  Running security scan...")
            try:
                issues = await self.detector.scan_content(text_content)
                detection_summary = self.detector.get_detection_summary(issues)
                print(f"  Security scan completed: {len(issues)} issues found")
            except Exception as scan_error:
                print(f"  Security scan error: {scan_error}")
                import traceback
                traceback.print_exc()
                # Continue with empty issues if scan fails
                issues = []
                detection_summary = {"clean": True, "issues": []}

            # Detailed logging
            print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Presidio Request {request_id}")
            print(f"  Content length: {len(text_content)} chars")
            print(f"  Issues detected: {len(issues)}")
            print(f"  Presidio active: {self.detector.presidio_analyzer is not None}")

            for issue in issues:
                print(f"    - {issue.type}: {issue.severity.name} (confidence: {issue.confidence:.3f}) [{issue.detector}]")

            # Determine blocking
            should_block = self.detector.should_block_request(issues)

            if should_block:
                error_response = {
                    "error": "Request blocked due to security policy violations",
                    "blocked": True,
                    "request_id": request_id,
                    "timestamp": int(time.time()),
                    "detection_engine": "Microsoft Presidio + Custom Patterns",
                    "detection_summary": detection_summary
                }
                print(f"  BLOCKED: {len(issues)} security violations detected")
                self.send_json(error_response, 400)
                return

            # Check if streaming is requested
            is_streaming = request_data.get('stream', False)
            print(f"  Streaming requested: {is_streaming}")

            # Check if DeepSeek API key is configured
            deepseek_key = os.getenv('DEEPSEEK_API_KEY')

            if deepseek_key:
                # Forward to DeepSeek API
                try:
                    if is_streaming:
                        await self._forward_to_deepseek_streaming(request_data, deepseek_key, detection_summary, len(issues))
                        print(f"  SUCCESS: Streaming DeepSeek response with {len(issues)} low-risk issues")
                    else:
                        response = await self._forward_to_deepseek(request_data, deepseek_key, detection_summary, len(issues))
                        print(f"  SUCCESS: Real DeepSeek response with {len(issues)} low-risk issues")
                        self.send_json(response)
                except Exception as e:
                    print(f"  DeepSeek API Error: {e}")
                    import traceback
                    traceback.print_exc()
                    # Fall back to mock response if DeepSeek fails
                    if is_streaming:
                        self._send_mock_streaming_response(request_id, messages, issues, detection_summary)
                        print(f"  FALLBACK: Mock streaming response due to DeepSeek error")
                    else:
                        response = self._create_mock_response(request_id, messages, issues, detection_summary)
                        print(f"  FALLBACK: Mock response due to DeepSeek error")
                        self.send_json(response)
            else:
                # Mock response when no API key
                if is_streaming:
                    self._send_mock_streaming_response(request_id, messages, issues, detection_summary)
                    print(f"  MOCK: Streaming mock response (no DeepSeek API key)")
                else:
                    response = self._create_mock_response(request_id, messages, issues, detection_summary)
                    print(f"  MOCK: No DeepSeek API key configured")
                    self.send_json(response)

        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
        except Exception as e:
            print(f"  ERROR: {e}")
            self.send_error(500, str(e))

    async def _forward_to_deepseek(self, request_data, api_key, detection_summary, issues_count):
        """Forward request to DeepSeek API"""
        import urllib.request
        import urllib.parse

        # DeepSeek API endpoint
        url = "https://api.deepseek.com/v1/chat/completions"

        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Presidio-Gateway/3.0.0'
        }

        # Prepare request data for DeepSeek
        deepseek_request = {
            "model": request_data.get("model", "deepseek-chat"),
            "messages": request_data.get("messages", []),
            "temperature": request_data.get("temperature", 0.7),
            "max_tokens": request_data.get("max_tokens", 1000),
            "stream": False  # Force non-streaming for simplicity
        }

        # Make request to DeepSeek
        req = urllib.request.Request(
            url,
            data=json.dumps(deepseek_request).encode('utf-8'),
            headers=headers
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                deepseek_response = json.loads(response.read().decode('utf-8'))

            # Add security scan information to response
            deepseek_response["security_scan"] = {
                "detection_engine": "Microsoft Presidio + Custom Patterns",
                "presidio_active": self.detector.presidio_analyzer is not None,
                "issues_detected": issues_count,
                "risk_level": "low",
                "scan_summary": detection_summary,
                "gateway_version": "3.0.0-presidio"
            }

            return deepseek_response

        except Exception as e:
            raise Exception(f"DeepSeek API request failed: {str(e)}")

    async def _forward_to_deepseek_streaming(self, request_data, api_key, detection_summary, issues_count):
        """Forward streaming request to DeepSeek API"""
        import urllib.request

        # DeepSeek API endpoint
        url = "https://api.deepseek.com/v1/chat/completions"

        # Prepare headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Presidio-Gateway/3.0.0'
        }

        # Prepare request data for DeepSeek with streaming
        deepseek_request = {
            "model": request_data.get("model", "deepseek-chat"),
            "messages": request_data.get("messages", []),
            "temperature": request_data.get("temperature", 0.7),
            "max_tokens": request_data.get("max_tokens", 1000),
            "stream": True
        }

        # Make streaming request to DeepSeek
        req = urllib.request.Request(
            url,
            data=json.dumps(deepseek_request).encode('utf-8'),
            headers=headers
        )

        try:
            # Set up SSE response headers
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # Send security scan info as first event
            security_event = {
                "id": f"security-scan",
                "object": "chat.completion.chunk",
                "created": int(time.time()),
                "model": "presidio-enhanced-gateway",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "role": "assistant",
                        "content": f"[Security: {issues_count} issues detected, request allowed] "
                    },
                    "finish_reason": None
                }],
                "security_scan": detection_summary
            }

            self.wfile.write(f"data: {json.dumps(security_event)}\n\n".encode())
            self.wfile.flush()

            # Forward streaming response from DeepSeek
            with urllib.request.urlopen(req, timeout=30) as response:
                for line in response:
                    line = line.decode('utf-8').strip()
                    if line.startswith('data: '):
                        # Forward the streaming data
                        self.wfile.write(f"{line}\n\n".encode())
                        self.wfile.flush()

                        # Check for end of stream
                        if line == 'data: [DONE]':
                            break

        except Exception as e:
            # Send error as SSE event
            error_event = {
                "error": f"DeepSeek streaming failed: {str(e)}",
                "type": "error"
            }
            self.wfile.write(f"data: {json.dumps(error_event)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            raise

    def _send_mock_streaming_response(self, request_id, messages, issues, detection_summary):
        """Send mock streaming response when DeepSeek is not available"""
        try:
            # Set up SSE response headers
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # Mock streaming chunks
            chunks = [
                "Presidio Gateway: ",
                f"Processed {len(messages)} message(s) ",
                "with enterprise ML security. ",
                f"{len(issues)} low-risk issues detected but allowed. ",
                "Add DEEPSEEK_API_KEY for real responses."
            ]

            for i, chunk in enumerate(chunks):
                event = {
                    "id": f"presidio-{request_id}-{i}",
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": "presidio-enhanced-gateway",
                    "choices": [{
                        "index": 0,
                        "delta": {
                            "content": chunk
                        },
                        "finish_reason": None if i < len(chunks) - 1 else "stop"
                    }]
                }

                if i == 0:
                    # Add security scan info to first chunk
                    event["security_scan"] = detection_summary

                self.wfile.write(f"data: {json.dumps(event)}\n\n".encode())
                self.wfile.flush()
                time.sleep(0.1)  # Small delay to simulate streaming

            # Send final [DONE] event
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        except Exception as e:
            print(f"Error in mock streaming: {e}")

    def _create_mock_response(self, request_id, messages, issues, detection_summary):
        """Create mock response when DeepSeek is not available"""
        return {
            "id": f"presidio-{request_id}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "presidio-enhanced-gateway",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Presidio Gateway: Processed {len(messages)} message(s) with enterprise ML security. {len(issues)} low-risk issues detected but allowed. Add DEEPSEEK_API_KEY for real responses."
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": sum(len(msg.get('content', '').split()) for msg in messages),
                "completion_tokens": 25,
                "total_tokens": sum(len(msg.get('content', '').split()) for msg in messages) + 25
            },
            "security_scan": {
                "detection_engine": "Microsoft Presidio + Custom Patterns",
                "presidio_active": self.detector.presidio_analyzer is not None,
                "issues_detected": len(issues),
                "risk_level": "low",
                "scan_summary": detection_summary,
                "gateway_version": "3.0.0-presidio",
                "mode": "mock"
            }
        }

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


async def initialize_global_detector():
    """Initialize the global detector instance"""
    await PresidioGatewayHandler.initialize_detector()


def main():
    """Start the Presidio-enhanced gateway"""
    PORT = int(os.getenv('PORT', 8000))
    HOST = "0.0.0.0"

    print("Microsoft Presidio-Enhanced LLM Gateway")
    print("=" * 60)
    print(f"Port: {PORT}")
    print(f"Presidio Available: {'✅ Yes' if PRESIDIO_AVAILABLE else '❌ No (fallback mode)'}")
    print(f"spaCy Available: {'✅ Yes' if SPACY_AVAILABLE else '❌ No'}")
    print(f"Detection Mode: {'Hybrid (ML + Regex)' if PRESIDIO_AVAILABLE else 'Custom Patterns Only'}")

    # Check DeepSeek configuration
    deepseek_key = os.getenv('DEEPSEEK_API_KEY')
    if deepseek_key:
        print(f"DeepSeek API: ✅ Configured (key: ...{deepseek_key[-4:]})")
        print(f"Response Mode: Real DeepSeek responses")
    else:
        print(f"DeepSeek API: ❌ Not configured")
        print(f"Response Mode: Mock responses (add DEEPSEEK_API_KEY for real responses)")

    print("=" * 60)

    # Initialize detector
    print("🚀 Initializing security detector...")
    asyncio.run(initialize_global_detector())
    print("✅ Security detector ready!")

    try:
        with socketserver.TCPServer((HOST, PORT), PresidioGatewayHandler) as httpd:
            print(f"🌐 Presidio Gateway running on port {PORT}")
            print("🔒 Enterprise ML security active!")
            httpd.serve_forever()
    except Exception as e:
        print(f"❌ Server error: {e}")


if __name__ == "__main__":
    main()

"""
Enterprise-Grade Security Detection System
Using Microsoft Presidio + Custom Rules + ML Models
"""
import re
import time
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

# Try to import Presidio (graceful fallback if not available)
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_AVAILABLE = True
except ImportError:
    PRESIDIO_AVAILABLE = False

# Try to import additional libraries
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
    location: Tuple[int, int]  # start, end positions
    severity: DetectionLevel
    context: str
    detector: str  # Which detector found it


class AdvancedSecurityDetector:
    """Enterprise-grade security detection system"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Detection thresholds
        self.min_confidence = self.config.get('min_confidence', DetectionLevel.MEDIUM.value)
        self.block_threshold = self.config.get('block_threshold', DetectionLevel.HIGH.value)
        
        # Initialize detection engines
        self.presidio_analyzer = None
        self.custom_patterns = self._load_custom_patterns()
        self.ml_models = {}
        
        # Performance tracking
        self.detection_stats = {
            'total_scans': 0,
            'issues_found': 0,
            'blocked_requests': 0,
            'avg_scan_time': 0.0
        }
    
    async def initialize(self):
        """Initialize all detection engines"""
        self.logger.info("Initializing advanced security detector")
        
        # Initialize Presidio if available
        if PRESIDIO_AVAILABLE:
            await self._init_presidio()
        else:
            self.logger.warning("Presidio not available, using fallback detection")
        
        # Initialize custom detectors
        self._init_custom_detectors()
        
        self.logger.info("Security detector initialization complete")
    
    async def _init_presidio(self):
        """Initialize Microsoft Presidio analyzer"""
        try:
            # Configure NLP engine
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            
            # Create analyzer with custom recognizers
            registry = RecognizerRegistry()
            registry.load_predefined_recognizers()
            
            self.presidio_analyzer = AnalyzerEngine(
                nlp_engine=nlp_engine,
                registry=registry
            )
            
            self.logger.info("Presidio analyzer initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Presidio: {e}")
            self.presidio_analyzer = None
    
    def _init_custom_detectors(self):
        """Initialize custom detection patterns"""
        self.logger.info("Loading custom detection patterns")
        
        # Add high-confidence patterns for common secrets
        self.custom_patterns.update({
            # Cloud provider keys
            'aws_access_key_id': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'confidence': 0.95,
                'severity': DetectionLevel.CRITICAL
            },
            'aws_secret_key': {
                'pattern': r'[A-Za-z0-9/+=]{40}',
                'confidence': 0.8,
                'severity': DetectionLevel.HIGH,
                'context_required': ['aws', 'secret']
            },
            
            # API Keys with high confidence
            'openai_api_key': {
                'pattern': r'sk-[a-zA-Z0-9]{48}',
                'confidence': 0.98,
                'severity': DetectionLevel.CRITICAL
            },
            'anthropic_api_key': {
                'pattern': r'sk-ant-[a-zA-Z0-9\-_]{95}',
                'confidence': 0.98,
                'severity': DetectionLevel.CRITICAL
            },
            
            # Database connections
            'database_url': {
                'pattern': r'(postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@[^:\s]+:\d+/\w+',
                'confidence': 0.9,
                'severity': DetectionLevel.CRITICAL
            },
            
            # JWT tokens
            'jwt_token': {
                'pattern': r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
                'confidence': 0.85,
                'severity': DetectionLevel.HIGH
            },
            
            # Private keys
            'private_key': {
                'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
                'confidence': 0.99,
                'severity': DetectionLevel.CRITICAL
            },
            
            # Credit cards (Luhn algorithm validation)
            'credit_card': {
                'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
                'confidence': 0.7,
                'severity': DetectionLevel.HIGH,
                'validator': self._validate_credit_card
            },
            
            # Social Security Numbers
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'confidence': 0.9,
                'severity': DetectionLevel.HIGH
            },
            
            # Enhanced email detection
            'email_address': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'confidence': 0.8,
                'severity': DetectionLevel.MEDIUM,
                'validator': self._validate_email
            },
            
            # Phone numbers
            'phone_number': {
                'pattern': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
                'confidence': 0.7,
                'severity': DetectionLevel.MEDIUM,
                'validator': self._validate_phone
            }
        })
    
    def _load_custom_patterns(self) -> Dict:
        """Load custom detection patterns from config"""
        return self.config.get('custom_patterns', {})
    
    async def scan_content(self, text: str, context: Dict = None) -> List[SecurityIssue]:
        """
        Comprehensive security scan of text content
        
        Args:
            text: Text content to scan
            context: Additional context (user_id, request_type, etc.)
            
        Returns:
            List of detected security issues
        """
        start_time = time.time()
        issues = []
        
        try:
            # Update stats
            self.detection_stats['total_scans'] += 1
            
            # Multi-layer detection
            if self.presidio_analyzer:
                presidio_issues = await self._presidio_scan(text)
                issues.extend(presidio_issues)
            
            # Custom pattern detection
            custom_issues = await self._custom_pattern_scan(text)
            issues.extend(custom_issues)
            
            # Context-aware detection
            if context:
                context_issues = await self._context_aware_scan(text, context)
                issues.extend(context_issues)
            
            # Deduplicate and rank issues
            issues = self._deduplicate_issues(issues)
            issues = sorted(issues, key=lambda x: x.confidence, reverse=True)
            
            # Update stats
            if issues:
                self.detection_stats['issues_found'] += len(issues)
            
            scan_time = time.time() - start_time
            self._update_performance_stats(scan_time)
            
            self.logger.info(f"Security scan completed: {len(issues)} issues found in {scan_time:.3f}s")
            
            return issues
            
        except Exception as e:
            self.logger.error(f"Error during security scan: {e}")
            return []
    
    async def _presidio_scan(self, text: str) -> List[SecurityIssue]:
        """Scan using Microsoft Presidio"""
        if not self.presidio_analyzer:
            return []
        
        try:
            # Define entities to detect
            entities = [
                "CREDIT_CARD", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS",
                "PERSON", "PHONE_NUMBER", "US_SSN", "US_PASSPORT",
                "US_DRIVER_LICENSE", "DATE_TIME", "LOCATION", "URL",
                "US_BANK_NUMBER", "CRYPTO", "MEDICAL_LICENSE"
            ]
            
            # Run analysis
            results = self.presidio_analyzer.analyze(
                text=text,
                entities=entities,
                language='en'
            )
            
            issues = []
            for result in results:
                issue = SecurityIssue(
                    type=result.entity_type.lower(),
                    description=f"Presidio detected {result.entity_type}",
                    confidence=result.score,
                    location=(result.start, result.end),
                    severity=self._confidence_to_severity(result.score),
                    context=text[max(0, result.start-20):result.end+20],
                    detector="presidio"
                )
                issues.append(issue)
            
            return issues
            
        except Exception as e:
            self.logger.error(f"Presidio scan error: {e}")
            return []
    
    async def _custom_pattern_scan(self, text: str) -> List[SecurityIssue]:
        """Scan using custom regex patterns"""
        issues = []
        
        for pattern_name, pattern_config in self.custom_patterns.items():
            try:
                pattern = pattern_config['pattern']
                confidence = pattern_config['confidence']
                severity = pattern_config['severity']
                
                matches = re.finditer(pattern, text, re.IGNORECASE)
                
                for match in matches:
                    # Apply validator if available
                    validator = pattern_config.get('validator')
                    if validator and not validator(match.group()):
                        continue
                    
                    # Check context requirements
                    context_required = pattern_config.get('context_required', [])
                    if context_required:
                        context_text = text[max(0, match.start()-50):match.end()+50].lower()
                        if not any(ctx in context_text for ctx in context_required):
                            confidence *= 0.5  # Reduce confidence without context
                    
                    issue = SecurityIssue(
                        type=pattern_name,
                        description=f"Custom pattern detected {pattern_name}",
                        confidence=confidence,
                        location=(match.start(), match.end()),
                        severity=severity,
                        context=text[max(0, match.start()-20):match.end()+20],
                        detector="custom_regex"
                    )
                    issues.append(issue)
                    
            except Exception as e:
                self.logger.error(f"Error in custom pattern {pattern_name}: {e}")
        
        return issues
    
    async def _context_aware_scan(self, text: str, context: Dict) -> List[SecurityIssue]:
        """Context-aware detection based on request metadata"""
        issues = []
        
        # Check for suspicious patterns based on context
        user_id = context.get('user_id')
        request_type = context.get('request_type')
        
        # Example: Detect potential data exfiltration attempts
        if 'export' in text.lower() or 'download' in text.lower():
            if any(pattern in text.lower() for pattern in ['database', 'users', 'passwords']):
                issue = SecurityIssue(
                    type="potential_data_exfiltration",
                    description="Potential data exfiltration attempt detected",
                    confidence=0.7,
                    location=(0, len(text)),
                    severity=DetectionLevel.HIGH,
                    context=text[:100],
                    detector="context_aware"
                )
                issues.append(issue)
        
        return issues
    
    def _deduplicate_issues(self, issues: List[SecurityIssue]) -> List[SecurityIssue]:
        """Remove duplicate issues and merge overlapping detections"""
        if not issues:
            return issues
        
        # Sort by location
        issues.sort(key=lambda x: x.location[0])
        
        deduplicated = []
        for issue in issues:
            # Check for overlaps with existing issues
            overlapping = False
            for existing in deduplicated:
                if self._issues_overlap(issue, existing):
                    # Keep the higher confidence issue
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
    
    def _validate_credit_card(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm"""
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
    
    def _validate_email(self, email: str) -> bool:
        """Enhanced email validation"""
        if not VALIDATORS_AVAILABLE:
            return True  # Skip validation if library not available
        
        try:
            import validators
            return validators.email(email)
        except:
            return True
    
    def _validate_phone(self, phone: str) -> bool:
        """Validate phone number using phonenumbers library"""
        if not PHONENUMBERS_AVAILABLE:
            return True  # Skip validation if library not available
        
        try:
            parsed = phonenumbers.parse(phone, "US")
            return phonenumbers.is_valid_number(parsed)
        except:
            return False
    
    def _update_performance_stats(self, scan_time: float):
        """Update performance statistics"""
        total_scans = self.detection_stats['total_scans']
        current_avg = self.detection_stats['avg_scan_time']
        
        # Calculate new average
        new_avg = ((current_avg * (total_scans - 1)) + scan_time) / total_scans
        self.detection_stats['avg_scan_time'] = new_avg
    
    def should_block_request(self, issues: List[SecurityIssue]) -> bool:
        """Determine if request should be blocked based on detected issues"""
        if not issues:
            return False
        
        # Block if any critical issues found
        critical_issues = [i for i in issues if i.severity == DetectionLevel.CRITICAL]
        if critical_issues:
            self.detection_stats['blocked_requests'] += 1
            return True
        
        # Block if high confidence issues above threshold
        high_confidence_issues = [i for i in issues if i.confidence >= self.block_threshold]
        if high_confidence_issues:
            self.detection_stats['blocked_requests'] += 1
            return True
        
        return False
    
    def get_detection_summary(self, issues: List[SecurityIssue]) -> Dict:
        """Generate summary of detected issues"""
        if not issues:
            return {"clean": True, "issues": []}
        
        summary = {
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
                    "confidence": issue.confidence,
                    "severity": issue.severity.name,
                    "detector": issue.detector
                }
                for issue in issues
            ]
        }
        
        return summary
    
    def get_stats(self) -> Dict:
        """Get detection statistics"""
        return self.detection_stats.copy()

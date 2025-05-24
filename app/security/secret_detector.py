"""
Secret Detection using regex patterns
"""
import re
import time
from typing import List, Dict, Pattern
import structlog

logger = structlog.get_logger()


class SecretDetector:
    """Detect secrets and sensitive information using regex patterns"""
    
    def __init__(self):
        self.patterns: Dict[str, Pattern] = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, Pattern]:
        """Compile regex patterns for secret detection"""
        patterns = {
            # API Keys
            "openai_api_key": re.compile(r'sk-[a-zA-Z0-9]{48}', re.IGNORECASE),
            "anthropic_api_key": re.compile(r'sk-ant-[a-zA-Z0-9\-_]{95}', re.IGNORECASE),
            "google_api_key": re.compile(r'AIza[0-9A-Za-z\-_]{35}', re.IGNORECASE),
            "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}', re.IGNORECASE),
            "github_token": re.compile(r'ghp_[a-zA-Z0-9]{36}', re.IGNORECASE),
            "github_oauth": re.compile(r'gho_[a-zA-Z0-9]{36}', re.IGNORECASE),
            "slack_token": re.compile(r'xox[baprs]-[a-zA-Z0-9\-]{10,72}', re.IGNORECASE),
            
            # Generic patterns
            "generic_api_key": re.compile(r'["\']?[a-z_]*api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{20,}["\']?', re.IGNORECASE),
            "generic_secret": re.compile(r'["\']?[a-z_]*secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{20,}["\']?', re.IGNORECASE),
            "generic_token": re.compile(r'["\']?[a-z_]*token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_]{20,}["\']?', re.IGNORECASE),
            "generic_password": re.compile(r'["\']?password["\']?\s*[:=]\s*["\']?[a-zA-Z0-9\-_!@#$%^&*()]{8,}["\']?', re.IGNORECASE),
            
            # Database connections
            "database_url": re.compile(r'[a-z]+://[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_!@#$%^&*()]+@[a-zA-Z0-9\-_.]+:[0-9]+/[a-zA-Z0-9\-_]+', re.IGNORECASE),
            "mongodb_url": re.compile(r'mongodb(\+srv)?://[a-zA-Z0-9\-_]+:[a-zA-Z0-9\-_!@#$%^&*()]+@[a-zA-Z0-9\-_.]+', re.IGNORECASE),
            
            # JWT tokens
            "jwt_token": re.compile(r'eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+', re.IGNORECASE),
            
            # Private keys
            "private_key": re.compile(r'-----BEGIN [A-Z ]+PRIVATE KEY-----', re.IGNORECASE),
            "rsa_private_key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE),
            
            # Cloud provider specific
            "azure_storage_key": re.compile(r'[a-zA-Z0-9+/]{88}==', re.IGNORECASE),
            "gcp_service_account": re.compile(r'"type":\s*"service_account"', re.IGNORECASE),
            
            # Common environment variables
            "env_secret": re.compile(r'[A-Z_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z_]*\s*=\s*["\']?[a-zA-Z0-9\-_!@#$%^&*()]{8,}["\']?', re.IGNORECASE),
        }
        
        return patterns
    
    def detect(self, text: str) -> List[str]:
        """
        Detect secrets in the given text
        
        Args:
            text: Text to analyze for secrets
            
        Returns:
            List of secret types detected
        """
        start_time = time.time()
        detected_secrets = []
        
        try:
            for secret_type, pattern in self.patterns.items():
                matches = pattern.findall(text)
                if matches:
                    detected_secrets.append(f"{secret_type} ({len(matches)} occurrence(s))")
            
            scan_time = (time.time() - start_time) * 1000
            
            if detected_secrets:
                logger.warning("Secrets detected", 
                             types=detected_secrets, 
                             scan_time_ms=scan_time)
            else:
                logger.debug("No secrets detected", scan_time_ms=scan_time)
            
            return detected_secrets
            
        except Exception as e:
            logger.error("Error during secret detection", error=str(e))
            return []
    
    def add_custom_pattern(self, name: str, pattern: str):
        """Add a custom regex pattern for secret detection"""
        try:
            self.patterns[name] = re.compile(pattern, re.IGNORECASE)
            logger.info("Added custom secret pattern", name=name)
        except re.error as e:
            logger.error("Invalid regex pattern", name=name, pattern=pattern, error=str(e))
            raise ValueError(f"Invalid regex pattern: {e}")
    
    def remove_pattern(self, name: str):
        """Remove a pattern from detection"""
        if name in self.patterns:
            del self.patterns[name]
            logger.info("Removed secret pattern", name=name)
        else:
            logger.warning("Pattern not found", name=name)

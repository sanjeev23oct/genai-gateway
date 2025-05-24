"""
PII Detection using Microsoft Presidio
"""
import asyncio
import time
from typing import List, Optional
import structlog
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

logger = structlog.get_logger()


class PIIDetector:
    """PII detection using Microsoft Presidio"""
    
    def __init__(self):
        self.analyzer: Optional[AnalyzerEngine] = None
        self.initialized = False
    
    async def initialize(self):
        """Initialize the PII detection engine"""
        try:
            logger.info("Initializing PII detector")
            
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            self.analyzer = await loop.run_in_executor(None, self._create_analyzer)
            
            self.initialized = True
            logger.info("PII detector initialized successfully")
            
        except Exception as e:
            logger.error("Failed to initialize PII detector", error=str(e))
            raise
    
    def _create_analyzer(self) -> AnalyzerEngine:
        """Create the analyzer engine (runs in thread pool)"""
        # Create NLP engine configuration
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        
        # Create NLP engine based on configuration
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        
        # Create analyzer with the NLP engine
        analyzer = AnalyzerEngine(nlp_engine=nlp_engine)
        
        return analyzer
    
    async def detect(self, text: str) -> List[str]:
        """
        Detect PII in the given text
        
        Args:
            text: Text to analyze for PII
            
        Returns:
            List of PII types detected
        """
        if not self.initialized or not self.analyzer:
            logger.warning("PII detector not initialized, skipping detection")
            return []
        
        try:
            start_time = time.time()
            
            # Run analysis in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None, 
                self._analyze_text, 
                text
            )
            
            scan_time = (time.time() - start_time) * 1000
            
            # Extract entity types
            detected_types = []
            for result in results:
                entity_info = f"{result.entity_type} (confidence: {result.score:.2f})"
                detected_types.append(entity_info)
            
            if detected_types:
                logger.warning("PII detected", 
                             types=detected_types, 
                             scan_time_ms=scan_time)
            else:
                logger.debug("No PII detected", scan_time_ms=scan_time)
            
            return detected_types
            
        except Exception as e:
            logger.error("Error during PII detection", error=str(e))
            return []
    
    def _analyze_text(self, text: str):
        """Analyze text for PII (runs in thread pool)"""
        # Define entities to detect
        entities = [
            "CREDIT_CARD", "EMAIL_ADDRESS", "IBAN_CODE", "IP_ADDRESS",
            "PERSON", "PHONE_NUMBER", "US_SSN", "US_PASSPORT",
            "US_DRIVER_LICENSE", "DATE_TIME", "LOCATION", "URL"
        ]
        
        return self.analyzer.analyze(
            text=text,
            entities=entities,
            language='en'
        )

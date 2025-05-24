"""
LLM Gateway MVP - Main FastAPI Application
"""
import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import structlog

from app.models import ChatRequest, ChatResponse, HealthResponse
from app.security.pii_detector import PIIDetector
from app.security.secret_detector import SecretDetector
from app.providers.deepseek_client import DeepSeekClient
from app.utils.logger import setup_logging

# Load environment variables
load_dotenv()

# Setup structured logging
setup_logging()
logger = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    logger.info("Starting LLM Gateway MVP")
    
    # Initialize components
    app.state.pii_detector = PIIDetector()
    app.state.secret_detector = SecretDetector()
    app.state.deepseek_client = DeepSeekClient()
    
    # Load PII detection models
    if os.getenv("ENABLE_PII_DETECTION", "true").lower() == "true":
        await app.state.pii_detector.initialize()
        logger.info("PII detection initialized")
    
    logger.info("LLM Gateway MVP started successfully")
    yield
    
    logger.info("Shutting down LLM Gateway MVP")


# Create FastAPI app
app = FastAPI(
    title="LLM Gateway MVP",
    description="Secure gateway for LLM providers with PII/secret detection",
    version="0.1.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        components={
            "pii_detection": os.getenv("ENABLE_PII_DETECTION", "true").lower() == "true",
            "secret_detection": os.getenv("ENABLE_SECRET_DETECTION", "true").lower() == "true",
            "deepseek_provider": bool(os.getenv("DEEPSEEK_API_KEY"))
        }
    )


@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat_completions(request: ChatRequest, http_request: Request):
    """
    Main chat completions endpoint with security scanning
    """
    request_id = id(http_request)
    logger.info("Processing chat request", request_id=request_id)
    
    try:
        # Extract text content from messages
        text_content = ""
        for message in request.messages:
            text_content += f"{message.content}\n"
        
        # Security scanning
        security_issues = []
        
        # PII Detection
        if os.getenv("ENABLE_PII_DETECTION", "true").lower() == "true":
            pii_results = await app.state.pii_detector.detect(text_content)
            if pii_results:
                security_issues.extend([f"PII detected: {result}" for result in pii_results])
        
        # Secret Detection
        if os.getenv("ENABLE_SECRET_DETECTION", "true").lower() == "true":
            secret_results = app.state.secret_detector.detect(text_content)
            if secret_results:
                security_issues.extend([f"Secret detected: {result}" for result in secret_results])
        
        # Block request if security issues found and blocking is enabled
        if security_issues and os.getenv("BLOCK_ON_DETECTION", "true").lower() == "true":
            logger.warning("Request blocked due to security issues", 
                         request_id=request_id, 
                         issues=security_issues)
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Request blocked due to security policy violations",
                    "issues": security_issues
                }
            )
        
        # Forward to DeepSeek
        response = await app.state.deepseek_client.chat_completion(request)
        
        logger.info("Request processed successfully", 
                   request_id=request_id,
                   model=request.model,
                   security_issues=security_issues)
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error processing request", 
                    request_id=request_id, 
                    error=str(e))
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("GATEWAY_HOST", "0.0.0.0")
    port = int(os.getenv("GATEWAY_PORT", "8000"))
    
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=True,
        log_level=os.getenv("LOG_LEVEL", "info").lower()
    )

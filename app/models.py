"""
Pydantic models for the LLM Gateway
"""
from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field


class Message(BaseModel):
    """Chat message model"""
    role: str = Field(..., description="Role of the message sender (user, assistant, system)")
    content: str = Field(..., description="Content of the message")


class ChatRequest(BaseModel):
    """Chat completion request model"""
    model: str = Field(default="deepseek-chat", description="Model to use for completion")
    messages: List[Message] = Field(..., description="List of messages in the conversation")
    temperature: Optional[float] = Field(default=0.7, ge=0.0, le=2.0, description="Sampling temperature")
    max_tokens: Optional[int] = Field(default=1000, ge=1, le=4000, description="Maximum tokens to generate")
    top_p: Optional[float] = Field(default=1.0, ge=0.0, le=1.0, description="Nucleus sampling parameter")
    stream: Optional[bool] = Field(default=False, description="Whether to stream the response")


class Choice(BaseModel):
    """Response choice model"""
    index: int
    message: Message
    finish_reason: Optional[str] = None


class Usage(BaseModel):
    """Token usage model"""
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class ChatResponse(BaseModel):
    """Chat completion response model"""
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: List[Choice]
    usage: Usage


class HealthResponse(BaseModel):
    """Health check response model"""
    status: str
    version: str
    components: Dict[str, Any]


class SecurityIssue(BaseModel):
    """Security issue model"""
    type: str = Field(..., description="Type of security issue (pii, secret, etc.)")
    description: str = Field(..., description="Description of the issue")
    location: Optional[str] = Field(None, description="Location where issue was found")
    confidence: Optional[float] = Field(None, description="Confidence score of detection")


class SecurityScanResult(BaseModel):
    """Security scan result model"""
    clean: bool = Field(..., description="Whether content is clean")
    issues: List[SecurityIssue] = Field(default_factory=list, description="List of security issues found")
    scan_time_ms: float = Field(..., description="Time taken for scan in milliseconds")

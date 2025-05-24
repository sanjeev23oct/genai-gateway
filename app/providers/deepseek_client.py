"""
DeepSeek API Client
"""
import os
import time
import uuid
from typing import Optional
import httpx
import structlog
from app.models import ChatRequest, ChatResponse, Choice, Message, Usage

logger = structlog.get_logger()


class DeepSeekClient:
    """Client for DeepSeek API"""
    
    def __init__(self):
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        self.base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        self.timeout = 60.0
        
        if not self.api_key:
            logger.warning("DEEPSEEK_API_KEY not found in environment variables")
    
    async def chat_completion(self, request: ChatRequest) -> ChatResponse:
        """
        Send chat completion request to DeepSeek
        
        Args:
            request: Chat completion request
            
        Returns:
            Chat completion response
        """
        if not self.api_key:
            raise ValueError("DeepSeek API key not configured")
        
        # Prepare request payload
        payload = {
            "model": request.model,
            "messages": [
                {"role": msg.role, "content": msg.content} 
                for msg in request.messages
            ],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
            "top_p": request.top_p,
            "stream": request.stream
        }
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                logger.info("Sending request to DeepSeek", 
                           model=request.model, 
                           messages_count=len(request.messages))
                
                response = await client.post(
                    f"{self.base_url}/v1/chat/completions",
                    json=payload,
                    headers=headers
                )
                
                response.raise_for_status()
                response_data = response.json()
                
                # Convert to our response model
                chat_response = self._convert_response(response_data)
                
                logger.info("Received response from DeepSeek", 
                           response_id=chat_response.id,
                           usage=chat_response.usage.dict())
                
                return chat_response
                
        except httpx.HTTPStatusError as e:
            logger.error("DeepSeek API error", 
                        status_code=e.response.status_code,
                        response=e.response.text)
            raise ValueError(f"DeepSeek API error: {e.response.status_code}")
            
        except httpx.TimeoutException:
            logger.error("DeepSeek API timeout")
            raise ValueError("DeepSeek API timeout")
            
        except Exception as e:
            logger.error("Unexpected error calling DeepSeek", error=str(e))
            raise ValueError(f"DeepSeek API error: {str(e)}")
    
    def _convert_response(self, response_data: dict) -> ChatResponse:
        """Convert DeepSeek response to our response model"""
        
        # Extract choices
        choices = []
        for choice_data in response_data.get("choices", []):
            message_data = choice_data.get("message", {})
            choice = Choice(
                index=choice_data.get("index", 0),
                message=Message(
                    role=message_data.get("role", "assistant"),
                    content=message_data.get("content", "")
                ),
                finish_reason=choice_data.get("finish_reason")
            )
            choices.append(choice)
        
        # Extract usage
        usage_data = response_data.get("usage", {})
        usage = Usage(
            prompt_tokens=usage_data.get("prompt_tokens", 0),
            completion_tokens=usage_data.get("completion_tokens", 0),
            total_tokens=usage_data.get("total_tokens", 0)
        )
        
        return ChatResponse(
            id=response_data.get("id", str(uuid.uuid4())),
            object=response_data.get("object", "chat.completion"),
            created=response_data.get("created", int(time.time())),
            model=response_data.get("model", "deepseek-chat"),
            choices=choices,
            usage=usage
        )
    
    async def health_check(self) -> bool:
        """Check if DeepSeek API is accessible"""
        if not self.api_key:
            return False
        
        try:
            # Simple test request
            test_request = ChatRequest(
                model="deepseek-chat",
                messages=[Message(role="user", content="Hello")],
                max_tokens=1
            )
            
            await self.chat_completion(test_request)
            return True
            
        except Exception as e:
            logger.error("DeepSeek health check failed", error=str(e))
            return False

"""
Simple test script for the LLM Gateway MVP
"""
import asyncio
import httpx
import json


async def test_gateway():
    """Test the gateway functionality"""
    base_url = "http://localhost:8000"
    
    print("🧪 Testing LLM Gateway MVP")
    print("=" * 50)
    
    async with httpx.AsyncClient() as client:
        
        # Test 1: Health Check
        print("\n1. Testing Health Check...")
        try:
            response = await client.get(f"{base_url}/health")
            if response.status_code == 200:
                health_data = response.json()
                print("✅ Health check passed")
                print(f"   Status: {health_data['status']}")
                print(f"   Components: {health_data['components']}")
            else:
                print(f"❌ Health check failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Health check error: {e}")
        
        # Test 2: Normal Chat Request
        print("\n2. Testing Normal Chat Request...")
        try:
            chat_request = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "user", "content": "Hello! Can you help me write a simple Python function?"}
                ],
                "temperature": 0.7,
                "max_tokens": 100
            }
            
            response = await client.post(f"{base_url}/v1/chat/completions", json=chat_request)
            if response.status_code == 200:
                chat_data = response.json()
                print("✅ Normal chat request successful")
                print(f"   Response: {chat_data['choices'][0]['message']['content'][:100]}...")
                print(f"   Tokens used: {chat_data['usage']['total_tokens']}")
            else:
                print(f"❌ Chat request failed: {response.status_code}")
                print(f"   Error: {response.text}")
        except Exception as e:
            print(f"❌ Chat request error: {e}")
        
        # Test 3: Request with PII (should be blocked)
        print("\n3. Testing PII Detection...")
        try:
            pii_request = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "user", "content": "My email is john.doe@example.com and my phone is 555-123-4567. Can you help me?"}
                ],
                "temperature": 0.7,
                "max_tokens": 100
            }
            
            response = await client.post(f"{base_url}/v1/chat/completions", json=pii_request)
            if response.status_code == 400:
                error_data = response.json()
                print("✅ PII detection working - request blocked")
                print(f"   Issues detected: {error_data['detail']['issues']}")
            else:
                print(f"⚠️  PII detection may not be working: {response.status_code}")
        except Exception as e:
            print(f"❌ PII test error: {e}")
        
        # Test 4: Request with Secrets (should be blocked)
        print("\n4. Testing Secret Detection...")
        try:
            secret_request = {
                "model": "deepseek-chat",
                "messages": [
                    {"role": "user", "content": "Here's my API key: sk-1234567890abcdef1234567890abcdef12345678. Can you help me use it?"}
                ],
                "temperature": 0.7,
                "max_tokens": 100
            }
            
            response = await client.post(f"{base_url}/v1/chat/completions", json=secret_request)
            if response.status_code == 400:
                error_data = response.json()
                print("✅ Secret detection working - request blocked")
                print(f"   Issues detected: {error_data['detail']['issues']}")
            else:
                print(f"⚠️  Secret detection may not be working: {response.status_code}")
        except Exception as e:
            print(f"❌ Secret test error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Testing completed!")


if __name__ == "__main__":
    asyncio.run(test_gateway())

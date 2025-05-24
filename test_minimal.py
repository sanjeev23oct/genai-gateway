"""
Test script for the minimal gateway
"""
import urllib.request
import urllib.parse
import json
import time


def test_gateway():
    """Test the minimal gateway"""
    base_url = "http://localhost:8000"
    
    print("🧪 Testing Minimal LLM Gateway")
    print("=" * 50)
    
    # Test 1: Health Check
    print("\n1. Testing Health Check...")
    try:
        with urllib.request.urlopen(f"{base_url}/health") as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                print("✅ Health check passed")
                print(f"   Status: {data['status']}")
                print(f"   Version: {data['version']}")
                print(f"   Components: {data['components']}")
            else:
                print(f"❌ Health check failed: {response.status}")
    except Exception as e:
        print(f"❌ Health check error: {e}")
        print("   Make sure the gateway is running: py minimal_gateway.py")
        return
    
    # Test 2: Normal Chat Request
    print("\n2. Testing Normal Chat Request...")
    try:
        request_data = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "user", "content": "Hello! Can you help me write a Python function?"}
            ]
        }
        
        data = json.dumps(request_data).encode()
        req = urllib.request.Request(
            f"{base_url}/v1/chat/completions",
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                result = json.loads(response.read().decode())
                print("✅ Normal chat request successful")
                print(f"   Response: {result['choices'][0]['message']['content'][:100]}...")
                print(f"   Tokens: {result['usage']['total_tokens']}")
            else:
                print(f"❌ Chat request failed: {response.status}")
    except Exception as e:
        print(f"❌ Chat request error: {e}")
    
    # Test 3: Request with PII (should be blocked)
    print("\n3. Testing PII Detection...")
    try:
        request_data = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "user", "content": "My email is john.doe@example.com and my phone is 555-123-4567"}
            ]
        }
        
        data = json.dumps(request_data).encode()
        req = urllib.request.Request(
            f"{base_url}/v1/chat/completions",
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode())
                print("⚠️  PII detection may not be working - request went through")
        except urllib.error.HTTPError as e:
            if e.code == 400:
                error_data = json.loads(e.read().decode())
                print("✅ PII detection working - request blocked")
                print(f"   Issues: {error_data['issues']}")
            else:
                print(f"❌ Unexpected error: {e.code}")
    except Exception as e:
        print(f"❌ PII test error: {e}")
    
    # Test 4: Request with Secrets (should be blocked)
    print("\n4. Testing Secret Detection...")
    try:
        request_data = {
            "model": "deepseek-chat",
            "messages": [
                {"role": "user", "content": "Here's my API key: sk-1234567890abcdef1234567890abcdef12345678"}
            ]
        }
        
        data = json.dumps(request_data).encode()
        req = urllib.request.Request(
            f"{base_url}/v1/chat/completions",
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode())
                print("⚠️  Secret detection may not be working - request went through")
        except urllib.error.HTTPError as e:
            if e.code == 400:
                error_data = json.loads(e.read().decode())
                print("✅ Secret detection working - request blocked")
                print(f"   Issues: {error_data['issues']}")
            else:
                print(f"❌ Unexpected error: {e.code}")
    except Exception as e:
        print(f"❌ Secret test error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 Testing completed!")
    print("\nTo view the gateway in browser: http://localhost:8000")


if __name__ == "__main__":
    test_gateway()

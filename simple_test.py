"""
Simple test to verify Python environment
"""
import sys
import os

print("🧪 Testing Python Environment")
print("=" * 40)
print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")
print(f"Current directory: {os.getcwd()}")
print(f"Python path: {sys.path[:3]}...")

# Test basic imports
try:
    import json
    print("✅ json module works")
except ImportError as e:
    print(f"❌ json module failed: {e}")

try:
    import re
    print("✅ re module works")
except ImportError as e:
    print(f"❌ re module failed: {e}")

try:
    import asyncio
    print("✅ asyncio module works")
except ImportError as e:
    print(f"❌ asyncio module failed: {e}")

print("\n🔍 Checking project files:")
files_to_check = [
    "requirements.txt",
    "app/main.py",
    "app/models.py",
    ".env.example"
]

for file_path in files_to_check:
    if os.path.exists(file_path):
        print(f"✅ {file_path} exists")
    else:
        print(f"❌ {file_path} missing")

print("\n✨ Environment check complete!")

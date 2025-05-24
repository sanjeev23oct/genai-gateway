"""
Simple Railway-compatible LLM Gateway
This is the main entry point for Railway deployment
"""
import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and run the railway gateway
from railway_main import main

if __name__ == "__main__":
    print("🚀 Starting LLM Gateway on Railway...")
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    print(f"PORT environment: {os.getenv('PORT', 'Not set')}")
    
    try:
        main()
    except Exception as e:
        print(f"❌ Failed to start gateway: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

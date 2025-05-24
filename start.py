#!/usr/bin/env python3
"""
Railway startup script for LLM Gateway
This script ensures the gateway starts correctly on Railway
"""
import os
import sys

print("🚀 Railway Startup Script")
print(f"Current working directory: {os.getcwd()}")
print(f"Python executable: {sys.executable}")
print(f"Python version: {sys.version}")

# List files in current directory
print("\n📁 Files in current directory:")
try:
    files = os.listdir('.')
    for file in sorted(files):
        if not file.startswith('.'):
            print(f"  - {file}")
except Exception as e:
    print(f"  Error listing files: {e}")

# Check for our main files
main_files = ['railway_main.py', 'main.py', 'cloud_gateway.py']
found_file = None

for file in main_files:
    if os.path.exists(file):
        found_file = file
        print(f"\n✅ Found main file: {file}")
        break

if not found_file:
    print("\n❌ No main file found!")
    print("Available Python files:")
    for file in os.listdir('.'):
        if file.endswith('.py'):
            print(f"  - {file}")
    sys.exit(1)

# Import and run the gateway
print(f"\n🚀 Starting gateway from {found_file}")

try:
    if found_file == 'railway_main.py':
        from railway_main import main
        main()
    elif found_file == 'main.py':
        import main
    elif found_file == 'cloud_gateway.py':
        from cloud_gateway import local_test
        local_test()
    else:
        print(f"❌ Don't know how to start {found_file}")
        sys.exit(1)
        
except Exception as e:
    print(f"❌ Error starting gateway: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

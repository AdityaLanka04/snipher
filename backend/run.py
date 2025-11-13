#!/usr/bin/env python3
"""
Mini Wireshark Backend Runner
Run with: sudo python run.py
"""
import sys
import os

# Check if running as root
if os.geteuid() != 0:
    print("❌ Error: This script must be run with sudo")
    print("Usage: sudo python run.py")
    sys.exit(1)

print("🚀 Starting Mini Wireshark Backend...")
print("="*50)

# Test the parser first
print("\n🔍 Testing packet parser...")
import subprocess
result = subprocess.run([sys.executable, "test_parser.py"], capture_output=True, text=True)

if result.returncode == 0:
    print("✅ Parser tests passed!")
else:
    print("❌ Parser tests failed:")
    print(result.stdout)
    print(result.stderr)
    sys.exit(1)

print("\n" + "="*50)
print("🌐 Starting FastAPI server...")
print("📡 API: http://localhost:8000")
print("📡 WebSocket: ws://localhost:8000/ws")
print("📡 Docs: http://localhost:8000/docs")
print("\nPress Ctrl+C to stop")
print("="*50 + "\n")

# Start the server
import uvicorn
from main import app

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )

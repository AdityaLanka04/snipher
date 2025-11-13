#!/bin/bash

# Mini Wireshark Backend Startup Script
# This script must be run with sudo for packet capture

echo "🚀 Starting Mini Wireshark Backend..."
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Error: This script must be run with sudo"
    echo "Usage: sudo ./start.sh"
    exit 1
fi

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
    source venv/bin/activate
    echo "📥 Installing dependencies..."
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo "✅ Virtual environment activated"
echo "🔍 Testing packet parser..."
python test_parser.py

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Parser tests passed!"
    echo "🌐 Starting FastAPI server on http://0.0.0.0:8000"
    echo "📡 WebSocket available at ws://localhost:8000/ws"
    echo ""
    echo "Press Ctrl+C to stop"
    echo ""
    python main.py
else
    echo ""
    echo "❌ Parser tests failed. Please fix errors before starting."
    exit 1
fi

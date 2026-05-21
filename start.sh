#!/bin/bash
# PentestKit v1.0 - Startup Script

echo "╔═══════════════════════════════════════════════╗"
echo "║       PentestKit v1.0 - Web Security Tool      ║"
echo "║  ⚠️   For authorized security testing only!     ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")"

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Create virtual environment if needed
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install dependencies
echo "📥 Installing dependencies..."
pip install -q -r requirements.txt

# Create reports directory
mkdir -p reports

echo ""
echo "🚀 Starting PentestKit..."
echo "🌐 Open http://localhost:5000 in your browser"
echo ""

python3 app.py

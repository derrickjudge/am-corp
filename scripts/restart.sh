#!/bin/bash
# =============================================================================
# AM-Corp Safe Restart Script
#
# This script ensures all bot processes are stopped before starting fresh.
# Prevents duplicate bot instances that cause commands to be processed
# multiple times.
#
# Usage:
#   ./scripts/restart.sh          # Restart without rebuild
#   ./scripts/restart.sh --build  # Rebuild and restart
# =============================================================================

set -e

cd "$(dirname "$0")/.."

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                   AM-Corp Safe Restart                         ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Activate venv for podman-compose
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Step 1: Kill any host Python processes
echo "🧹 Step 1: Killing host Python processes..."
pkill -9 -f "python.*src.main" 2>/dev/null || true
pkill -9 -f "python.*src/main" 2>/dev/null || true
pkill -9 -f "python -m src" 2>/dev/null || true
sleep 1

# Step 2: Stop all containers
echo "🧹 Step 2: Stopping all containers..."
podman-compose down 2>/dev/null || true
podman stop -a 2>/dev/null || true
podman rm -a 2>/dev/null || true
sleep 1

# Step 3: Verify cleanup
echo "🔍 Step 3: Verifying cleanup..."
HOST_PROCS=$(ps aux | grep -E "python.*src" | grep -v grep | wc -l | tr -d ' ')
CONTAINERS=$(podman ps -a | grep -c am-corp 2>/dev/null || echo "0")

if [ "$HOST_PROCS" != "0" ]; then
    echo "⚠️  WARNING: Found $HOST_PROCS host Python processes still running"
    ps aux | grep -E "python.*src" | grep -v grep
    echo ""
    read -p "Force kill these processes? [y/N] " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pkill -9 -f "python.*src" 2>/dev/null || true
    fi
fi

if [ "$CONTAINERS" != "0" ]; then
    echo "⚠️  WARNING: Found $CONTAINERS am-corp containers still running"
    podman ps -a | grep am-corp || true
fi

echo "   ✅ Host processes: 0"
echo "   ✅ Containers: 0"

# Step 4: Rebuild if requested
if [ "$1" == "--build" ]; then
    echo ""
    echo "🔨 Step 4: Rebuilding container..."
    podman-compose build
fi

# Step 5: Start the container
echo ""
echo "🚀 Step 5: Starting container..."
podman-compose up -d

# Step 6: Wait and verify
echo ""
echo "⏳ Step 6: Waiting for bot to start..."
sleep 5

# Check container is running
RUNNING=$(podman ps | grep -c am-corp-bot || echo "0")
if [ "$RUNNING" == "1" ]; then
    echo "   ✅ Container running: am-corp-bot"
else
    echo "   ❌ Container not running!"
    podman-compose logs --tail=20
    exit 1
fi

# Check for duplicate host processes
HOST_PROCS=$(ps aux | grep -E "python.*src" | grep -v grep | wc -l | tr -d ' ')
if [ "$HOST_PROCS" == "0" ]; then
    echo "   ✅ No host processes (correct)"
else
    echo "   ⚠️  WARNING: $HOST_PROCS host processes detected"
fi

# Show recent logs
echo ""
echo "📋 Recent logs:"
echo "────────────────────────────────────────"
podman-compose logs --tail=15 2>&1 | grep -E "connected|ready|started|PASSED|FAILED" | head -10

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ AM-Corp bot restarted successfully!"
echo ""
echo "Commands:"
echo "  View logs:    podman-compose logs -f"
echo "  Stop:         podman-compose down"
echo "  Restart:      ./scripts/restart.sh"
echo "════════════════════════════════════════════════════════════════"

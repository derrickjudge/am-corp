#!/bin/bash
# =============================================================================
# AM-Corp Container Entrypoint
# Runs preflight checks before starting the bot
# =============================================================================

set -e

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    AM-Corp Preflight Check                     ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Run preflight check (quick mode for faster startup)
# Use --exit-code to fail if critical checks don't pass
if [ "${SKIP_PREFLIGHT}" = "true" ]; then
    echo "⏭️ Skipping preflight checks (SKIP_PREFLIGHT=true)"
else
    python src/preflight.py --quick --exit-code
    PREFLIGHT_EXIT=$?
    
    if [ $PREFLIGHT_EXIT -ne 0 ]; then
        echo ""
        echo "🛑 Preflight checks failed. Fix issues and try again."
        echo "   Set SKIP_PREFLIGHT=true to bypass (not recommended)."
        exit 1
    fi
fi

echo ""
echo "🚀 Starting AM-Corp Bot..."
echo ""

# Start the main application
exec python src/main.py "$@"

#!/bin/bash
# =============================================================================
# Nuclei Update Script
#
# Usage:
#   ./scripts/update_nuclei.sh              # Update templates only (no rebuild)
#   ./scripts/update_nuclei.sh --upgrade    # Bump binary to latest + rebuild
#   ./scripts/update_nuclei.sh --check      # Show current vs latest versions
# =============================================================================

set -e

cd "$(dirname "$0")/.."

DOCKERFILE="Dockerfile"
CURRENT_VERSION=$(grep 'ARG NUCLEI_VERSION=' "$DOCKERFILE" | cut -d'=' -f2)
LATEST_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))" 2>/dev/null)
LATEST_TEMPLATES=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null)

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                   Nuclei Update Manager                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Binary:    v${CURRENT_VERSION} installed  →  v${LATEST_VERSION} available"
echo "  Templates: ${LATEST_TEMPLATES} available"
echo ""

# --check: just print status and exit
if [ "$1" = "--check" ]; then
    CURRENT_TEMPLATES=$(podman exec am-corp-bot nuclei -tl 2>/dev/null | wc -l | tr -d ' ')
    echo "  Templates in container: ${CURRENT_TEMPLATES}"
    if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
        echo "  Binary is up to date."
    else
        echo "  Run with --upgrade to update the binary (requires rebuild)."
    fi
    echo ""
    exit 0
fi

# --upgrade: bump the pinned version in Dockerfile and rebuild
if [ "$1" = "--upgrade" ]; then
    if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
        echo "  Binary is already at latest (v${LATEST_VERSION}). Skipping rebuild."
        echo "  Re-running with no flags to update templates only."
        echo ""
    else
        echo "  Bumping Dockerfile: v${CURRENT_VERSION} → v${LATEST_VERSION}"
        sed -i.bak "s/ARG NUCLEI_VERSION=${CURRENT_VERSION}/ARG NUCLEI_VERSION=${LATEST_VERSION}/" "$DOCKERFILE"
        rm -f "${DOCKERFILE}.bak"
        echo "  Rebuilt Dockerfile. Building new image..."
        echo ""
        podman-compose build
        echo ""
        echo "  Restarting container..."
        podman-compose down
        podman-compose up -d
        echo ""
        sleep 8
        podman exec am-corp-bot nuclei --version 2>&1 | grep "Engine Version"
        echo "  Binary upgraded to v${LATEST_VERSION}."
        echo ""
        echo "  Templates will auto-update on next restart via entrypoint.sh."
        exit 0
    fi
fi

# Default (no flag or after skipping upgrade): update templates in running container
echo "  Updating templates in running container..."
echo ""
podman exec am-corp-bot nuclei -ut -silent 2>&1
UPDATED_COUNT=$(podman exec am-corp-bot nuclei -tl 2>/dev/null | wc -l | tr -d ' ')
echo ""
echo "  Templates updated: ${UPDATED_COUNT} total"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Done. No restart required — template updates take effect"
echo "  immediately for the next scan."
echo "════════════════════════════════════════════════════════════════"
echo ""

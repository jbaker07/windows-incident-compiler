#!/usr/bin/env bash
# EDR Desktop Sanity Check Script
# Verifies the desktop app works correctly in development mode
#
# Usage: ./sanity_check.sh
#
# Requirements:
# - Rust toolchain installed
# - Tauri CLI installed (cargo install tauri-cli)
# - Backend already built (cd crates/server && cargo build --release)

# Don't exit on error - we want to report all failures
set +e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_test() { echo -e "  ${GREEN}✓${NC} $1"; }
log_fail() { echo -e "  ${RED}✗${NC} $1"; }

TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    log_test "$1"
    ((TESTS_PASSED++))
}

fail() {
    log_fail "$1"
    ((TESTS_FAILED++))
}

echo "========================================"
echo "  EDR Desktop Sanity Check"
echo "========================================"
echo ""

# Test 1: Check backend binary exists
log_info "Checking prerequisites..."

if [[ -f "$REPO_ROOT/target/release/edr-server" ]]; then
    pass "Backend binary exists (target/release/edr-server)"
elif [[ -f "$REPO_ROOT/target/debug/edr-server" ]]; then
    pass "Backend binary exists (target/debug/edr-server)"
else
    fail "Backend binary not found. Run: cd crates/server && cargo build --release"
fi

# Test 2: Check Tauri CLI
SKIP_TAURI=0
if command -v cargo-tauri &> /dev/null; then
    pass "Tauri CLI installed (cargo-tauri)"
elif cargo tauri --version &> /dev/null 2>&1; then
    pass "Tauri CLI installed (cargo tauri)"
else
    log_warn "Tauri CLI not found. Install with: cargo install tauri-cli"
    log_warn "  Skipping Tauri-specific tests"
    SKIP_TAURI=1
fi

# Test 3: Check tauri.conf.json
if [[ -f "$SCRIPT_DIR/tauri.conf.json" ]]; then
    pass "tauri.conf.json exists"
else
    fail "tauri.conf.json not found"
fi

# Test 4: Run Rust unit tests
log_info "Running unit tests..."
cd "$SCRIPT_DIR"
if cargo test 2>&1 | tee /tmp/tauri_test_output.txt | grep -q "test result: ok"; then
    UNIT_TESTS=$(grep -o '[0-9]* passed' /tmp/tauri_test_output.txt | head -1)
    pass "Unit tests passed ($UNIT_TESTS)"
else
    fail "Unit tests failed. Check output above."
fi

# Test 5: Check port availability
log_info "Checking port availability..."
if ! lsof -i :3000 &> /dev/null; then
    pass "Port 3000 is available"
else
    log_warn "Port 3000 is in use, will use fallback"
fi

# Test 6: Manual backend spawn test
log_info "Testing backend spawn..."
BACKEND_BIN="$REPO_ROOT/target/release/edr-server"
if [[ ! -f "$BACKEND_BIN" ]]; then
    BACKEND_BIN="$REPO_ROOT/target/debug/edr-server"
fi

if [[ -f "$BACKEND_BIN" ]]; then
    # Start backend in background
    TEMP_TELEM=$(mktemp -d)
    "$BACKEND_BIN" --port 18999 --telemetry-root "$TEMP_TELEM" &
    BACKEND_PID=$!
    sleep 2
    
    # Check health endpoint
    if curl -s http://127.0.0.1:18999/api/health | grep -q '"ok"'; then
        pass "Backend health endpoint responds"
    else
        fail "Backend health endpoint failed"
    fi
    
    # Test UI endpoint
    if curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:18999/ui/index.html | grep -q "200"; then
        pass "Backend serves UI files"
    else
        fail "Backend does not serve UI files (may be expected)"
    fi
    
    # Cleanup
    kill $BACKEND_PID 2>/dev/null || true
    wait $BACKEND_PID 2>/dev/null || true
    rm -rf "$TEMP_TELEM"
    
    # Verify process terminated
    if ! kill -0 $BACKEND_PID 2>/dev/null; then
        pass "Backend process cleaned up"
    else
        fail "Backend process still running (orphan)"
        kill -9 $BACKEND_PID 2>/dev/null || true
    fi
else
    fail "Cannot test backend spawn - binary not found"
fi

# Test 7: Check Tauri build (dry run check)
log_info "Validating Tauri config..."
cd "$SCRIPT_DIR"
if cargo check 2>&1 | grep -q "^error"; then
    fail "Tauri crate has compilation errors"
else
    pass "Tauri crate compiles"
fi

echo ""
echo "========================================"
echo "  Results"
echo "========================================"
echo -e "  Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "  Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    log_info "All sanity checks passed! ✓"
    echo ""
    echo "Next steps:"
    if [[ -n "$SKIP_TAURI" ]]; then
        echo "  1. Install Tauri CLI: cargo install tauri-cli"
        echo "  2. Run development mode: cd src-tauri && cargo tauri dev"
    else
        echo "  1. Run development mode: cd src-tauri && cargo tauri dev"
    fi
    echo "  3. Build release: cd src-tauri && cargo tauri build"
    exit 0
else
    log_error "Some checks failed. Please fix issues above."
    exit 1
fi

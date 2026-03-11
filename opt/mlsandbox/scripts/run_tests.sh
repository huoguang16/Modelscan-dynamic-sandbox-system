#!/bin/bash
set -euo pipefail

MLSANDBOX="/opt/mlsandbox/src/mlsandbox"
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "============================================"
echo "  MLSandbox Integration Test Suite"
echo "============================================"
echo ""

passed=0
failed=0

run_test() {
    local name="$1"
    local model="$2"
    local expect_safe="$3"  # "safe" or "attack"

    echo -n "  [$name] "

    output=$($MLSANDBOX "$model" 2>&1) || true
    exit_code=$?

    if [ "$expect_safe" = "safe" ]; then
        if echo "$output" | grep -q "SAFE"; then
            echo -e "${GREEN}PASS${NC} — loaded safely"
            passed=$((passed + 1))
        else
            echo -e "${RED}FAIL${NC} — expected safe load but got blocked"
            echo "    Output: $(echo "$output" | tail -3)"
            failed=$((failed + 1))
        fi
    else
        if echo "$output" | grep -q "ATTACK DETECTED" || [ $exit_code -ne 0 ]; then
            echo -e "${GREEN}PASS${NC} — attack blocked"
            passed=$((passed + 1))
        else
            echo -e "${RED}FAIL${NC} — attack was NOT detected"
            echo "    Output: $(echo "$output" | tail -3)"
            failed=$((failed + 1))
        fi
    fi
}

echo "--- Benign Models (should pass) ---"
run_test "Safe pickle model" "/opt/mlsandbox/models/safe_model.pkl" "safe"

echo ""
echo "--- Malicious Models (should be blocked) ---"
run_test "A1: Reverse shell"  "/opt/mlsandbox/attacks/a1_reverse_shell.pkl" "attack"
run_test "A2: exec attack"    "/opt/mlsandbox/attacks/a2_exec_attack.pkl"   "attack"
run_test "A3: Network exfil"  "/opt/mlsandbox/attacks/a3_network.pkl"       "attack"
run_test "A4: Fork bomb"      "/opt/mlsandbox/attacks/a4_fork_bomb.pkl"     "attack"
run_test "A5: File steal"     "/opt/mlsandbox/attacks/a5_file_steal.pkl"    "attack"

echo ""
echo "============================================"
echo -e "  Results: ${GREEN}${passed} passed${NC}, ${RED}${failed} failed${NC}"
echo "============================================"

if [ $failed -gt 0 ]; then
    exit 1
fi

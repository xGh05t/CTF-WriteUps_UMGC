#!/usr/bin/env bash
# =============================================================================
# Solve Script — CTF Challenge: Reversal
# Maryland CTF | Reverse Engineering
# =============================================================================
# Approach: Static analysis only — no debugger or disassembler needed.
#
# The binary stores the flag as a Base64-encoded, reversed string.
# We extract it, decode it, and reverse it to recover the plaintext flag.
# =============================================================================

set -euo pipefail

BINARY="./challenge"
ENCODED="bGxheV93b25fa2NhYl90aV9la2F0e2dhbGYA"

echo "============================================="
echo " CTF Solve Script — Reversal"
echo "============================================="
echo ""

# Step 1 — Confirm the binary exists
if [[ ! -f "$BINARY" ]]; then
    echo "[!] Binary '$BINARY' not found. Make sure you're running this"
    echo "    from the same directory as the challenge file."
    exit 1
fi

echo "[*] File info:"
file "$BINARY"
echo ""

# Step 2 — Extract the Base64-encoded string via strings
echo "[*] Searching binary for Base64-encoded string..."
FOUND=$(strings "$BINARY" | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$' | head -1)
echo "    Found: $FOUND"
echo ""

# Step 3 — Decode the Base64 string
DECODED=$(echo "$ENCODED" | base64 -d)
echo "[*] Base64 decoded: $DECODED"
echo ""

# Step 4 — Reverse the decoded string to recover the flag
FLAG=$(echo "$DECODED" | rev)
echo "[*] Reversed:       $FLAG"
echo ""

# Step 5 — Verify against the binary
echo "[*] Verifying flag against binary..."
RESULT=$(echo "$FLAG" | "$BINARY" 2>/dev/null || true)
echo "    Binary says: $RESULT"
echo ""

if echo "$RESULT" | grep -q "found"; then
    echo "[+] SUCCESS! Flag confirmed: $FLAG"
else
    echo "[-] Verification failed — check the binary manually."
fi

echo ""
echo "============================================="

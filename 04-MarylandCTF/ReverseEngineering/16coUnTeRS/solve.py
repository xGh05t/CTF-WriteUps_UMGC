#!/usr/bin/env python3
"""
CTF Challenge: 16coUnTeRS
Category: Reverse Engineering
Author: xGh05t

Exploit: u16 integer overflow via INCREMENT env var
  counter starts at 1, adding 65535 wraps to 0, triggering the hidden flag branch.
"""

import subprocess
import sys
import os

BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "counter")

def solve():
    print("[*] 16coUnTeRS - CTF Solve Script")
    print("[*] Triggering u16 integer overflow: 1 + 65535 = 0 (mod 2^16)")
    print("[*] Running binary with INCREMENT=65535 and a single ENTER...\n")

    env = os.environ.copy()
    env["INCREMENT"] = "65535"

    result = subprocess.run(
        [BINARY],
        input=b"\n",
        capture_output=True,
        env=env
    )

    output = result.stdout.decode()
    print(output)

    # Extract and highlight the flag
    for line in output.splitlines():
        if line.startswith("flag{"):
            print(f"[+] FLAG CAPTURED: {line}")
            return line

    print("[-] Flag not found. Make sure the 'counter' binary is in the same directory.")
    sys.exit(1)

if __name__ == "__main__":
    solve()

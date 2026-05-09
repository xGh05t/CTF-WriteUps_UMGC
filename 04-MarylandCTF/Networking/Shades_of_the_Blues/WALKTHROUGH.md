# CTF Walkthrough: Shades of the Blues

**Challenge:** Shades of the Blues
**Category:** Network Forensics / Steganography
**Difficulty:** Medium
**Flag:** `HidingDataIsPhun`

> *"More than meets the eye!"*

---

## Overview

This challenge combines **PCAP analysis**, **web forensics**, and **image steganography**. Traffic captured in `blues.pcap` leads to a hidden PNG image whose color values encode the flag — literally hidden in different shades of blue.

---

## Step 1 — Initial Recon of the PCAP

Start by exporting all HTTP objects from the capture to see what was transferred:

```bash
tshark -r blues.pcap --export-objects http,extracted/
ls -la extracted/
```

Key files recovered:

| File | Size | Notes |
|------|------|-------|
| `index.html` | 4,565 B | Main site page |
| `index(1).html` | 4,550 B | `/more_sekrits/` page |
| `about_us.html` | 4,534 B | About page |
| `secret_squirrel.jpeg` | 127,946 B | Squirrel image |
| `RangerUpSekrit.gif` | 14,304 B | GIF image |
| `squirrel-under-construction.jpg` | 16,347 B | Under-construction image |

The site is hosted at `sekritskwerl.com` — already suspicious.

---

## Step 2 — Hunt for Hidden Clues in the HTML

Inspect the page source. Inside `index(1).html` (the `/more_sekrits/` page):

```html
<p>
  <img src="RangerUpSekrit.gif" width="500pts">
</p>
<p>
  <!-- <img src="AlbumCover.png" width=500pts"> -->
</p>
```

A **commented-out image** — `AlbumCover.png` — was deliberately hidden from the rendered page. It was never fetched over HTTP, which means it must be hiding somewhere else in the traffic.

The main page also drops a hint:

```html
"CouldThisBeTheSecretMessage?"
```

---

## Step 3 — Dig Into the Raw Packet Data

The `AlbumCover.png` wasn't in the HTTP exports, so search the raw packet payloads:

```bash
tshark -r blues.pcap -Y "data" -T fields -e data 2>/dev/null | head -5
```

One large data field begins with:

```
6956424f5277304b47676f414141414e535568455567...
```

Decode it:

```bash
echo "6956424f..." | xxd -r -p | base64 -d > hidden_image.png
file hidden_image.png
```

```
hidden_image.png: PNG image data, 1920 x 1080, 8-bit/color RGB
```

**The hidden album cover is a 1920×1080 PNG embedded as base64 inside a raw TCP data packet.**

---

## Step 4 — Analyze the Hidden Image

Opening `hidden_image.png` reveals a mostly white canvas with a **4×4 grid of 16 navy-blue circles** in the upper-left quadrant. The circles look nearly identical — but the title says *"Shades of the Blues"*.

Sample the exact RGB color of each circle's center:

```python
from PIL import Image
import numpy as np

img = Image.open('hidden_image.png')
arr = np.array(img)

# Locate circle boundaries by scanning for blue pixels (R=0, G=0, B>50)
# ... detect row and column segment centers ...

for row_y in row_centers:
    for col_x in col_centers:
        r, g, b = arr[row_y, col_x]
        print(chr(b), end=' ')
```

Every circle is **pure blue** — meaning `R=0, G=0` — but the **B (blue) channel value varies**. Each value is a valid ASCII code.

---

## Step 5 — Decode the Color Grid

Reading the B-channel values left-to-right, top-to-bottom:

| | Col 1 | Col 2 | Col 3 | Col 4 |
|---|:---:|:---:|:---:|:---:|
| **Row 1** | 72 → `H` | 105 → `i` | 100 → `d` | 105 → `i` |
| **Row 2** | 110 → `n` | 103 → `g` | 68 → `D` | 97 → `a` |
| **Row 3** | 116 → `t` | 97 → `a` | 73 → `I` | 115 → `s` |
| **Row 4** | 80 → `P` | 104 → `h` | 117 → `u` | 110 → `n` |

Concatenated: **`HidingDataIsPhun`**

---

## Flag

```
HidingDataIsPhun
```

---

## Techniques Used

- **PCAP / HTTP object extraction** — `tshark --export-objects`
- **HTML source analysis** — finding commented-out references
- **Raw payload inspection** — locating base64-encoded binary in TCP data streams
- **Image steganography** — ASCII encoding in the blue channel of RGB pixels

---

## Key Takeaways

- Always inspect raw packet data, not just reassembled HTTP streams — hidden content can ride in `data` layer packets outside of normal HTTP responses.
- HTML comments can be breadcrumbs pointing toward assets that were deliberately kept off the rendered page.
- Steganography doesn't require complex tools. Sometimes the message is literally encoded in the color values of the image itself — just in a way your eye can't distinguish.

---

*Challenge from CyberFusion 2019 — Virginia Cyber Range*

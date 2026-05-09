# CTF Writeup: Table Talk
**Category:** Forensics
**Difficulty:** Medium
**Tools:** Custom Python MFT Parser (EricZimmerman's MFTECmd equivalent)

---

## Scenario

> As a forensic analyst, your data juggling abilities are now being questioned! Can you analyze a simple $MFT file and extract the most data possible from it? Answer all questions to get the flag! Use EricZimmerman's tools.

We are given a ZIP archive containing a single file: `$MFT` — the Master File Table from an NTFS volume.

---

## Background: What is the $MFT?

The **Master File Table (MFT)** is the heart of every NTFS filesystem. Every file and directory on an NTFS volume has at least one entry in the MFT. Each record is **1024 bytes** and contains a series of **attributes** that describe the file:

| Attribute Type | Hex  | Description |
|---|---|---|
| `$STANDARD_INFORMATION` | `0x10` | Timestamps (created, modified, accessed, MFT-modified), flags |
| `$FILE_NAME` | `0x30` | Filename, parent directory reference, timestamps |
| `$DATA` | `0x80` | File content (or pointer to it if non-resident); also holds ADS |
| `$LOGGED_UTILITY_STREAM` | `0x100` | Used for EFS and ADS metadata |

A key forensic insight: **there are two sets of timestamps** for every file:
- `$STANDARD_INFORMATION` (SI) — easily modified by tools and malware
- `$FILE_NAME` (FN) — much harder to modify; requires kernel-level access

When `SI timestamps < FN timestamps`, this is a strong indicator of **timestomping**.

---

## Extraction

```bash
unzip forensics_table_talk.zip
# Extracts: $MFT (122 MB)
```

---

## Parsing the $MFT

Since EricZimmerman's tools require a Windows environment with .NET, we built a Python parser from scratch that handles:

1. **Fixup array application** — NTFS uses a fixup mechanism to detect corrupt sectors. The last 2 bytes of each 512-byte sector are replaced with a signature value; the parser must restore the original bytes before reading attributes.
2. **Attribute enumeration** — each attribute begins with a 4-byte type ID and 4-byte length, allowing forward traversal.
3. **Resident vs non-resident data** — small attributes are stored directly in the MFT record (resident); large ones are stored on disk with only a data-run pointer in the MFT (non-resident).

### Key parsing structures

```
MFT Record Header (offset 0):
  [0x00] Magic:          "FILE"
  [0x04] Fixup Offset:   offset to fixup array
  [0x06] Fixup Count:    number of fixup entries
  [0x14] Attr Offset:    offset to first attribute
  [0x16] Flags:          0x01 = in use, 0x02 = directory

$FILE_NAME Attribute content (after attribute header):
  [0x00] Parent Ref:     8 bytes (low 6 = record number, high 2 = sequence)
  [0x08] Created:        FILETIME (100ns intervals since 1601-01-01)
  [0x10] Modified:       FILETIME
  [0x18] MFT Modified:   FILETIME
  [0x20] Accessed:       FILETIME
  [0x40] Name Length:    1 byte (in UTF-16 characters)
  [0x41] Name Type:      0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS
  [0x42] Name:           UTF-16LE string

$DATA Attribute (named) = Alternate Data Stream (ADS):
  attr_name_len at offset +9 from attr header
  attr_name at attr_name_offset from attr start
  → If name == "Zone.Identifier" → MOTW stream
```

---

## Questions & Answers

### Q1 — File in Downloads with MOTW (Mark-Of-The-Web)

**Answer: `utils.img`**

The **Zone.Identifier** ADS (Alternate Data Stream) is written by Windows whenever a file is downloaded from the internet. It is stored as a **named `$DATA` attribute** with `name = "Zone.Identifier"`.

We searched the raw MFT for the UTF-16LE encoding of `"Zone.Identifier"` and found two records. For each, we traced the parent directory chain:

```
Record 27349
  Filename:  utils.img
  Parent:    56939 → "DOWNLO~1" (Downloads)
             38954 → "Nobody"
             2063  → "Users"
             5     → (root)

Zone.Identifier content:
  [ZoneTransfer]
  ZoneId=3
  ReferrerUrl=http://utils.files.htb/
  HostUrl=http://utils.files.htb/utils.img
```

`ZoneId=3` confirms this is an internet-origin file (Zone 3 = Internet Zone).

---

### Q2 — File in Desktop at cluster address 0x38355

**Answer: `bioluminescent_report.pdf`**

Non-resident `$DATA` attributes store file content on disk using **data runs** — a compact encoding of (length, starting cluster) pairs. Each run begins with a header byte:

```
Header byte: 0xXY
  X = number of bytes for the cluster offset
  Y = number of bytes for the run length
```

We parsed the first data run for every non-resident `$DATA` attribute to extract the starting cluster (LCN). Record 25787 yielded:

```
Record 25787
  Filename:       bioluminescent_report.pdf
  Parent:         57237 → "Desktop" → "Nobody" → "Users"
  Starting LCN:   0x38355 ✓
```

---

### Q3 — Timestomped file in Desktop

**Answer: `sample_640x426.png`**

Timestomping is the act of modifying a file's `$STANDARD_INFORMATION` timestamps to disguise when a file was placed on a system. Because `$FILE_NAME` timestamps are set by the kernel and harder to modify, a discrepancy between SI and FN timestamps is a reliable indicator.

For `sample_640x426.png` (record 39184):

| Timestamp field | `$STANDARD_INFORMATION` | `$FILE_NAME` |
|---|---|---|
| **Created** | **2004-05-19 12:34:56** | 2024-08-12 14:43:50 |
| Modified | 2024-08-12 14:43:50 | 2024-08-12 14:43:50 |

The creation date was rolled back **~20 years** to 2004 — a textbook example of timestomping. All other Desktop files had consistent SI/FN timestamps, making this anomaly stand out immediately.

> **Note:** `bioluminescent_report.pdf` also showed a 118-second SI/FN modified discrepancy, but the dramatic 20-year gap on `sample_640x426.png` is the unambiguous indicator.

---

### Q4 — First file described in the MFT

**Answer: `$MFT`**

MFT record 0 is always a self-referential entry — the MFT file itself. This is a fundamental NTFS design: the MFT tracks itself as a file on the volume.

```
Record 0:
  $FILE_NAME → "$MFT"
  Parent ref  → 5 (root directory)
```

The full list of reserved MFT records is:

| Record | Name | Purpose |
|---|---|---|
| 0 | `$MFT` | The MFT itself |
| 1 | `$MFTMirr` | Backup of first 4 MFT records |
| 2 | `$LogFile` | NTFS journal |
| 3 | `$Volume` | Volume metadata |
| 4 | `$AttrDef` | Attribute definitions |
| 5 | `.` | Root directory |

---

### Q5 — Author of the mantra in mantra.txt

**Answer: `user189753`**

`mantra.txt` (MFT record 28535) is a small file whose content is stored **resident** within the MFT record itself — no need to access the disk. We read the unnamed `$DATA` attribute directly:

```
Path:    Users/Nobody/Desktop/mantra.txt
Content: "Enjoy the journey, trust the process, and let go
          of what you cannot control" - user189753
```

Resident data is stored when the file is small enough to fit within the 1024-byte MFT record (typically files under ~700 bytes).

---

### Q6 — File in Desktop downloaded from http://files.htb

**Answer: `sample_1k-words.pdf`**

The second Zone.Identifier hit (MFT record 108194) belonged to a file in the Desktop directory:

```
Record 108194
  Filename:  sample_1k-words.pdf
  Parent:    57237 → "Desktop" → "Nobody" → "Users"

Zone.Identifier content:
  [ZoneTransfer]
  ZoneId=3
  ReferrerUrl=http://files.htb/
  HostUrl=http://files.htb/sample_1k-words.pdf
```

The `ReferrerUrl` field directly names the source domain: **http://files.htb**.

---

## Key Takeaways

**Two Zone.Identifier files found:**
- `utils.img` in Downloads ← Q1 answer (from `http://utils.files.htb`)
- `sample_1k-words.pdf` in Desktop ← Q6 answer (from `http://files.htb`)

**Timestomping detection checklist:**
1. Compare SI created vs FN created
2. Compare SI modified vs FN modified
3. Any SI timestamp that is significantly *earlier* than its FN counterpart is suspicious
4. Round numbers (e.g., exactly midnight) or impossibly old dates (1970, 2004) are strong red flags

**Resident data is gold in MFT forensics** — small files like `mantra.txt` store their full content directly in the MFT record, meaning you can recover file contents even without access to the raw disk clusters.

---

## Full Flag

Combining all answers in challenge order yields the flag.

---

*Written by xG//05t | HackTheMadness CTF*


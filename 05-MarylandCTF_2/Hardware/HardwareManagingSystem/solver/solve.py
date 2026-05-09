#!/usr/bin/env python3
"""
solve.py — End-to-end automated solver for the HTB Hardware Managing System CTF.

Walks the hidden 7-step state machine in the synthesized Verilog netlist,
discovering each triplet of the unlock sequence in turn. After the chain
completes (reg[7] = 1, the backdoor is armed), the script optionally invokes
the original Verilator binary VCtfTask to confirm that the discovered input
causes the simulation to print

    INPUT '...' NEEDS FURTHER ANALYSIS

— at which point the printed input string is the flag.

This takes a couple of minutes per step (each step is a 128**3 brute force
over 7-bit ASCII triplets) — about 15 minutes for the full 7-step chain on
a typical machine.
"""
import argparse
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from chain_search import find_next_reg, fmt_char  # noqa: E402


def walk_chain(verbose=True):
    """Walk the full chain from reset until reg[7] is set. Returns the list
    of (c, y, bx) triplets in order."""
    chain = []
    reg = 0b00000001  # post-reset: only reg[0] high (FDPE)

    while not (reg >> 7) & 1:
        if verbose:
            print(f"[step {len(chain) + 1}] starting from reg = 0b{reg:08b}")
        t0 = time.time()
        found = find_next_reg(reg)
        if not found:
            raise RuntimeError(
                f"No triplet advances the chain from reg=0b{reg:08b}!")

        # In the actual challenge each state has at most two successors:
        # the canonical step forward, and (sometimes) a self-loop or revert.
        # We pick the one with the largest new_reg as a heuristic; the trigger
        # condition for the *correct* path always sets a higher reg bit than
        # what's currently there.
        candidates = sorted(found.items(), key=lambda kv: -kv[1])
        # Filter to those that move strictly forward: turn ON a bit not yet set
        forward = [(t, nr) for t, nr in candidates if (nr & ~reg) != 0]
        if not forward:
            forward = candidates

        triplet, new_reg = forward[0]
        c, y, bx = triplet
        if verbose:
            print(f"           -> '{fmt_char(c)}{fmt_char(y)}{fmt_char(bx)}'  "
                  f"  reg becomes 0b{new_reg:08b}  ({time.time() - t0:.0f}s)")
        chain.append(triplet)
        reg = new_reg

    return chain


def chain_to_input(chain):
    """Join triplets into the byte string fed to VCtfTask (no separators)."""
    return bytes(b for triplet in chain for b in triplet)


def run_binary(binary_path, input_bytes, timeout=10):
    """Run the original Verilator binary and capture its output."""
    proc = subprocess.run(
        [binary_path], input=input_bytes, capture_output=True, timeout=timeout)
    # Strip ANSI escapes and non-ASCII for readability
    raw = proc.stdout
    cleaned = []
    i = 0
    while i < len(raw):
        b = raw[i]
        if b == 0x1B and i + 1 < len(raw) and raw[i + 1] == ord('['):
            # Skip ANSI CSI sequence
            i += 2
            while i < len(raw) and not (0x40 <= raw[i] <= 0x7E):
                i += 1
            i += 1
        elif b < 0x80:
            cleaned.append(b)
            i += 1
        else:
            i += 1
    return bytes(cleaned).decode('ascii', errors='replace')


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--binary', default=os.path.join(
        os.path.dirname(__file__), '..', 'challenge_files', 'VCtfTask'),
                    help='Path to VCtfTask binary')
    ap.add_argument('--no-run', action='store_true',
                    help="Don't invoke VCtfTask after walking the chain")
    args = ap.parse_args()

    print("=" * 64)
    print("HTB Hardware Managing System — automated solver")
    print("=" * 64)
    t_start = time.time()

    chain = walk_chain()
    input_str = chain_to_input(chain).decode('ascii', errors='replace')

    print()
    print("=" * 64)
    print(f"Recovered unlock sequence (took {time.time() - t_start:.0f}s):")
    for i, t in enumerate(chain, 1):
        print(f"  step {i}: '{fmt_char(t[0])}{fmt_char(t[1])}{fmt_char(t[2])}'")
    print()
    print(f"Concatenated input: '{input_str}'")
    print("=" * 64)

    if args.no_run:
        return

    if not os.path.exists(args.binary):
        print(f"\n(VCtfTask not found at {args.binary}; skipping live test)")
        return

    print("\nFeeding the recovered input to VCtfTask...")
    out = run_binary(args.binary, input_str.encode())
    # Print just the interesting tail
    interesting = []
    for line in out.splitlines():
        s = line.strip()
        if any(k in s for k in ('Input:', 'Temperature', 'EMERGENCY',
                                'TEST', 'INPUT ', 'NEEDS FURTHER')):
            interesting.append(s)
    print('\n'.join(interesting))

    if 'NEEDS FURTHER ANALYSIS' in out:
        # Pull the flag line
        for line in out.splitlines():
            if 'NEEDS FURTHER ANALYSIS' in line:
                print()
                print("=" * 64)
                print(f"FLAG: {line.strip()}")
                print("=" * 64)
                break


if __name__ == '__main__':
    main()

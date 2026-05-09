# Hardware Managing System — Walkthrough

**Event:** 2026 Maryland HTB CTF
**Category:** Hardware
**Flag:** `HTB{BCKD000RD_HRDWR3}`

---

## Challenge

> Recently one of our assembly line machines broke after working prolonged under to high temperature exposure. This is not something that should have been possible as we use a very sophisticated Temperature-Workload-Management-System. It is directly implemented in hardware and should have instantly responded by activating the emergency-off safety feature. After recent reports that the vendor we acquired this system from might be involved in a row of industrial sabotage cases we are a bit anxious that this failure was deliberately caused by a backdoor in the hardware. We were able to get both a copy of the Hardware Description Language code of the system and a matching simulation program, could you please check them out to see if anything is wrong?
>
> Find the Flag.

Files provided (`hw_managing_system.zip`):

- `CtfTask.v` — synthesized Verilog netlist of the management system (gate-level, ~4700 lines)
- `VCtfTask` — Verilator-compiled binary that simulates the system and prompts for input
- `notes.txt` — short hint: an input that prevents the emergency shutdown causes the simulation to print `INPUT '...' NEEDS FURTHER ANALYSIS`, and that whole printed string is the flag

---

## TL;DR

The shutdown logic in the netlist is

    shutdown = ~comparator_says_too_hot  &  ~reg[7]

`reg[7]` is supposed to stay 0 forever — but it’s actually the output of a
flip‑flop whose D-input is driven by a 6‑input LUT that fires on a very
specific combination of (latched triplet bytes, current `reg[]`, and a
newline‑edge condition). The seven other `reg` bits work the same way: they
form a hidden state machine that walks through a unique chain of seven
3‑byte “key codes,” and only the right sequence ever sets bit 7.

The chain decodes to **`HTB{BCKD000RD_HRDWR3}`** — punning on
*BackDoor’d Hardware*. Fed to `VCtfTask`, this input causes the temperature
to climb to 255 in step 8 with no shutdown:

```
[8] EMERGENCY SHUTDOWN MISSED!
TEST FAILED, EMERGENCY SHUTDOWN WAS NOT ACTIVED!
INPUT 'HTB{BCKD000RD_HRDWR3}' NEEDS FURTHER ANALYSIS
```

Solver runs in ~15 minutes (`solver/solve.py`). PoC with the known answer:
`exploit/exploit.sh`.

---

## Reconnaissance

### What the simulation does

```
$ ./VCtfTask < /dev/null    # no input, just newline
[1] Input: '',    Power Level: '000'
[1] Before Temperature 020 => After Temperature 016
...
[7] Input: '',    Power Level: '000'
[7] Before Temperature 005 => After Temperature 004
[8] Testing Emergency Shutdown:
[8] Input: '255', Power Level: '255'
[8] Before Temperature 004 => After Temperature 000
[8] EMERGENCY SHUTDOWN ACTIVATED!
TEST SUCCESSFUL
```

So the program:

1. Reads up to 21 input bytes (or until newline), grouped into seven triplets.
2. For each triplet, sends the three ASCII bytes plus a newline to the
   hardware as `io_input`. Whatever the hardware spits back as `io_power`
   is then plugged into a temperature update:
   `new_temp = old_temp × (power/255 + 0.8)` clamped to `[0, 255]`.
3. The hardware should emergency-stop (force `io_power = 0`) whenever
   `io_temp ≥ 100`.
4. After the seven user-controlled iterations, step 8 hard-codes power 255
   to verify the shutdown trips. With temperature 255 incoming, it always
   should. If it ever doesn’t, the program prints
   `INPUT '...' NEEDS FURTHER ANALYSIS` — the input string itself.

### What lives in the binary

```
$ strings VCtfTask | grep -E 'INPUT|MISSED|TEST FAILED'
[%d] EMERGENCY SHUTDOWN MISSED!
[8] EMERGENCY SHUTDOWN MISSED!
TEST FAILED, EMERGENCY SHUTDOWN WAS NOT ACTIVED!
INPUT '%s' NEEDS FURTHER ANALYSIS
```

The path to the flag is therefore: **find an input that lets the temperature
exceed 100 while `io_power` stays nonzero**, and the simulation will echo
that very input back as the flag.

### What the netlist looks like

`CtfTask.v` is the Yosys output of a behavioural source that we don’t have.
It’s a flat list of `LUT*`, `MUXCY`, `MUXF7`, `MUXF8`, `XORCY`, `FDCE`,
`FDPE` primitives plus parametrised `paramod` LUT6s with custom mux-tree
bodies. There are ~430 instances. Net names are SHA-256-looking hashes
because Yosys hashes deduplicated structural identifiers.

The module port list is the most useful thing in there:

```verilog
module CtfTask(io_input, io_inputDone, io_temp, io_power, clk, reset);
  input  [6:0] io_input;
  input        io_inputDone;
  output [7:0] io_power;
  input  [7:0] io_temp;
  input        reset;
```

So the hardware sees a 7‑bit input, returns an 8-bit `io_power`, and reads
the simulator’s `io_temp` reading.

---

## Locating the backdoor

### `io_power` is gated by a single signal

Search for what drives the eight `io_power` bits:

```
LUT2 INIT=4'0100   _545_ ( .I0(_270_), .I1(<reg_pwr[i]>), .O(io_power[i]) )
```

`INIT=4'0100` means the output is 1 only when `I1=1, I0=0`, i.e.
`io_power[i] = ~_270_ & reg_pwr[i]`. Every `io_power` bit is gated by the
same signal `_270_`. So `_270_` is the global shutdown signal — when it’s 1,
all eight power bits are forced to 0.

### `_270_ = ~_271_ & ~reg[7]`

```
LUT2 INIT=4'0001   _485_ ( .I0(_271_), .I1(reg[7]), .O(_270_) )
```

`INIT=4'0001` is 1 only when both inputs are 0, so:

    _270_ = ~_271_ & ~reg[7]

Two ways to defeat the shutdown: either keep `_271_` from going low
(make the comparator miss high temperatures), or make `reg[7]` go high.

### The temperature comparator is bit-perfect

`_271_` is a `paramod` LUT6 that combines `io_temp[0..3]` with a partial
result `_058_` from a carry chain. The carry chain is the canonical FPGA
"is `io_temp ≥ 100`" comparator built out of `MUXCY`s — I traced it
manually and verified by exhaustive Python simulation that it produces
the correct answer for all 256 input values:

    for every io_temp in [100, 255]:  shutdown asserts
    for every io_temp in [  0,  99]:  shutdown does NOT assert

So the comparator has no bugs. **The backdoor is `reg[7]`.**

### `reg[7]` updates from `_226_ AND _261_`

`reg[7]` is the Q output of an FDCE (clocked, async‑reset to 0). Its D input
is `_196_`, and `_196_` is a paramod LUT6 with inputs
`(_265_, _269_, _226_, _261_, _213_, reg[7])`. Tabulating all 64
input combinations of that LUT (the body is in the netlist) gives:

| Current `reg[7]` | Conditions for next `reg[7] = 1` |
|------------------|-----------------------------------|
| 0                | `_226_ = 1` AND `_261_ = 1` (other four LUT inputs are don’t‑cares) |
| 1                | mostly stays at 1 once latched   |

So the trigger is the conjunction `_226_ AND _261_`.

### Decomposing `_226_` and `_261_`

`_226_` is a 6‑input AND of LUT2 outputs whose inputs are bits of four
internal registers — call them `C[6:0]`, `Y[6:0]`, `B[3:0]+X[6:4]`, and
`reg[3]`. By reading the LUT2 init values:

```
_226_ =  C[0] & Y[0] & X[6] & ... & reg[3]    (combination across 22 bits)
```

`_261_ = ~_214_ & _233_ & _239_ & _222_`, where `_222_ = (state == 0b11)` —
i.e. `_261_` only becomes 1 at the moment the parser’s 2-bit state machine
is in state 3 (after the third byte of a triplet has been latched).

### What are C, Y, B+X?

A short experiment with the simulator (after building it; see below) shows
the parser cycles `state ∈ {0, 1, 2, 3, 0, ...}` on every byte, and the three
data registers act as a shift register over the bytes of a triplet:

| After byte | state | C    | Y    | B+X  |
|------------|-------|------|------|------|
| 1          | 1     | b1   | 0    | 0    |
| 2          | 2     | b1   | b2   | 0    |
| 3          | 3     | b1   | b2   | b3   |
| newline    | 0     | b1   | b2   | b3   |

So C/Y/B+X latch the three ASCII characters of the current triplet, and on
the trailing newline the parser is back in state 0 (so `_222_` would be 0).
But the FF for `reg[7]` clocks on the *rising edge* of `clk`. Looking at
`VCtfTask`’s `sendByte` function:

```c
void sendByte(top, byte) {
    io_input = byte & 0x7F;
    io_inputDone = 1;
    tick();           // <-- _196_ sampled here, with state still = 3
    io_inputDone = 0;
    tick();
}
```

When the newline byte is being driven, the *previous* clock cycle still has
`state == 3` (from byte 3). So at the moment `reg[7]` samples its D input,
`_222_ = 1` and `_226_` evaluates over (C, Y, B+X) = (byte1, byte2, byte3).
**The trigger is therefore: a triplet whose three bytes match the magic
combination, with the current `reg[]` value matching the prerequisites.**

---

## Solving the trigger condition

### The single matching triplet for `_226_=1`

Restrict to the case `reg[7] = 0` (we want to flip it). With C, Y, B+X each
free over 7 bits and `reg[3] ∈ {0, 1}`, that’s a 2²² space — 4 M evaluations,
trivial when the simulator runs at ~17 k ticks/s:

```
$ python3 check_226.py
HIT: reg[3]=1  C=0x52='R'  Y=0x33='3'  B+X=0x7d='}'
Total _226_=1 cases: 1
```

There’s exactly one combination, and **`R3}` ends like a CTF flag**.

### The chain to set `reg[3]`

`reg[3]` doesn’t start at 1. Each `reg[i]` is the Q of an FDCE driven by a
similar LUT6 over the same set of inputs. They form a **state machine**:
each triplet that matches a unique pattern flips one specific `reg` bit;
and the 6-LUTs for the other bits depend on the current `reg` so each step
is conditional on the previous step having succeeded.

The brute-force approach: starting from `reg = 0b00000001` (post-reset:
`reg[0]` is preset by an FDPE, all others cleared), enumerate every
possible (C, Y, B+X) and compute the next-state of `reg`. Walk forward
until `reg[7]` flips.

Each step is `128**3 ≈ 2.1 M` iterations and takes ~2 minutes on this
machine. Seven steps total → ~15 minutes. The chain is deterministic at
every step (only one triplet ever advances the state):

| step | `reg` before  | triplet | `reg` after  |
|------|---------------|---------|--------------|
| 1    | `0b00000001`  | `HTB`   | `0b00010001` |
| 2    | `0b00010001`  | `{BC`   | `0b00000100` |
| 3    | `0b00000100`  | `KD0`   | `0b01000000` |
| 4    | `0b01000000`  | `00R`   | `0b00000010` |
| 5    | `0b00000010`  | `D_H`   | `0b00100000` |
| 6    | `0b00100000`  | `RDW`   | `0b00001000` |  ← `reg[3]=1`
| 7    | `0b00001000`  | `R3}`   | `0b10000000` |  ← **`reg[7]=1`**

Concatenating the seven triplets: **`HTB{BCKD000RD_HRDWR3}`** — 21 bytes,
exactly the maximum input length. The `_HRDWR3` portion plus `BCKD00R`
spells *backdoored hardware*. Cute.

---

## Verifying the flag

```
$ printf 'HTB{BCKD000RD_HRDWR3}' | ./VCtfTask
[1] Input: 'HTB', Power Level: '000'
[1] Before Temperature 020 => After Temperature 016
[2] Input: '{BC', Power Level: '000'
...
[7] Input: 'R3}', Power Level: '000'
[7] Before Temperature 005 => After Temperature 004
[8] Testing Emergency Shutdown:
[8] Input: '255', Power Level: '255'
[8] Before Temperature 004 => After Temperature 255
[8] EMERGENCY SHUTDOWN MISSED!
TEST FAILED, EMERGENCY SHUTDOWN WAS NOT ACTIVED!
INPUT 'HTB{BCKD000RD_HRDWR3}' NEEDS FURTHER ANALYSIS
```

Temperature climbs to 255 in step 8 with `io_power` still 255, because
`reg[7]` is now 1 and the shutdown is suppressed. The flag is the printed
input string.

> **Flag:** `HTB{BCKD000RD_HRDWR3}`

---

## Files in this writeup

```
challenge_files/      Original distribution (CtfTask.v, VCtfTask, notes.txt)
solver/
    verilog_sim.py    Self-contained Python simulator parsed from CtfTask.v
    chain_search.py   Brute-forces one chain step at a time
    solve.py          Walks the whole 7-step chain, then runs VCtfTask
exploit/
    exploit.sh        Trivial PoC: feeds the answer to VCtfTask
README.md             This file
```

### Reproducing the solve

```
# 1. Quick PoC with the known answer (~1 second):
$ ./exploit/exploit.sh

# 2. Discover the answer from scratch (~15 minutes):
$ python3 solver/solve.py
```

### Reproducing one step at a time

```
$ python3 solver/chain_search.py 1            # post-reset state
$ python3 solver/chain_search.py 0b00010001
$ python3 solver/chain_search.py 0b00000100
... etc.
```

---

## Lessons / takeaways

- **Yosys-synthesized netlists are readable enough to attack.** The hashes
  look intimidating, but every gate is a 6-input LUT or a basic mux/FF.
  A small Python parser plus exhaustive truth-table extraction makes the
  whole thing tractable.
- **A “gating” LUT is always worth checking.** Whenever a critical signal
  is `~A & ~B`, ask whether `B` was supposed to be there at all.
  Here, `~reg[7]` is wired in as a backdoor enable — invisible at the RTL
  level unless you walk the netlist.
- **State machines hidden in `reg[]` bits look harmless individually.**
  Every single bit of `reg[1..7]` would, in isolation, look like dead logic.
  Together they form an unlock chain. Comparing each FF’s D-input fan-in
  against “what does it really need to be?” catches this.
- **Bit-7 of `io_input` was a red herring.** The port is `[6:0]` and the
  simulator masks each byte with `0x7F` before driving it. I burned an hour
  hunting a bit-7 bypass that didn’t exist.

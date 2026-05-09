# 16coUnTeRS — CTF Walkthrough

**Category:** Reverse Engineering
**Flag:** `flag{isnt_rust_suppos3dtobe_S4fe}`

---

## Challenge Description

We're given a compiled Rust binary (`counter`) and its source (`counter.rs`). The author claims: *"Nobody can break my counter!"* — it counts up to 65535 and that's it.

---

## Step 1: Recon — Read the Source

The source is provided, which makes this a whitebox RE challenge. Key observations:

```rust
let increment: u16;
match env::var("INCREMENT"){
    Ok(val) => { increment = val.trim().parse::<u16>().expect("..."); },
    Err(_)  => { increment = 0; }
}
let mut counter: u16 = 1;
loop {
    // ...read line...
    counter += increment;
    println!("Counter: {}", counter);
    match counter {
        0         => { println!("HEY! HOWD YOU BREAK MY COUNTER?"); break; }
        1..=65535 => continue,
        _         => { println!("Max count reached!"); break; }
    }
}
```

**Critical findings:**

1. `counter` and `increment` are both **`u16`** — unsigned 16-bit integers with a range of `0..=65535`.
2. An `INCREMENT` value can be passed via environment variable.
3. The `0` match arm is treated as the "broken" state — and that's exactly where the flag is hidden (discovered at runtime).

---

## Step 2: Identify the Vulnerability — Integer Overflow

The program uses `counter += increment` without any overflow guard.

In Rust:
- **Debug builds** → integer overflow causes a **panic** (safe by default).
- **Release builds** (`--release`) → integer overflow **wraps around silently** (two's complement behavior).

The binary is compiled in release mode, so overflow wraps.

### The Math

| Variable  | Value   |
|-----------|---------|
| `counter` | `1`     |
| `increment`| `65535` |
| `counter += increment` | `1 + 65535 = 65536` |
| `65536 mod 65536` | **`0`** |

A `u16` can only hold values up to `65535`. Adding `65535` to `1` produces `65536`, which wraps to `0` — hitting the "broken" branch and revealing the flag.

---

## Step 3: Exploit

### One-liner (bash)
```bash
echo "" | INCREMENT=65535 ./counter
```

### Python script
```bash
python3 solve.py
```

Expected output:
```
Increment: 65535
Press ENTER to count up!
Counter: 0
flag{isnt_rust_suppos3dtobe_S4fe}
```

---

## Step 4: Why the `_` Branch is Unreachable

You might wonder about the `_ => { println!("Max count reached!"); }` branch. Since `counter` is a `u16`, its only possible values are `0..=65535`. The match arms already cover:
- `0` — the overflow/broken arm
- `1..=65535` — normal counting

The wildcard `_` **can never be reached** for a `u16`. The Rust compiler would even warn about this. It's dead code — a red herring to make the program look more robust than it is.

---

## Root Cause & Fix

The vulnerability is **unchecked integer arithmetic in release mode**.

**Vulnerable code:**
```rust
counter += increment;
```

**Fixed code (saturating addition):**
```rust
counter = counter.saturating_add(increment);
```

`saturating_add` clamps the result at `u16::MAX` (65535) instead of wrapping, preventing the overflow entirely.

---

## Flag

```
flag{isnt_rust_suppos3dtobe_S4fe}
```

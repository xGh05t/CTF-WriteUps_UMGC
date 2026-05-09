#!/usr/bin/env python3
"""
Gate-level Verilog netlist simulator for the HTB Hardware Managing System CTF.

Parses CtfTask.v (a synthesized netlist of LUT/MUXCY/MUXF7/MUXF8/XORCY/FDCE/FDPE
primitives) and provides a fast Python simulator that matches the behaviour of
the supplied Verilator binary VCtfTask exactly.

Public API:
    NETS          — dict: net name -> internal index
    ff_list       — list of (D_idx, Q_idx, ctrl_idx, init_value)
    comb_gates    — list of combinational gate descriptions (post-toposort)
    init_values() — fresh value vector with constants populated
    tick(values)  — advance one clock cycle
    tick_compiled(values) — same, using a code-generated evaluate()
    reset_state() — return a value vector after a reset pulse
    evaluate(values), evaluate_compiled(values) — combinational eval only

This module is purely combinational/sequential simulation; it does not emulate
the temperature loop in main() — that lives in chain_search.py / solve.py.
"""
import os, re, sys

VERILOG_PATH = os.environ.get(
    'CTF_VERILOG',
    os.path.join(os.path.dirname(__file__), '..', 'challenge_files', 'CtfTask.v')
)


# ---------------------------------------------------------------------------
# Verilog parsing helpers
# ---------------------------------------------------------------------------

def find_modules(text):
    out = {}
    i = 0
    while True:
        m = re.search(r'module\s+(\S+)\s*\(([^)]*)\)\s*;', text[i:])
        if not m:
            break
        name = m.group(1)
        start_body = i + m.end()
        end = text.find('endmodule', start_body)
        out[name] = (m.group(2), text[start_body:end])
        i = end + len('endmodule')
    return out


def parse_instances(body):
    out = []
    pos = 0
    L = len(body)
    while pos < L:
        while pos < L and body[pos] in ' \t\r\n':
            pos += 1
        if pos >= L:
            break
        if (body.startswith('wire ', pos) or body.startswith('input ', pos)
                or body.startswith('output ', pos) or body.startswith('assign ', pos)):
            sc = body.find(';', pos)
            pos = sc + 1
            continue
        start = pos
        if body[pos] == '\\':
            pos += 1
            while pos < L and body[pos] not in ' \t\r\n':
                pos += 1
        else:
            while pos < L and (body[pos].isalnum() or body[pos] in '_$'):
                pos += 1
        modname = body[start:pos]
        while pos < L and body[pos] in ' \t\r\n':
            pos += 1
        istart = pos
        if body[pos] == '\\':
            pos += 1
            while pos < L and body[pos] not in ' \t\r\n':
                pos += 1
        else:
            while pos < L and (body[pos].isalnum() or body[pos] in '_$'):
                pos += 1
        instname = body[istart:pos]
        while pos < L and body[pos] in ' \t\r\n':
            pos += 1
        if pos >= L or body[pos] != '(':
            break
        pos += 1
        depth = 1
        portlist_start = pos
        while pos < L and depth > 0:
            if body[pos] == '(':
                depth += 1
            elif body[pos] == ')':
                depth -= 1
            pos += 1
        portlist_text = body[portlist_start:pos - 1]
        while pos < L and body[pos] in ' \t\r\n':
            pos += 1
        if pos < L and body[pos] == ';':
            pos += 1
        out.append((modname, instname, portlist_text))
    return out


def parse_ports(text):
    out = {}
    pos = 0
    L = len(text)
    while pos < L:
        dot = text.find('.', pos)
        if dot < 0:
            break
        i = dot + 1
        while i < L and (text[i].isalnum() or text[i] == '_'):
            i += 1
        port = text[dot + 1:i]
        while i < L and text[i] in ' \t\r\n':
            i += 1
        if i >= L or text[i] != '(':
            pos = i
            continue
        i += 1
        depth = 1
        vstart = i
        while i < L and depth > 0:
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
            i += 1
        out[port] = text[vstart:i - 1].strip()
        pos = i
    return out


def norm(net):
    n = net.strip()
    if n.startswith('\\'):
        n = n[1:].strip()
    return re.sub(r'\s+', '', n)


def parse_const(s):
    s = s.strip()
    m = re.match(r"(\d+)'([hbd])([0-9a-fA-F]+)", s)
    if m:
        b = m.group(2)
        return int(m.group(3), {'h': 16, 'b': 2, 'd': 10}[b])
    return None


# ---------------------------------------------------------------------------
# LUT body compilation (paramod LUT6 with custom mux-tree bodies)
# ---------------------------------------------------------------------------

def compute_lut_truth_table(modname, modules):
    """Compute the truth table for a paramod LUT module by interpreting its
    body's `assign` statements."""
    if modname not in modules:
        return None
    body = modules[modname][1]
    assigns = []
    for m in re.finditer(r'assign\s+(\\?\S+(?:\s*\[\s*\d+\s*\])?)\s*=\s*(.*?);',
                         body, re.DOTALL):
        assigns.append((norm(m.group(1)), m.group(2).strip()))

    def eval_expr(expr, env):
        expr = expr.strip()

        def find_top(s, op):
            depth = 0
            for i, c in enumerate(s):
                if c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                elif c == op and depth == 0:
                    return i
            return -1

        qi = find_top(expr, '?')
        if qi >= 0:
            cond = expr[:qi]
            rest = expr[qi + 1:]
            ci = find_top(rest, ':')
            return (eval_expr(rest[:ci], env) if eval_expr(cond, env)
                    else eval_expr(rest[ci + 1:], env))
        while expr.startswith('(') and expr.endswith(')'):
            depth = 0
            ok = True
            for i, c in enumerate(expr[:-1]):
                if c == '(':
                    depth += 1
                elif c == ')':
                    depth -= 1
                    if depth == 0:
                        ok = False
                        break
            if ok:
                expr = expr[1:-1].strip()
            else:
                break
        for op in ['|', '&']:
            i = find_top(expr, op)
            if i >= 0:
                a = eval_expr(expr[:i], env)
                b = eval_expr(expr[i + 1:], env)
                return (a & b & 1) if op == '&' else ((a | b) & 1)
        if expr.startswith('~'):
            return (~eval_expr(expr[1:], env)) & 1
        c = parse_const(expr)
        if c is not None:
            return c & 1
        name = norm(expr)
        if name in env:
            return env[name] & 1
        raise ValueError(f"Unknown identifier: {name}")

    def eval_lut(input_vals):
        env = {}
        for i, n in enumerate(['I0', 'I1', 'I2', 'I3', 'I4', 'I5']):
            if i < len(input_vals):
                env[n] = input_vals[i] & 1
        # Repeat until all assigns can be evaluated (handles out-of-order assigns)
        for _ in range(50):
            changed = False
            for lhs, rhs in assigns:
                if lhs in env:
                    continue
                try:
                    env[lhs] = eval_expr(rhs, env)
                    changed = True
                except (ValueError, KeyError):
                    pass
            if not changed:
                break
        return env.get('O', 0)

    table = 0
    for idx in range(64):
        bits = [(idx >> i) & 1 for i in range(6)]
        if eval_lut(bits):
            table |= 1 << idx
    return table


# ---------------------------------------------------------------------------
# Build the circuit
# ---------------------------------------------------------------------------

with open(VERILOG_PATH) as _f:
    _text = _f.read()

modules = find_modules(_text)
ctf_body = modules['CtfTask'][1]
instances = parse_instances(ctf_body)

NETS = {}


def net_idx(name):
    if name not in NETS:
        NETS[name] = len(NETS)
    return NETS[name]


# Reserve indices for module IO and constants
for i in range(7):
    net_idx(f'io_input[{i}]')
for i in range(8):
    net_idx(f'io_temp[{i}]')
for i in range(8):
    net_idx(f'io_power[{i}]')
net_idx('io_inputDone')
net_idx('reset')
net_idx('clk')
net_idx('CONST_0')
net_idx('CONST_1')

ff_list = []     # (D_idx, Q_idx, ctrl_idx, init_value)
comb_gates = []  # (output_idx, gate_type_tuple, [input_idxs])

for modname, instname, portlist_text in instances:
    ports = {p: norm(v) for p, v in parse_ports(portlist_text).items()}

    def to_idx(net_name):
        c = parse_const(net_name)
        if c == 0:
            return NETS['CONST_0']
        if c == 1:
            return NETS['CONST_1']
        return net_idx(net_name)

    if 'FDCE' in modname:
        # Async clear FF: when CLR=1, Q=0
        ff_list.append((to_idx(ports['D']), to_idx(ports['Q']),
                        to_idx(ports['CLR']), 0))
    elif 'FDPE' in modname:
        # Async preset FF: when PRE=1, Q=1
        ff_list.append((to_idx(ports['D']), to_idx(ports['Q']),
                        to_idx(ports['PRE']), 1))
    else:
        init_match = re.search(r"INIT=(\d+)'([01]+)", modname)
        if init_match and 'LUT' in modname:
            n = int(re.search(r'LUT(\d)', modname).group(1))
            init = int(init_match.group(2), 2)
            inps = [to_idx(ports[f'I{i}']) for i in range(n)]
            comb_gates.append((to_idx(ports['O']), ('LUT_INIT', init, n), inps))
        elif 'paramod' in modname and 'LUT' in modname:
            tt = compute_lut_truth_table(modname, modules)
            inps = []
            for i in range(6):
                key = f'I{i}'
                if key in ports:
                    inps.append(to_idx(ports[key]))
            comb_gates.append((to_idx(ports['O']), ('LUT_TT', tt, len(inps)), inps))
        elif modname == 'MUXCY':
            comb_gates.append((to_idx(ports['O']), ('MUXCY',),
                               [to_idx(ports['CI']), to_idx(ports['DI']),
                                to_idx(ports['S'])]))
        elif modname in ('MUXF7', 'MUXF8'):
            comb_gates.append((to_idx(ports['O']), ('MUX',),
                               [to_idx(ports['I0']), to_idx(ports['I1']),
                                to_idx(ports['S'])]))
        elif modname == 'XORCY':
            comb_gates.append((to_idx(ports['O']), ('XORCY',),
                               [to_idx(ports['CI']), to_idx(ports['LI'])]))


# ---------------------------------------------------------------------------
# Topological sort of combinational gates
# ---------------------------------------------------------------------------

out_to_gate = {g[0]: i for i, g in enumerate(comb_gates)}

free_nets = set()
for i in range(7):
    free_nets.add(NETS[f'io_input[{i}]'])
for i in range(8):
    free_nets.add(NETS[f'io_temp[{i}]'])
free_nets.add(NETS['io_inputDone'])
free_nets.add(NETS['reset'])
free_nets.add(NETS['clk'])
free_nets.add(NETS['CONST_0'])
free_nets.add(NETS['CONST_1'])
for d, q, ctrl, init in ff_list:
    free_nets.add(q)

topo_order = []
_visited = set()


def _visit(idx):
    if idx in _visited:
        return
    _visited.add(idx)
    out_net, gtype, inps = comb_gates[idx]
    for inp in inps:
        if inp in free_nets:
            continue
        if inp in out_to_gate:
            _visit(out_to_gate[inp])
    topo_order.append(idx)


# Increase recursion for the deep carry chain
sys.setrecursionlimit(10000)
for i in range(len(comb_gates)):
    _visit(i)


# ---------------------------------------------------------------------------
# Simulator
# ---------------------------------------------------------------------------

def init_values():
    v = [0] * len(NETS)
    v[NETS['CONST_1']] = 1
    return v


def evaluate(values):
    """Combinational eval, in topological order."""
    for gidx in topo_order:
        out_net, gtype, inps = comb_gates[gidx]
        gt = gtype[0]
        if gt == 'LUT_INIT':
            init = gtype[1]
            n = gtype[2]
            sel = 0
            for i in range(n):
                sel |= (values[inps[i]] & 1) << i
            values[out_net] = (init >> sel) & 1
        elif gt == 'LUT_TT':
            tt = gtype[1]
            n = gtype[2]
            sel = 0
            for i in range(n):
                sel |= (values[inps[i]] & 1) << i
            values[out_net] = (tt >> sel) & 1
        elif gt == 'MUXCY':
            ci, di, s = inps
            values[out_net] = values[ci] if values[s] else values[di]
        elif gt == 'MUX':
            i0, i1, s = inps
            values[out_net] = values[i1] if values[s] else values[i0]
        elif gt == 'XORCY':
            ci, li = inps
            values[out_net] = values[ci] ^ values[li]


# Generate a faster compiled evaluator (inlined Python source)
def _generate_eval_code():
    lines = ["def evaluate_compiled(values):"]
    for gidx in topo_order:
        out_net, gtype, inps = comb_gates[gidx]
        gt = gtype[0]
        if gt in ('LUT_INIT', 'LUT_TT'):
            tbl = gtype[1]
            n = gtype[2]
            sel_terms = " | ".join(f"(values[{inps[i]}] << {i})" for i in range(n))
            lines.append(f"    values[{out_net}] = ({tbl} >> ({sel_terms})) & 1")
        elif gt == 'MUXCY':
            ci, di, s = inps
            lines.append(
                f"    values[{out_net}] = values[{ci}] if values[{s}] else values[{di}]")
        elif gt == 'MUX':
            i0, i1, s = inps
            lines.append(
                f"    values[{out_net}] = values[{i1}] if values[{s}] else values[{i0}]")
        elif gt == 'XORCY':
            ci, li = inps
            lines.append(f"    values[{out_net}] = values[{ci}] ^ values[{li}]")
    return "\n".join(lines)


_ns = {}
exec(_generate_eval_code(), _ns)
evaluate_compiled = _ns['evaluate_compiled']


def tick(values):
    evaluate(values)
    new_q = []
    for d, q, ctrl, init in ff_list:
        if values[ctrl]:
            new_q.append(init)
        else:
            new_q.append(values[d])
    for i, (d, q, ctrl, init) in enumerate(ff_list):
        values[q] = new_q[i]


def tick_compiled(values):
    evaluate_compiled(values)
    new_q = []
    for d, q, ctrl, init in ff_list:
        if values[ctrl]:
            new_q.append(init)
        else:
            new_q.append(values[d])
    for i, (d, q, ctrl, init) in enumerate(ff_list):
        values[q] = new_q[i]


def reset_state():
    """Pulse reset for one cycle, then deassert. Returns post-reset state."""
    v = init_values()
    v[NETS['reset']] = 1
    tick_compiled(v)
    v[NETS['reset']] = 0
    tick_compiled(v)
    return v


# ---------------------------------------------------------------------------
# Helpers for sending bytes the same way VCtfTask does
# ---------------------------------------------------------------------------

INPUT_NETS = [NETS[f'io_input[{i}]'] for i in range(7)]
DONE_NET = NETS['io_inputDone']


def send_byte_state(v, byte_value):
    """Send one byte to the parser: drive io_input, pulse io_inputDone."""
    bv = byte_value & 0x7F  # io_input is 7 bits
    for i in range(7):
        v[INPUT_NETS[i]] = (bv >> i) & 1
    v[DONE_NET] = 1
    tick_compiled(v)
    v[DONE_NET] = 0
    tick_compiled(v)


if __name__ == '__main__':
    import time
    print(f"Loaded netlist with {len(NETS)} nets, "
          f"{len(comb_gates)} combinational gates, {len(ff_list)} flip-flops")
    v = reset_state()
    REG7 = NETS[
        '_211d3dff7ef1a9f1f061bbe9f64546fa9e5b30f265dcfa230fef9e3774891161[7]']
    print(f"After reset: reg[7] (backdoor bit) = {v[REG7]}")
    t0 = time.time()
    for _ in range(1000):
        v2 = list(v)
        tick_compiled(v2)
    print(f"1000 ticks in {time.time() - t0:.3f}s")

"""fuzz_kernel.py -- differential scheduler fuzzer: random scheduling programs
run on the real kernel under QEMU, judged by ledger conservation (O_CBS) and by
the kernel's own crash output. Coverage-guided over op shapes.

Usage: python3 fuzz_kernel.py --kernel /path/bzImage --rounds 5 --batch 60
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "adapters"))
from linux_cbs import check_stepwise, check_boundary  # noqa: E402
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "oracle"))
from schedfuzz_oracle import witness_signature  # noqa: E402

HERE = Path(__file__).resolve().parent
EXEC_SRC = HERE / "sched_fuzz_exec.c"

# Probability that an op reuses the previous op's worker slot.
SLOT_LOCALITY = 0.5

# Probability that an op is steered onto a slot satisfying its precondition.
STATE_BIAS = 0.5

# Ops this run never generates; no mutation operator writes one either.
EXCLUDE_OPS: set = set()


def _excluded(line: str) -> bool:
    t = line.split()
    return bool(t) and t[0] in EXCLUDE_OPS


# Fraction of each batch derived by mutation rather than drawn fresh.
MUTATE_RATE = 0.5

POLICIES = [0, 1, 2, 3, 5, 6]          # OTHER FIFO RR BATCH IDLE DEADLINE
FLAGS = [0x0, 0x01, 0x08, 0x10, 0x18]  # 0, RESET_ON_FORK, KEEP_POLICY, KEEP_PARAMS, KEEP_ALL

# Ops that move total_bw in ways sigma does not model.
PERTURBERS = ("H", "D", "P", "F", "Y", "G")

LEDGER_TOL = 1 << 10                 # ~0.1% of a CPU (1<<20 == one CPU)


# ---------------------------------------------------------------- coverage
def shape_of(lines: list[str]) -> tuple:
    """The coverage key of an op-line program, derived only from its ops."""
    shape = set()
    for ln in lines:
        t = ln.split()
        if not t:
            continue
        k = t[0]
        if k == "A" and len(t) >= 8:              # A i pol rt dl pd nice fl(hex)
            try:
                shape.add(("A", int(t[2]), int(t[7], 16) != 0))
            except ValueError:
                pass
        elif k == "C" and len(t) >= 3:
            try:
                shape.add(("C", int(t[2])))
            except ValueError:
                pass
        elif k in ("P", "Y", "G") and len(t) >= 2:
            try:
                shape.add((k, int(t[1])))
            except ValueError:
                pass
        elif k in ("R", "K", "H", "D", "F", "T", "E", "O", "M", "U", "X", "S"):
            shape.add((k,))
    # Edge coverage: ordered same-slot op pairs.
    last_op: dict[str, str] = {}
    for ln in lines:
        t = ln.split()
        if len(t) > 1 and t[0] in ("A", "R", "O", "C", "U", "E", "K", "T", "M"):
            prev = last_op.get(t[1])
            if prev is not None:
                shape.add(("pair", prev, t[0]))
            last_op[t[1]] = t[0]

    # Repetition is part of coverage, coarsely (spawn ops excluded).
    counts: dict[str, int] = {}
    for ln in lines:
        t = ln.split()
        if t and t[0] not in ("W", "WB"):
            counts[t[0]] = counts.get(t[0], 0) + 1
    if counts:
        letter, n = max(counts.items(), key=lambda kv: (kv[1], kv[0]))
        bucket = 0 if n <= 1 else 1 if n <= 3 else 2 if n <= 7 else 3
        if bucket:
            shape.add(("rep", letter, bucket))
    if not any(ln[:1] in PERTURBERS for ln in lines):
        shape.add(("clean",))
    return tuple(sorted(shape))


# ---------------------------------------------------------------- generator
def rand_program(rng: random.Random) -> tuple[list[str], tuple]:
    """A random scheduling program. Returns (lines, coverage_shape)."""
    ops: list[str] = []
    nW = rng.randint(1, 4)
    ids = list(range(nW))
    # Some programs stay "ledger-clean": no bw-perturbing op (H/D/P/F/Y/G).
    ledger_clean = rng.random() < 0.30
    # Per-slot state, used only to steer the slot choice (STATE_BIAS).
    st_admitted: set = set()
    st_moved: set = set()
    st_dead: set = set()
    for i in ids:
        blocked = rng.random() < 0.5     # WB = worker spawned blocked
        spawn = ("WB %d" if blocked else "W %d") % i
        if not _excluded(spawn):
            ops.append(spawn)
    nsteps = rng.randint(4, 24)
    last_slot = None
    for _ in range(nsteps):
        i = (last_slot if (last_slot is not None and rng.random() < SLOT_LOCALITY)
             else rng.choice(ids))
        last_slot = i
        # grammar: A=setattr R=GRUB-reclaim K=kill H=hotplug D=fair_server-write
        # F=fork-churn P=cpuset-partition re-apply S=ledger-sample Z=sleep
        # O=DL-overrun M=cgroup-migrate X=futex-PI boost E=DL<->OTHER churn
        # T=RLIMIT_RTTIME on a SCHED_FIFO task  C/U=into a cpu's partition/back
        # Y/G=background hotplug / fair_server-write churners
        if ledger_clean:
            kind = rng.choice(["A", "A", "A", "E", "E", "T", "T",
                               "O", "R", "K", "X", "S", "Z", "C", "U"])
        else:
            kind = rng.choice(["A", "A", "A", "R", "K", "H", "D", "F", "P",
                               "O", "M", "X", "S", "Z",
                               "Y", "Y", "G", "G", "T", "T",
                               "E", "E", "C", "C", "U", "U"])
        if EXCLUDE_OPS:
            _tries = 0
            while kind in EXCLUDE_OPS and _tries < 16:
                pool = ["A", "A", "A", "R", "K", "H", "D", "F", "P",
                        "O", "M", "X", "S", "Z", "Y", "Y", "G", "G",
                        "T", "T", "E", "E", "C", "C", "U", "U",
                        "Z"]
                kind = rng.choice(pool); _tries += 1
            if kind in EXCLUDE_OPS:
                kind = "S"
            if kind in EXCLUDE_OPS:
                continue
        # steer toward a slot where this op means something (STATE_BIAS)
        _want = {"C": st_admitted, "E": st_admitted, "U": st_moved}.get(kind)
        if _want is None and kind in ("K", "T", "M"):
            _want = set(ids) - st_dead
        if _want and rng.random() < STATE_BIAS:
            _cand = [j for j in ids if j in _want]
            if _cand:
                i = rng.choice(_cand)
                last_slot = i

        if kind == "A":
            pol = rng.choice(POLICIES)
            fl = rng.choice(FLAGS)
            if pol == 6:
                pd = rng.choice([10000, 20000, 50000, 100000])
                rt = max(1000, int(pd * rng.uniform(0.05, 0.4)))
                dl = rng.choice([pd, int(pd * rng.uniform(0.5, 1.0))])
                if rng.random() < 0.4:      # mix in GRUB reclaim
                    fl |= 0x02
            else:
                rt = dl = pd = 0
            nice = rng.choice([0, 0, -5, 5, 19, -20])
            ops.append(f"A {i} {pol} {rt} {dl} {pd} {nice} {fl:x}")
            if not (fl & 0x18):
                st_admitted.add(i) if pol == 6 else st_admitted.discard(i)
        elif kind == "R":
            pd = rng.choice([20000, 50000, 100000])
            rt = max(1000, int(pd * rng.uniform(0.05, 0.3)))
            ops.append(f"R {i} {rt} {pd}"); st_admitted.add(i)
        elif kind == "K":
            ops.append(f"K {i}")
            st_admitted.discard(i); st_moved.discard(i); st_dead.add(i)
        elif kind == "H":
            ops.append(f"H {rng.choice([1,2,3])} {rng.randint(0,1)}")
        elif kind == "D":
            ops.append(f"D {rng.choice([1,2,3])} {rng.choice([1,100000,300000])} "
                       f"{rng.choice([100000,1000000,2000000])}")
        elif kind == "F":
            ops.append(f"F {rng.choice([50,150,400])}")
        elif kind == "P":
            pc = rng.choice([1,2,3]); ops.append(f"P {pc}")
        elif kind == "Y":
            c = rng.choice([1, 2, 3]); ops.append(f"Y {c}")
        elif kind == "G":
            c = rng.choice([1, 2, 3]); ops.append(f"G {c}")
        elif kind == "T":
            _t = i; ops.append(f"T {_t}")
            st_admitted.discard(_t); st_moved.discard(_t); st_dead.add(_t)
        elif kind == "E":
            _e = i
            ops.append(f"E {_e} {rng.choice([1000,2000,5000,12000])} "
                       f"{rng.choice([10000,50000,100000])} {rng.randint(1,4)}")
            st_admitted.discard(_e)
        elif kind == "C":
            ops.append(f"C {i} {rng.choice([1,2,3])}"); st_moved.add(i)
        elif kind == "U":
            ops.append(f"U {i}"); st_moved.discard(i)
        elif kind == "O":
            pd = rng.choice([20000, 50000])
            ops.append(f"O {i} {rng.randint(2000,7000)} {pd}"); st_admitted.add(i)
        elif kind == "M":
            ops.append(f"M {i}")
        elif kind == "X":
            ops.append("X")
        elif kind == "S":
            ops.append("S")
        else:
            ops.append(f"Z {rng.choice([1000,5000,20000])}")
    return ops, shape_of(ops)


# Ops of one operand shape, which change_op may swap for one another.
OP_CLASSES = [
    ["T", "K", "M"],             # <op> <slot>
    ["P", "Y", "G"],             # <op> <cpu>
    ["R", "O"],                  # <op> <slot> <runtime> <period>
]


def mutate_program(lines: list[str], rng: random.Random) -> list[str]:
    """Mutate one scenario with one operator, drawn uniformly from nine."""
    out = list(lines)
    op = rng.choice(["dup", "drop", "tweak", "append", "bitflip", "change_op",
                     "swap", "insert", "splice"])
    if op == "swap":
        body = [k for k, l in enumerate(out) if l.split()[0] not in ("W", "WB")]
        if len(body) >= 2:
            a, b = rng.sample(body, 2)
            out[a], out[b] = out[b], out[a]
        return out
    if op == "insert":
        body = [k for k, l in enumerate(out) if l.split()[0] not in ("W", "WB")]
        if body:
            donor, _ = rand_program(rng)
            cand = [l for l in donor if l.split()[0] not in ("W", "WB")]
            if cand:
                out.insert(rng.choice(body), rng.choice(cand))
        return out
    if op == "splice":
        donor, _ = rand_program(rng)
        cand = [l for l in donor if l.split()[0] not in ("W", "WB")]
        body = [k for k, l in enumerate(out) if l.split()[0] not in ("W", "WB")]
        if len(cand) >= 2 and body:
            n = rng.randint(2, min(5, len(cand)))
            st = rng.randrange(0, max(1, len(cand) - n + 1))
            at = rng.choice(body)
            out[at:at] = cand[st:st + n]
        return out
    if op == "bitflip":
        # Redirect an op to a different object: rewrite its slot or cpu operand.
        slots = sorted({int(l.split()[1]) for l in out
                        if l.split()[0] in ("W", "WB") and len(l.split()) > 1})
        idxs = [k for k, l in enumerate(out)
                if l.split()[0] not in ("W", "WB", "X", "S", "Z")
                and len(l.split()) > 1 and l.split()[1].lstrip("-").isdigit()]
        if idxs:
            k = rng.choice(idxs); t = out[k].split()
            if t[0] in ("P", "Y", "G", "H"):
                t[1] = str(rng.choice([1, 2, 3]))
            elif slots:
                t[1] = str(rng.choice(slots))
            out[k] = " ".join(t)
        return out
    if op == "change_op":
        idxs = [k for k, l in enumerate(out) if l.split()[0] in
                ("E", "T", "K", "M", "P", "Y", "G", "R", "O", "C", "U")]
        if idxs:
            k = rng.choice(idxs); t = out[k].split()
            if t[0] == "C" and len(t) >= 3:
                if "U" not in EXCLUDE_OPS:
                    out[k] = f"U {t[1]}"
            elif t[0] == "U" and len(t) >= 2:
                if "C" not in EXCLUDE_OPS:
                    out[k] = f"C {t[1]} {rng.choice([1,2,3])}"
            else:
                for cls in OP_CLASSES:
                    if t[0] in cls:
                        alt = [c for c in cls
                               if c != t[0] and c not in EXCLUDE_OPS]
                        if alt:
                            t[0] = rng.choice(alt)
                            out[k] = " ".join(t)
                        break
        return out
    keep = [k for k, l in enumerate(out) if not _excluded(l)]
    if op == "dup" and keep:
        i = keep[rng.randrange(len(keep))]; out.insert(i, out[i])
    elif op == "drop" and len(out) > 2:
        del out[rng.randrange(len(out))]
    elif op == "append":
        extra, _ = rand_program(rng)
        if extra:
            out += extra[rng.randrange(len(extra)):]
    else:  # tweak: rewrite a numeric parameter, or an A op's policy and flags
        def _bend(v):
            v = int(v)
            if v <= 0:
                return v
            f = rng.choice([0.25, 0.5, 0.9, 0.99, 1.01, 1.1, 2.0, 4.0])
            return max(1, int(v * f))
        # field indices that carry a number, per op
        NUMF = {"A": [3, 4, 5, 6], "R": [2, 3], "O": [2, 3],
                "D": [2, 3], "Z": [1], "F": [1], "E": [2, 3, 4]}
        idxs = [k for k, l in enumerate(out)
                if l.split()[0] in NUMF and len(l.split()) > max(NUMF[l.split()[0]])]
        if idxs:
            k = rng.choice(idxs); p = out[k].split()
            if p[0] == "A" and rng.random() < 0.4:
                p[2] = str(rng.choice(POLICIES))
                p[7] = f"{rng.choice(FLAGS):x}"
            else:
                f = rng.choice(NUMF[p[0]])
                if p[0] == "A" and f == 6:
                    p[6] = str(rng.choice([0, -5, 5, 19, -20]))
                else:
                    p[f] = str(_bend(p[f]))
            out[k] = " ".join(p)
    return out


# ---------------------------------------------------------------- oracle

def oracle(prog_trace: str, lines: list[str], *,
           boundary: bool = False) -> list[dict]:
    """Check one program's trace against the formal invariants; return the
    violations. `boundary` marks a boundary-granularity (no per-op) trace."""
    v = []
    cbs = check_stepwise(prog_trace, lines, tol=LEDGER_TOL)
    # Boundary granularity: no per-op records, so judge the whole program.
    if "error" in cbs and boundary:
        b = check_boundary(prog_trace, tol=LEDGER_TOL)
        if b["checked"] and b["fired"]:
            leak = b["residual"] > 0
            v.append({"kind": "ledger_leak" if leak else "ledger_over_release",
                      "theorem": ("REL_O_CBS_LEAK" if leak
                                  else "REL_O_CBS_OVER_RELEASE"),
                      "residual_bw": b["residual"],
                      "expected": b.get("expected"),
                      "observed": b.get("observed"),
                      "residual_change": None,
                      "granularity": "boundary",
                      "note": "boundary verdict: the break is somewhere in this "
                              "program; re-run it under --oracle-granularity "
                              "perop to attribute it to an operation"})
    for w in cbs.get("violations", []):
        if w["status"] != "confirmed":
            continue
        if w["delta"] > 0:
            v.append({"kind": "ledger_leak",
                      "theorem": "REL_O_CBS_LEAK",
                      "residual_bw": w["delta"],
                      "expected": w.get("expected"),
                      "observed": w.get("observed"),
                      "residual_change": w.get("residual_change"),
                      "sigma_sig": w.get("sigma_sig"),
                      "step": w["step"],
                      "op": w["op"], "note": w["note"]})
        elif w["class"] == "baseline_drift":
            v.append({"kind": "ledger_baseline_drift",
                      "theorem": "DIAG_LEDGER_BASELINE_DRIFT",
                      "residual_bw": w["delta"],
                      "expected": w.get("expected"),
                      "observed": w.get("observed"),
                      "residual_change": w.get("residual_change"),
                      "sigma_sig": w.get("sigma_sig"),
                      "step": w["step"],
                      "op": w["op"],
                      "note": "ledger moved below this program's baseline while it "
                              "held NOTHING admitted -- drift from outside the "
                              "program, NOT attributable to this op"})
        else:
            v.append({"kind": "ledger_over_release",
                      "theorem": "REL_O_CBS_OVER_RELEASE",
                      "residual_bw": w["delta"],
                      "expected": w.get("expected"),
                      "observed": w.get("observed"),
                      "residual_change": w.get("residual_change"),
                      "sigma_sig": w.get("sigma_sig"),
                      "step": w["step"],
                      "op": w["op"],
                      "note": (w["note"] + " | " if w["note"] else "")
                              + "ledger below expected: over-release or an "
                                "out-of-program ledger change -- triage"})
    x = cbs.get("xcheck", {})
    if x.get("disagree") or x.get("state_disagree"):
        return [{"kind": "sigma_model_disagreement",
                 "theorem": "TOOL_SELF_CHECK",
                 "residual": (x.get("disagree") or x.get("state_disagree"))[:3],
                 "note": "in-guest sigma and host re-derivation disagree -- one of "
                         "the two MODELS is wrong; NOT a kernel finding. Every "
                         "O_CBS verdict from this trace is DISCARDED, not reported"}]
    return v


def finding_id(v: dict, lines: list[str]) -> str:
    """Dedup key for violation `v` of program `lines`: kind|op|sigma signature,
    or kind|step|op|program text when `v` carries no sigma signature."""
    return "B_" + witness_signature(
        v["kind"], v.get("op", ""), v.get("sigma_sig"),
        step=v.get("step"), fallback_ctx="\n".join(lines))


# Ops that cannot change total_bw: sleep, ledger sample and futex-PI boost.
BW_NEUTRAL_OPS = set("ZSX")


def public_name(v: dict) -> str:
    """The name a finding is reported under: its theorem, or KERNEL:<kind>."""
    return v.get("theorem") or ("KERNEL:" + v["kind"])


def trigger_counts(bugs: dict) -> dict:
    """Recorded findings per public name, leaving out DIAG_ diagnostics."""
    out: dict[str, int] = {}
    for b in bugs.values():
        n = public_name(b["violation"])
        if not n.startswith("DIAG_"):
            out[n] = out.get(n, 0) + 1
    return out


def attribution_misses(bugs: dict) -> list[tuple[str, str]]:
    """REL_O_CBS_* verdicts charged to an op that cannot move the ledger."""
    out = []
    for name, b in sorted(bugs.items()):
        v = b.get("violation") or {}
        if not str(v.get("theorem") or "").startswith("REL_O_CBS_"):
            continue
        prog, step, op = b.get("program") or [], v.get("step"), v.get("op", "")
        if step is None or not op:
            continue
        k, sl = op[:1], (op.split() + [None])[1]
        why = None
        if k in BW_NEUTRAL_OPS:
            why = f"{k} has no bandwidth effect"
        elif k in ("U", "M") and not any(p.split()[:1] == ["C"]
                                         and (p.split() + [None])[1] == sl
                                         for p in prog[:step]):
            why = ("move-back on a slot that was never moved out" if k == "U"
                   else "M on a slot that was never moved out has no "
                        "bandwidth effect")
        elif k == "C":
            outs = [i for i, p in enumerate(prog[:step])
                    if p.split()[:1] == ["C"] and (p.split() + [None])[1] == sl]
            backs = [i for i, p in enumerate(prog[:step])
                     if p.split()[:1] in (["U"], ["M"])
                     and (p.split() + [None])[1] == sl]
            if outs and (not backs or max(backs) < max(outs)):
                why = "move-out on a slot already out of the observed domain"
        if why:
            out.append((name, f"{public_name(v)} at step {step} op {op!r} -- {why}"))
    return out


def oracle_applicability(prog_trace: str, lines: list[str], *,
                         boundary: bool = False) -> dict:
    """Per-relation "checked" / "inapplicable:<why>", plus per-op `_counts`."""
    st = {}
    cbs = check_stepwise(prog_trace, lines, tol=LEDGER_TOL)
    if "error" in cbs and boundary:
        b = check_boundary(prog_trace, tol=LEDGER_TOL)
        st["ledger"] = "checked" if b["checked"] else "inapplicable:" + b["reason"]
    elif "error" in cbs:
        st["ledger"] = "inapplicable:no_step_records"
    else:
        st["ledger"] = "checked" if cbs["checked"] else "inapplicable:no_checked_step"
    x = cbs.get("xcheck", {})
    st["_counts"] = {
        "ledger_steps_checked": cbs.get("checked", 0),
        "ledger_steps_suspended": cbs.get("suspended", 0),
        "ledger_steps_anchored": cbs.get("anchored", 0),
        "xcheck_agree": 0 if x.get("absent") else x.get("agree", 0),
        "xcheck_compared": 0 if x.get("absent") else x.get("compared", 0),
        "xcheck_absent_progs": 1 if x.get("absent") else 0,
    }
    return st


# Crash signatures, most specific first: the first match on a line wins.
_OOPS_HEADER = r".*: [0-9a-f]{4} \[#[0-9]+\]"
_LOCKDEP_REPORT = "|".join((
    r"WARNING: possible circular locking dependency detected",
    r"WARNING: \S+-safe -> \S+-unsafe lock order detected",
    r"WARNING: possible recursive locking detected",
    r"WARNING: inconsistent lock state",
    r"WARNING: possible irq lock inversion dependency detected",
    r"\[ BUG: Invalid wait context \]",
    r"WARNING: Nested lock was not taken",
    r"WARNING: bad unlock balance detected!",
    r"WARNING: bad contention detected!",
    r"WARNING: held lock freed!",
    r"WARNING: .+/\d+ still has locks held!",
    r"WARNING: lock held when returning to user space!",
    r"WARNING: suspicious RCU usage",
))
CRASH_SIGS = [
    (r"divide error" + _OOPS_HEADER, "divide_error"),
    (r"invalid opcode" + _OOPS_HEADER, "invalid_opcode"),
    (r"stack segment" + _OOPS_HEADER, "stack_segment"),
    (r"general protection fault" + _OOPS_HEADER, "general_protection_fault"),
    (r"Kernel panic|Oops:", "kernel_oops"),
    (_LOCKDEP_REPORT, "lockdep"),
    (r"WARNING:.*kernel/sched", "sched_warn"),
    (r"BUG:.*kernel/sched", "kernel_bug"),
]


def scan_crashes(serial: str) -> list[dict]:
    out = []
    seen = set()
    for line in serial.splitlines():
        for pat, kind in CRASH_SIGS:
            if re.search(pat, line):
                key = (kind, line.strip())
                if key not in seen:
                    seen.add(key)
                    out.append({"kind": kind, "evidence": line.strip()})
                break
    return out


def split_programs(serial: str) -> dict[int, str]:
    progs = {}
    for m in re.finditer(r"##PROG (\d+)\n(.*?)##PROG_END \1", serial, re.DOTALL):
        progs[int(m.group(1))] = m.group(2)
    return progs


# ---------------------------------------------------------------- qemu batch
def build_initramfs(exec_bin: Path, programs_txt: str, out_cpio: Path):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "proc").mkdir(); (root / "sys").mkdir()
        shutil.copy(exec_bin, root / "init"); os.chmod(root / "init", 0o755)
        (root / "programs").write_text(programs_txt)
        cp = subprocess.run(
            ["bash", "-c", "find . -print0 | cpio --null -o --format=newc"],
            cwd=root, capture_output=True)
        out_cpio.write_bytes(cp.stdout)


def _serial_text(data) -> str:
    """QEMU output as text: decoded, CRLF and lone CR translated to LF."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        data = data.decode(errors="replace")
    return data.replace("\r\n", "\n").replace("\r", "\n")


def run_batch(qemu, kernel, exec_bin, programs, smp, timeout) -> str:
    txt = "\n===\n".join("\n".join(p) for p in programs) + "\n"
    fd, cpio_path = tempfile.mkstemp(prefix="fuzzprogs_", suffix=".cpio")
    os.close(fd)
    cpio = Path(cpio_path)
    build_initramfs(exec_bin, txt, cpio)
    cmd = [qemu, "-no-reboot", "-nographic", "-m", "512", "-smp", str(smp),
           "-kernel", kernel, "-initrd", str(cpio),
           "-append", "console=ttyS0 panic=1 rdinit=/init"]
    try:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return p.stdout + p.stderr
        except subprocess.TimeoutExpired as e:
            # The marker tells the resume logic that this boot timed out.
            return (_serial_text(e.stdout) + _serial_text(e.stderr)
                    + "\n##QEMU_TIMEOUT\n")
    finally:
        try:
            cpio.unlink()
        except OSError:
            pass


def run_batch_resumable(qemu, kernel, exec_bin, programs, smp, timeout,
                        max_reboots=None):
    """Run a batch, rebooting to resume past a program that cut its boot short.
    Returns (merged_serial, {orig_idx: trace}, crasher_orig_idxs, n_reboots,
    segments), where segments is [(one boot's serial, its crasher or None)]."""
    if max_reboots is None:
        max_reboots = max(8, len(programs))
    todo = list(range(len(programs)))        # original indices still to run, in order
    traces, serials, crashers, boots = {}, [], set(), 0
    timeouts = 0
    rebase_failed = 0
    segments: list[tuple[str, int | None]] = []
    while todo and boots <= max_reboots:
        boots += 1
        sub = [programs[i] for i in todo]
        serial = run_batch(qemu, kernel, exec_bin, sub, smp, timeout)
        serials.append(serial)
        local = split_programs(serial)
        for lidx, tr in local.items():
            traces[todo[lidx]] = tr
        done_local = set(local.keys())
        if "##LEDGER_REBASE_FAILED" in serial:
            # stopped between programs: re-run the untested tail, blaming none
            rebase_failed += 1
            segments.append((serial, None))
            nxt = [todo[l] for l in range(len(sub)) if l not in done_local]
            if not nxt or len(nxt) == len(todo):
                break
            todo = nxt
            continue
        if "##FUZZ_DONE" in serial or len(done_local) == len(sub):
            segments.append((serial, None))
            break
        started = {int(m) for m in re.findall(r"##PROG (\d+)", serial)}
        running = started - done_local
        if running and "##QEMU_TIMEOUT" in serial:
            # wall-clock timeout: counted apart from crashers; re-run the tail
            timeouts += 1
            segments.append((serial, None))
            nxt = [todo[l] for l in range(len(sub)) if l not in done_local]
            if not nxt:
                break
            if len(nxt) == len(todo):
                # no progress: skip the running program without blaming it
                cut = min(running)
                todo = [todo[l] for l in range(len(sub))
                        if l > cut and l not in done_local]
                if not todo:
                    break
                continue
            todo = nxt
            continue
        if running:
            cut = min(running)
            crashers.add(todo[cut])
            segments.append((serial, todo[cut]))
            todo = [todo[l] for l in range(len(sub)) if l > cut and l not in done_local]
        else:
            segments.append((serial, None))
            nxt = [todo[l] for l in range(len(sub)) if l not in done_local]
            if not nxt or len(nxt) == len(todo):
                break
            todo = nxt
    if rebase_failed:
        print(f"   [resume] rebooted {rebase_failed}x because the guest could not "
              f"restore its ledger baseline; re-ran the untested tail in a fresh "
              f"boot")
    if timeouts:
        print(f"   [resume] {timeouts} boot(s) hit the wall-clock timeout with a "
              f"program still running -- counted as TIMEOUTS, not crashes. The guest "
              f"may have been perfectly alive. Raise --timeout if this is common, "
              f"and do NOT read these as kernel aborts")
    return ("\n".join(serials), traces, crashers, boots - 1,  # reboots = extra boots
            segments)


# ---------------------------------------------------------------- minimizer
def _kinds_of(serial: str, lines: list, boundary: bool = False) -> set:
    """Violation kinds of a single-program run: oracle plus crash signatures."""
    tr = split_programs(serial).get(0, "")
    k = {v["kind"] for v in oracle(tr, lines, boundary=boundary)} if tr else set()
    return k | {c["kind"] for c in scan_crashes(serial)}


def minimize_program(qemu, kernel, exec_bin, lines, smp, timeout, want: set,
                     boundary: bool = False):
    """Drop ops one at a time by replay, keeping a drop only if every violation
    kind still fires. Returns (minimized_lines, verified_kinds)."""
    cur = list(lines)
    cur_kinds = set(want)
    improved = True
    while improved and len(cur) > 1:
        improved = False
        for i in range(len(cur)):
            cand = cur[:i] + cur[i + 1:]
            if not cand:
                continue
            serial = run_batch(qemu, kernel, exec_bin, [cand], smp, timeout)
            k = _kinds_of(serial, cand, boundary=boundary) & want
            if k >= cur_kinds:
                cur, cur_kinds = cand, k
                improved = True
                break
    return cur, cur_kinds


def main():
    global SLOT_LOCALITY, STATE_BIAS
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--batch", type=int, default=60)
    ap.add_argument("--smp", type=int, default=2)
    ap.add_argument("--minimize", action="store_true",
                    help="after testing completes, run a SEPARATE reduction "
                         "phase that replay-minimizes one representative "
                         "program per violation kind (does not affect or "
                         "interrupt the test phase)")
    ap.add_argument("--minimize-max", type=int, default=5,
                    help="cap how many reproducers the reduction phase "
                         "minimizes (default 5); reduction costs one QEMU boot "
                         "per candidate drop")
    ap.add_argument("--resume", action="store_true",
                    help="reboot and resume the batch tail past any program that "
                         "panics the kernel (instead of losing the rest of the batch)")
    ap.add_argument("--replay", default=None, metavar="FILE",
                    help="replay ONE scenario in a fresh boot and print the "
                         "oracle's verdict. FILE is a corpus B_*.json, a "
                         "reductions.json (its FIRST entry is replayed), or a "
                         "plain op-per-line text file. This is the clean-state "
                         "replay a reported finding is checked with.")
    ap.add_argument("--slot-locality", type=float, default=None,
                    help="fraction of ops steered onto the previous slot "
                         "(default %.2f); 0 makes slot choice uniform."
                         % SLOT_LOCALITY)
    ap.add_argument("--state-bias", type=float, default=None,
                    help="fraction of ops steered by sigma's current state "
                         "(default %.2f); 0 disables state-aware steering."
                         % STATE_BIAS)
    ap.add_argument("--mutate-rate", type=float, default=None,
                    help="fraction of each batch derived by mutation "
                         "(default 0.5); 0 disables mutation entirely")
    ap.add_argument("--exclude-ops", default="",
                    help="comma-separated ops to suppress (never generated), "
                         "e.g. to focus a stage on ops a relation can judge. "
                         "A run using this must state it when reporting.")
    ap.add_argument("--oracle-granularity", choices=("perop", "boundary"),
                    default="boundary",
                    help="boundary (default): judge once at the end of the "
                         "sequence, faster, NO op-level attribution -- the "
                         "verdict carries no step and no op. perop: judge after "
                         "every op and localise the break to it, ~1.26x slower; "
                         "required by anything that reads `step`/`op` off a "
                         "finding.")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out",
                    default=str(Path(tempfile.gettempdir()) / "schedfuzz_corpus"))
    args = ap.parse_args()

    run_workdir = Path(tempfile.mkdtemp(prefix="schedfuzz_run_"))
    atexit.register(shutil.rmtree, run_workdir, ignore_errors=True)

    if args.slot_locality is not None:
        SLOT_LOCALITY = args.slot_locality
        print(f"[!] SLOT_LOCALITY={SLOT_LOCALITY} (non-default): slot steering "
              f"{'DISABLED -- uniform slot choice' if SLOT_LOCALITY == 0 else 'retuned'}")
    if args.state_bias is not None:
        STATE_BIAS = args.state_bias
        print(f"[!] STATE_BIAS={STATE_BIAS} (non-default): state-aware steering "
              f"{'DISABLED' if STATE_BIAS == 0 else 'retuned'}")
    if args.mutate_rate is not None:
        global MUTATE_RATE
        MUTATE_RATE = args.mutate_rate
        print(f"[!] MUTATE_RATE={MUTATE_RATE}: "
              + ("mutation DISABLED -- every scenario is drawn fresh"
                 if MUTATE_RATE == 0 else "non-default mutation fraction"))
    if args.exclude_ops:
        global EXCLUDE_OPS
        EXCLUDE_OPS = {o.strip() for o in args.exclude_ops.split(",") if o.strip()}
        print(f"[!] EXCLUDE_OPS={sorted(EXCLUDE_OPS)}: these ops are never "
              f"generated -- this run CANNOT report any finding those ops reach")
    if args.replay:
        txt = Path(args.replay).read_text()
        try:
            doc = json.loads(txt)
            if isinstance(doc, list):          # reductions.json: its first entry
                lines = doc[0]["program"]
                recorded = None
            else:                              # a corpus B_*.json
                lines = doc.get("reduced_program") or doc["program"]
                recorded = doc.get("violation")
        except json.JSONDecodeError:
            lines = [l for l in txt.splitlines() if l.strip()]
            recorded = None
        print(f"[replay] {len(lines)} op(s) from {args.replay}")
        for l in lines:
            print(f"    {l}")
        exec_bin = run_workdir / "sched_fuzz_exec_replay"
        if subprocess.run(["gcc", "-O2", "-static", str(EXEC_SRC),
                           "-o", str(exec_bin)]).returncode != 0:
            raise SystemExit("executor failed to compile")
        qemu = shutil.which("qemu-system-x86_64")
        if not qemu:
            raise SystemExit("qemu-system-x86_64 not found")
        serial = run_batch(qemu, args.kernel, exec_bin, [lines], args.smp,
                           args.timeout)
        tr = split_programs(serial).get(0, "")
        if not tr:
            print("[replay] NO TRACE -- the boot did not complete this program. "
                  "That is not a clean negative: nothing was checked.")
            raise SystemExit(2)
        # the replay build is per-op (no -DSG_BOUNDARY_ONLY)
        vio = oracle(tr, lines)
        crash = scan_crashes(serial)
        print(f"[replay] oracle verdict: {len(vio)} violation(s), "
              f"{len(crash)} crash signature(s)")
        if recorded:
            same = [w for w in vio if w.get("kind") == recorded.get("kind")]
            if not same:
                print(f"    [stability] RELATION NOT REPRODUCED: recorded "
                      f"{recorded.get('kind')}, replay produced "
                      f"{sorted({w.get('kind') for w in vio}) or 'nothing'}")
            else:
                w = same[0]
                fields = ("expected", "observed", "residual_bw")
                diffs = [(f, recorded.get(f), w.get(f)) for f in fields
                         if recorded.get(f) is not None and recorded.get(f) != w.get(f)]
                if diffs:
                    print(f"    [stability] relation reproduced but FACTS DIFFER:")
                    for f, a, b_ in diffs:
                        print(f"        {f}: recorded={a} replay={b_}")
                else:
                    print(f"    [stability] STABLE: same relation and same "
                          f"expected/observed/drift as recorded")
        for v in vio:
            print(f"    {v}")
        for c in crash:
            print(f"    {c}")
        raise SystemExit(0 if (vio or crash) else 1)

    seed = args.seed or (int(time.time()) & 0xffffffff)
    rng = random.Random(seed)
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)

    # The granularity is a guest build option: two binaries, one source.
    boundary_mode = args.oracle_granularity == "boundary"
    exec_bin = run_workdir / (
        "sched_fuzz_exec_boundary" if boundary_mode else "sched_fuzz_exec")
    cc = ["gcc", "-O2", "-static"] + (["-DSG_BOUNDARY_ONLY"] if boundary_mode else [])
    print(f"[*] compiling guest executor (oracle granularity: "
          f"{args.oracle_granularity}) ...")
    if subprocess.run(cc + [str(EXEC_SRC), "-o", str(exec_bin)]).returncode != 0:
        raise SystemExit("executor failed to compile")
    if boundary_mode:
        print("[*] BOUNDARY mode: one verdict per program, no per-op attribution.")
        print("    A ledger break is reported against the whole program, so it can be")
        print("    detected from this run but not attributed to an operation. Re-run "
              "the flagged program under --oracle-granularity perop to attribute it.")
    qemu = shutil.which("qemu-system-x86_64")
    if not qemu:
        raise SystemExit("qemu-system-x86_64 not found")

    coverage: set = set()
    queue: list[tuple[list[str], float]] = []   # (scenario, energy)
    sigma_sigs: set = set()
    bugs: dict[str, dict] = {}
    # programs that produced a trace (##PROG_END), and their ops
    n_exec = 0
    n_ops = 0
    n_trig_prev = 0
    # per-relation applicability tally ("checked" vs why-not)
    applic: dict[str, dict] = {"ledger": {}}
    # per-op step counts and in-guest vs host sigma cross-check totals
    step_counts: dict[str, int] = {}

    t_start = time.time()
    for rnd in range(args.rounds):
        batch, shapes = [], []
        sig_of: dict[int, str] = {}
        for _ in range(args.batch):
            if queue and rng.random() < MUTATE_RATE:
                # energy-weighted selection from the queue
                tot = sum(e for _l, e in queue)
                r = rng.random() * tot
                pick = queue[-1]
                for ent in queue:
                    r -= ent[1]
                    if r <= 0:
                        pick = ent
                        break
                lines = mutate_program(pick[0], rng)
                shape = shape_of(lines)
            else:
                lines, shape = rand_program(rng)
            batch.append(lines); shapes.append(shape)
        print(f"[round {rnd+1}/{args.rounds}] booting -smp {args.smp}, "
              f"{len(batch)} programs ...")
        if args.resume:
            serial, progs, crasher_idxs, reboots, segments = run_batch_resumable(
                qemu, args.kernel, exec_bin, batch, args.smp, args.timeout)
            if reboots:
                print(f"   [resume] rebooted {reboots}x past panicking program(s) "
                      f"{sorted(crasher_idxs)}; ran the batch tail a single boot would "
                      f"have skipped -> {len(progs)}/{len(batch)} programs completed + "
                      f"every panic in the batch captured (vs only up to the first)")
        else:
            serial = run_batch(qemu, args.kernel, exec_bin, batch, args.smp, args.timeout)
            progs = split_programs(serial)
            crasher_idxs = set()
            segments = [(serial, None)]
        _ran = [i for i in progs if 0 <= i < len(batch)]
        n_exec += len(_ran)
        n_ops += sum(len(batch[i]) for i in _ran)
        crashes = scan_crashes(serial)
        crash = bool(crashes)
        # attribute crash signatures per boot, to that boot's crasher if any
        crashes = []
        seen_ev = set()
        for seg_serial, seg_crasher in segments:
            for c in scan_crashes(seg_serial):
                if c["evidence"] in seen_ev:
                    continue
                seen_ev.add(c["evidence"])
                if seg_crasher is not None and 0 <= seg_crasher < len(batch):
                    c["_prog"] = batch[seg_crasher]
                    c["_attr"] = ("program running when this boot panicked, "
                                  "identified by the resume boot sequence")
                else:
                    c["_prog"] = None
                    c["_attr"] = ("this boot completed, or panicked between "
                                  "programs, so no single program can be blamed"
                                  if args.resume else
                                  "run without --resume: the boot stops at the first "
                                  "panic and the crashing program is not identified; "
                                  "re-run with --resume to record it")
                crashes.append(c)
        crash = bool(crashes)
        for c in crashes:
            prog, attr = c.pop("_prog"), c.pop("_attr")
            bid = "B_" + hashlib.sha1(
                (c["kind"] + c["evidence"]).encode()).hexdigest()[:12]
            if bid not in bugs:
                bugs[bid] = {"id": bid, "violation": c, "program": prog,
                             "source": "in_kernel_serial", "attribution": attr}
                (out / f"{bid}.json").write_text(json.dumps(bugs[bid], indent=2))
        for idx, lines in enumerate(batch):
            shape = shapes[idx]
            new_cov = shape not in coverage
            if new_cov:
                coverage.add(shape)
            tr = progs.get(idx, "")
            vio = oracle(tr, lines, boundary=boundary_mode) if tr else []
            for _v in vio:
                if _v.get("sigma_sig"):
                    sig_of[idx] = _v["sigma_sig"]
                    break
            appl = (oracle_applicability(tr, lines, boundary=boundary_mode) if tr
                    else {"ledger": "inapplicable:no_trace"})
            for k, val in appl.pop("_counts", {}).items():
                step_counts[k] = step_counts.get(k, 0) + val
            applic_state = dict(appl)
            for rel, statev in appl.items():
                applic[rel][statev] = applic[rel].get(statev, 0) + 1
            if vio:
                for x in vio:
                    bid = finding_id(x, lines)
                    if bid not in bugs:
                        bugs[bid] = {"id": bid, "violation": x, "program": lines}
                        (out / f"{bid}.json").write_text(json.dumps(bugs[bid], indent=2))
            new_sig = sig_of.get(idx) and sig_of[idx] not in sigma_sigs
            if new_sig:
                sigma_sigs.add(sig_of[idx])

            print(f"    prog={idx} ops={len(lines)}"
                  f" O_CBS={applic_state.get('ledger', '?')}"
                  f" viol={len(vio)}"
                  + (" NOVEL" if (new_cov or new_sig) else ""))
            if new_cov or vio or new_sig:
                if len(queue) < 2000:
                    energy = 1.0 + (2.0 if vio else 0.0) + (0.5 if new_cov else 0.0) \
                                 + (0.5 if new_sig else 0.0)
                    queue.append((lines, energy))
        names = trigger_counts(bugs)
        n_trig = sum(names.values())
        print(f"   cov={len(coverage)} new-trigs={n_trig - n_trig_prev} "
              f"total-trigs={n_trig} {names}"
              + ("  CRASH-SIG-IN-SERIAL" if crash else ""))
        n_trig_prev = n_trig
        if crash:
            (out / f"crash_round{rnd}.log").write_text(serial)
        elif crasher_idxs:
            (out / f"unknown_abort_round{rnd}.log").write_text(serial)
            print(f"      !! {len(crasher_idxs)} program(s) aborted the kernel with "
                  f"NO known crash signature -- serial kept in "
                  f"unknown_abort_round{rnd}.log; this is an unclassified crash, "
                  f"not a clean run")

    wall = time.time() - t_start
    print(f"\n=== kernel fuzzing done (seed={seed}) ===")
    print(f"  programs executed : {n_exec}")
    print(f"  ops executed       : {n_ops}")
    print(f"  wall time          : {wall:.1f} s")
    print(f"  throughput         : {n_ops / wall:.1f} ops/s"
          if wall > 0 else "  throughput         : n/a (no wall time)")
    print(f"  coverage shapes    : {len(coverage)}")
    print(f"  distinct triggers  : {len(bugs)}  (distinct witness/crash-line keys, NOT distinct bugs)")
    by_thm = {}
    for b in bugs.values():
        t = public_name(b["violation"])
        by_thm[t] = by_thm.get(t, 0) + 1
    for t, c in sorted(by_thm.items()):
        print(f"    {t}: {c}")
    print("  oracle applicability (checked vs why-not):")
    for rel, tally in applic.items():
        checked = tally.get("checked", 0)
        total = sum(tally.values())
        rest = ", ".join(f"{k.split(':', 1)[1]}={v}"
                         for k, v in sorted(tally.items()) if k != "checked")
        print(f"    {rel}: checked={checked}/{total}" + (f"  [{rest}]" if rest else ""))
        if checked == 0 and total:
            print(f"      !! {rel} was NEVER evaluated -- 0 violations here means "
                  f"UNTESTED, not clean")
    sc = step_counts
    ck, su = sc.get("ledger_steps_checked", 0), sc.get("ledger_steps_suspended", 0)
    an = sc.get("ledger_steps_anchored", 0)
    if boundary_mode:
        print("    ledger per-op: n/a (boundary granularity: one verdict per program)")
    else:
        print(f"    ledger per-op: {ck} step(s) evaluated, {su} not judged "
              f"(anchors + churner-suspended) (of {ck + su} sampled)"
              + (f"; {an} of the evaluated are AFTER an anchor, so they cannot "
                 f"report a break that happened at it" if an else ""))
        if ck == 0 and (ck + su):
            print("      !! 0 operations evaluated -- says NOTHING about conservation")
    xa, xc = sc.get("xcheck_agree", 0), sc.get("xcheck_compared", 0)
    absent = sc.get("xcheck_absent_progs", 0)
    if xc:
        print(f"    sigma cross-check: {xa}/{xc} step(s) where the in-guest sigma "
              f"and the host re-derivation agree"
              + (f"  [{absent} program(s) NOT COMPARED]" if absent else ""))
        if xa != xc:
            print("      !! the two sigma MODELS disagree somewhere -- see the "
                  "sigma_model_disagreement records (a tool bug, not a finding)")
    else:
        led = applic["ledger"]
        if led.get("inapplicable:no_trace", 0) == sum(led.values()):
            why = "no program produced a trace"
        elif boundary_mode:
            why = ("the boundary build emits no per-op records; expected at "
                   "this granularity")
        elif absent:
            why = f"{absent} program(s) had no in-guest SIGMA records"
        else:
            why = "no step had both sigma models applicable"
        print(f"    sigma cross-check: NOT COMPARED ({why})")
    mis = attribution_misses(bugs)
    nled = sum(1 for b in bugs.values()
               if public_name(b["violation"]).startswith("REL_O_CBS_"))
    if nled and not boundary_mode:
        print(f"    per-op attribution: {len(mis)}/{nled} ledger violation(s) are "
              f"charged to an op that cannot move the ledger "
              f"({100 * len(mis) / nled:.1f}% -- a LOWER bound on mis-attribution)")
        for name, why in mis[:5]:
            print(f"      mis-attributed {name}: {why}")
    seen = set()
    for b in bugs.values():
        k = public_name(b["violation"])
        if k in seen:
            continue
        seen.add(k)
        print(f"\n  [{k}] {b['violation']}")
        if b.get("program"):
            print("   program:")
            for l in b["program"]:
                print(f"     {l}")
    # ---- phase 2: reduction ----
    reductions = []
    if args.minimize:
        # Tool self-check records and crash findings are not reduced.
        cands = [b for b in bugs.values()
                 if b.get("program")
                 and b["violation"].get("theorem") != "TOOL_SELF_CHECK"
                 and b.get("source") != "in_kernel_serial"]
        by_kind: dict[str, dict] = {}
        for b in sorted(cands, key=lambda b: len(b["program"])):
            by_kind.setdefault(b["violation"]["kind"], b)
        todo = list(by_kind.values())[:args.minimize_max]
        print(f"\n=== PHASE 2: reduction ({len(todo)} representative "
              f"program(s), one per violation kind) ===")
        if not todo:
            print("  (nothing to reduce -- no program-attributed violations)")
        for b in todo:
            lines = b["program"]
            want = {b["violation"]["kind"]}
            print(f"\n[minimize] kind={sorted(want)[0]}: reducing "
                  f"{len(lines)} ops by replay ...")
            mini, mini_kinds = minimize_program(
                qemu, args.kernel, exec_bin, lines,
                args.smp, args.timeout, want, boundary=boundary_mode)
            print(f"[minimize] {len(lines)} -> {len(mini)} ops; "
                  f"replay-verified to still trigger {sorted(mini_kinds)}:")
            lost = want - set(mini_kinds)
            if lost:
                print(f"           NOTE: reduction did not preserve "
                      f"{sorted(lost)}; reported as unreduced.")
            for l in mini:
                print(f"    {l}")
            reductions.append({"kind": sorted(want)[0],
                               "bug_id": b["id"],
                               "ops_before": len(lines), "ops_after": len(mini),
                               "verified_kinds": sorted(mini_kinds),
                               "program": mini})
            if set(mini_kinds) >= want:
                b["reduced_program"] = mini
                b["reduced_verified_kinds"] = sorted(mini_kinds)
                b["program_full"] = b["program"]
                (out / f"{b['id']}.json").write_text(json.dumps(b, indent=2))
            else:
                b["reduction_incomplete"] = {
                    "attempted_ops": len(mini),
                    "lost_kinds": sorted(want - set(mini_kinds)),
                    "note": "reduction did not preserve the finding; the report "
                            "stays anchored at the full program"}
                (out / f"{b['id']}.json").write_text(json.dumps(b, indent=2))
        if reductions:
            (out / "reductions.json").write_text(json.dumps(reductions, indent=2))
            print(f"\n  reduced {len(reductions)} reproducer(s) -> {out}/reductions.json")

    (out / "fuzz_kernel_summary.json").write_text(json.dumps(
        {"seed": seed, "programs": n_exec, "coverage": len(coverage),
         "bugs": len(bugs), "by_theorem": by_thm,
         "oracle_applicability": applic,
         "per_op": step_counts,
         "reductions": reductions}, indent=2))
    print(f"\n  corpus + summary in {out}")


if __name__ == "__main__":
    main()

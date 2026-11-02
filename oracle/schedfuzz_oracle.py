"""schedfuzz_oracle.py -- the shared, target-independent oracle checker.
Shadow state sigma for O_CBS (bandwidth conservation), its per-op transition,
and the oracle that judges sigma against the observed ledger."""
from __future__ import annotations
import hashlib
from dataclasses import dataclass, field


# ---- shadow state sigma -------------------------------------------------
@dataclass
class Sigma:
    # A: deadline-admission ledger, slot -> reserved bandwidth (kernel units).
    A: dict = field(default_factory=dict)
    # D: slot -> root domain (0 = default, observed; c = partition of cpu c).
    D: dict = field(default_factory=dict)
    # unknown: slots whose reservation sigma cannot pin down.
    unknown: set = field(default_factory=set)
    # True once a background churner has started; nothing later is judged.
    churning: bool = False
    # Ledger value admitted_total() builds on; re-anchored after a perturber.
    baseline_bw: int = 0

    def admitted_total(self, domain: int = 0) -> int:
        """Expected value of the observed root domain's ledger."""
        return self.baseline_bw + sum(bw for i, bw in self.A.items()
                                      if self.D.get(i, 0) == domain
                                      and i not in self.unknown)


def to_ratio(period_ns: int, runtime_ns: int) -> int:
    """Kernel's to_ratio(): reserved bandwidth = (runtime << 20) / period."""
    if period_ns <= 0:
        return 0
    return (runtime_ns << 20) // period_ns


# ---- O_CBS : bandwidth conservation ------------------------------------
def oracle_cbs(sigma: Sigma, observed_total_bw: int, tol: int = 1000) -> dict | None:
    """Witness dict if the observed ledger disagrees with sigma, else None."""
    expected = sigma.admitted_total()
    delta = observed_total_bw - expected
    if abs(delta) > tol:
        return {
            "oracle": "O_CBS",
            "relation": "total_bw == sum_{t in sigma.A} bw(t)",
            "expected": expected,
            "observed": observed_total_bw,
            "delta": delta,
        }
    return None


# ---- sigma_step : the per-op shadow transition (A and D) ----------------
# Perturbers: ops that move the ledger in ways sigma does not model.
CBS_PERTURBERS = frozenset("HDPFYG")

# Background churners: sigma suspends for the rest of the program after these.
CBS_CONTINUOUS = frozenset("YG")

SCHED_FLAG_KEEP_POLICY = 0x08
SCHED_FLAG_KEEP_PARAMS = 0x10

# A/R/O ops carry runtime/deadline/period in microseconds.
_US_TO_NS = 1000


def sigma_step_cbs(sigma: Sigma, op_line: str, setattr_rc: int | None = None,
                   suspended: bool = False) -> tuple[Sigma, bool, str]:
    """Apply one op to sigma in place; returns (sigma, suspended, note)."""
    toks = op_line.split()
    if not toks:
        return sigma, suspended, ""
    op = toks[0][0]

    def _int(i, default=0):
        try:
            return int(toks[i])
        except (IndexError, ValueError):
            return default

    # H c 0 (cpu c offline): slots in cpu c's partition return to domain 0.
    if op == "H" and len(toks) >= 3 and toks[2] == "0":
        gone = _int(1, -1)
        for slot, dom in list(sigma.D.items()):
            if dom == gone:
                sigma.D[slot] = 0

    if op in CBS_CONTINUOUS:
        sigma.churning = True
        return sigma, True, (f"background churner {op}: it keeps perturbing after "
                             f"this op returns, so no single observation can "
                             f"re-anchor; sigma suspends for the rest of the program")
    if op in CBS_PERTURBERS:
        return sigma, True, (f"perturber {op}: one-shot, sigma re-anchors on the "
                             f"next observation and resumes")

    if op == "W":
        # W i: spawn a worker if slot i is empty; bandwidth-neutral.
        return sigma, suspended, ""

    if op == "A" and len(toks) >= 8:
        i, pol = _int(1, -1), _int(2, -1)
        rt, pd = _int(3), _int(5)
        try:
            fl = int(toks[7], 16)
        except ValueError:
            fl = 0
        if setattr_rc is None:
            sigma.unknown.add(i)
            return sigma, suspended, (f"setattr return code unknown -> slot {i} "
                                      f"cannot be modelled; it is excluded and the "
                                      f"rest of the program stays checked")
        if setattr_rc != 0:
            return sigma, suspended, "setattr failed -> spec charges nothing"
        sigma.unknown.discard(i)      # a known outcome restores the slot
        if fl & SCHED_FLAG_KEEP_POLICY:
            if not (fl & SCHED_FLAG_KEEP_PARAMS) and i in sigma.A:
                sigma.A[i] = to_ratio(pd * _US_TO_NS, rt * _US_TO_NS)
                return sigma, suspended, (f"KEEP_POLICY: DL slot {i} stays DL "
                                          f"with these parameters "
                                          f"bw={sigma.A[i]}")
            return sigma, suspended, ("KEEP_POLICY: policy intentionally "
                                      "unchanged -> no charge")
        if fl & SCHED_FLAG_KEEP_PARAMS:
            return sigma, suspended, ("KEEP_PARAMS: policy does not change "
                                      "-> spec charges nothing")
        if pol == 6:
            sigma.A[i] = to_ratio(pd * _US_TO_NS, rt * _US_TO_NS)
            return sigma, suspended, f"admit DL slot {i} bw={sigma.A[i]}"
        if i in sigma.A:
            sigma.A.pop(i)
            return sigma, suspended, (f"slot {i} left DL -> reservation must be "
                                      f"released")
        return sigma, suspended, ""

    if op in ("R", "O") and len(toks) >= 4:
        # R (DL + GRUB reclaim) and O (DL admit, then overrun) both end as DL.
        i, rt, pd = _int(1, -1), _int(2), _int(3)
        if setattr_rc is None:
            sigma.unknown.add(i)
            return sigma, suspended, (f"return code unknown -> slot {i} excluded; "
                                      f"the rest of the program stays checked")
        if setattr_rc != 0:
            return sigma, suspended, "setattr failed -> spec charges nothing"
        sigma.unknown.discard(i)
        sigma.A[i] = to_ratio(pd * _US_TO_NS, rt * _US_TO_NS)
        kind = "DL(reclaim)" if op == "R" else "DL"
        return sigma, suspended, f"admit {kind} slot {i} bw={sigma.A[i]}"

    if op == "E" and len(toks) >= 2:
        # E cycles the slot DL->OTHER and ends as OTHER: nothing is charged.
        i = _int(1, -1)
        if setattr_rc is None:
            sigma.unknown.add(i)
            return sigma, suspended, (f"E: final drop result unknown -> slot {i} "
                                      f"excluded; the rest stays checked")
        if setattr_rc != 0:
            return sigma, True, (f"E: final DL->OTHER drop failed -> slot {i} "
                                 f"may still be DL; sigma re-anchors on this "
                                 f"observation")
        sigma.unknown.discard(i)
        if i in sigma.A:
            sigma.A.pop(i)
            return sigma, suspended, (f"slot {i} left DL "
                                      f"-> reservation must be released")
        return sigma, suspended, ""

    if op in ("K", "T") and len(toks) >= 2:
        # K (kill) and T (FIFO task run and reaped) leave the slot empty.
        i = _int(1, -1)
        sigma.D.pop(i, None)
        if i in sigma.A:
            sigma.A.pop(i)
            why = {"K": "killed", "T": "emptied"}[op]
            return sigma, suspended, f"slot {i} {why} -> reservation must be released"
        return sigma, suspended, ""

    if op == "C" and len(toks) >= 3:
        # C i c: move slot i into the exclusive partition of cpu c.
        i, c = _int(1, -1), _int(2, 0)
        if setattr_rc is None:
            sigma.unknown.add(i)
            return sigma, suspended, (f"move result unknown -> slot {i} excluded")
        if setattr_rc != 0:
            return sigma, suspended, "move rejected -> the slot did not change domain"
        sigma.D[i] = c
        return sigma, suspended, (f"slot {i} moved to the partition of cpu {c} "
                                  f"-> leaves the observed root domain's ledger")

    if op == "U" and len(toks) >= 2:
        # U i: move slot i back to the root cgroup.
        i = _int(1, -1)
        if setattr_rc is None:
            sigma.unknown.add(i)
            return sigma, suspended, (f"move result unknown -> slot {i} excluded")
        if setattr_rc != 0:
            return sigma, suspended, "move rejected -> the slot did not change domain"
        sigma.D[i] = 0
        return sigma, suspended, (f"slot {i} moved back to the root domain "
                                  f"-> its reservation must reappear in the ledger")

    if op == "M" and len(toks) >= 2:
        # M i: move slot i into a cgroup of the root partition (like U).
        i = _int(1, -1)
        if setattr_rc is None:
            sigma.unknown.add(i)
            return sigma, suspended, (f"move result unknown -> slot {i} excluded")
        if setattr_rc != 0:
            return sigma, suspended, "move rejected -> the slot did not change domain"
        if sigma.D.get(i, 0) != 0:
            sigma.D[i] = 0
            return sigma, suspended, (f"slot {i} moved to a cgroup of the root "
                                      f"partition -> accounted against the "
                                      f"observed root domain again")
        return sigma, suspended, ""

    # X (futex-PI), S (sample), Z (settle) and any other op: bandwidth-neutral.
    return sigma, suspended, ""


def sigma_signature(sigma: "Sigma") -> str:
    """Execution signature: a hash of sigma's shape, not its exact values."""
    total = sum(bw for i, bw in sigma.A.items() if i not in sigma.unknown)
    bucket = total.bit_length()          # coarse: 2^k band, not the exact value
    parts = (tuple(sorted(sigma.A.keys())),
             tuple(sorted(sigma.D.items())),
             tuple(sorted(sigma.unknown)),
             bool(sigma.churning),
             bucket)
    return hashlib.sha1(repr(parts).encode()).hexdigest()[:12]


def witness_signature(kind: str, op: str, sigma_sig: str | None,
                      step: int | None = None,
                      fallback_ctx: str = "") -> str:
    """A finding's identity: hash of (kind, op, sigma signature at its step)."""
    if sigma_sig:
        key = f"{kind}|{op}|{sigma_sig}"
    else:
        key = f"{kind}|{step}|{op}|{fallback_ctx}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def classify_persistence(violations: list[dict], residuals: dict[int, int],
                         tol: int = 1000) -> list[dict]:
    """Tag each per-op disagreement confirmed / transient / unconfirmed."""
    for v in violations:
        k = v.get("step")
        later = [r for kk, r in sorted(residuals.items())
                 if k is not None and kk > k]
        same_sign = [r for r in later
                     if abs(r) > tol and (r > 0) == (v.get("delta", 0) > 0)]
        if not later:
            v["status"] = "unconfirmed_last_step"
        elif v.get("delta", 0) > 0:
            # A positive residual must survive to the last evaluated step.
            v["status"] = ("confirmed" if abs(later[-1]) > tol
                           and later[-1] > 0 else "drained_after_release")
        elif same_sign:
            v["status"] = "confirmed"
        else:
            v["status"] = "transient_async_lag"
    return violations


def oracle_cbs_stepwise(steps: list[dict], tol: int = 1000) -> dict:
    """Evaluate O_CBS after every operation and classify the disagreements."""
    res = {"checked": 0, "suspended": 0, "anchored": 0,
           "violations": [], "residuals": {}}
    prev_resid = 0
    for s in steps:
        if s.get("expected") is None:
            res["suspended"] += 1
            continue
        res["checked"] += 1
        if s.get("anchored"):
            res["anchored"] += 1
        sigma = Sigma(baseline_bw=s["expected"])       # expected already absolute
        v = oracle_cbs(sigma, observed_total_bw=s["observed"], tol=tol)
        resid = s["observed"] - s["expected"]
        res["residuals"][s["step"]] = resid
        change = resid - prev_resid
        # only the step that moved the residual is charged with it
        if v and abs(change) <= tol:
            v = None
        prev_resid = resid
        if v:
            adm = s.get("admitted", 0)
            v.update({"residual_change": change,
                      "sigma_sig": s.get("sigma_sig"),
                      "step": s["step"], "op": s.get("op", ""),
                      "note": s.get("note", ""), "admitted": adm,
                      "anchored": bool(s.get("anchored")),
                      # class follows the change, not the level v["delta"]
                      "class": ("leak" if change > 0
                                else "over_release" if adm > 0
                                else "baseline_drift")})
            res["violations"].append(v)
    classify_persistence(res["violations"], res["residuals"], tol)
    return res

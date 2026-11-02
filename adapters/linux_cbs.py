"""linux_cbs.py -- the Linux SCHED_DEADLINE adapter for the O_CBS oracle.

Parses the guest's trace and checks its sigma against a host re-derivation."""
from __future__ import annotations
import re, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "oracle"))
from schedfuzz_oracle import (Sigma, oracle_cbs_stepwise,  # noqa: E402
                              sigma_signature,
                              sigma_step_cbs)


def read_omega_steps(serial: str) -> dict:
    """Project the guest's per-op records into the oracle's observation Omega."""
    out = {"base": None, "steps": [], "sigma": [], "summary": None,
           "setattr": [], "skipped": {}}
    for m in re.finditer(r"^##OP_SKIPPED op=(\S) cpu=(-?\d+) step=(\d+)"
                         r"(?: reason=(\S+))?", serial, re.M):
        out["skipped"][int(m.group(3))] = m.group(4) or ""
    m = re.search(r"^base_bw=(-?\d+)", serial, re.M)
    if m:
        out["base"] = int(m.group(1))
    for m in re.finditer(r"^STEP i=(\d+) op=(.) bw=(-?\d+)", serial, re.M):
        out["steps"].append({"i": int(m.group(1)), "op": m.group(2),
                             "bw": int(m.group(3))})
    for m in re.finditer(r"^SIGMA i=(\d+) op=(.) state=checked "
                         r"expected=(-?\d+) observed=(-?\d+) delta=(-?\d+)"
                         r"(?: anchored=1)?", serial, re.M):
        out["sigma"].append({"i": int(m.group(1)), "op": m.group(2),
                             "state": "checked", "expected": int(m.group(3)),
                             "observed": int(m.group(4)), "delta": int(m.group(5))})
    # an anchor step is never judged: the guest's equivalent of suspended
    for m in re.finditer(r"^SIGMA i=(\d+) op=(.) state=(?:suspended|anchor) "
                         r"observed=(-?\d+)", serial, re.M):
        out["sigma"].append({"i": int(m.group(1)), "op": m.group(2),
                             "state": "suspended", "expected": None,
                             "observed": int(m.group(3)), "delta": None})
    out["sigma"].sort(key=lambda s: s["i"])
    m = re.search(r"^SIGMA_SUMMARY prog=\d+ steps=(\d+) checked=(\d+) "
                  r"suspended=(\d+) out_of_spec=(\d+)", serial, re.M)
    if m:
        out["summary"] = {"steps": int(m.group(1)), "checked": int(m.group(2)),
                          "suspended": int(m.group(3)),
                          "out_of_spec": int(m.group(4))}
    # A (A/R/O/E) and MOVE (C/U/M) return codes, bound to their op by step=
    for m in re.finditer(r"^MOVE id=(\d+) cpu=(\d+) rc=(-?\d+) step=(\d+)",
                         serial, re.M):
        out["setattr"].append({"id": int(m.group(1)), "rc": int(m.group(3)),
                               "step": int(m.group(4))})
    for m in re.finditer(r"^A id=(\d+) rc=(-?\d+) errno=\d+ step=(\d+)",
                         serial, re.M):
        out["setattr"].append({"id": int(m.group(1)), "rc": int(m.group(2)),
                               "step": int(m.group(3))})
    return out


def host_sigma_trace(ops: list[str], setattrs: list[dict], base: int,
                     observed: list[int] | None = None,
                     skipped: dict | None = None) -> list[dict]:
    """Re-derive sigma on the host via the shared oracle, one entry per op."""
    sigma = Sigma(baseline_bw=base)
    suspended = False
    by_step = {s["step"]: s for s in setattrs}
    trace: list[dict] = []
    anchored = False
    skipped = skipped or {}
    for k, op_line in enumerate(ops):
        op = op_line[:1]
        if k in skipped:
            why = (skipped.get(k) if isinstance(skipped, dict) else "") or ""
            trace.append({"op": op_line,
                          "note": "op skipped by the guest"
                                  + (f" ({why.replace('_', ' ')})" if why else ""),
                          "admitted": sum(bw for i, bw in sigma.A.items()
                                          if i not in sigma.unknown),
                          "anchored": anchored,
                          "expected": None if sigma.churning else sigma.admitted_total(),
                          "sigma_sig": sigma_signature(sigma)})
            continue
        rc = None
        executed = True
        if op in ("A", "R", "O", "E", "C", "U", "M"):
            rec = by_step.get(k)
            if rec is None:
                executed = False
            else:
                rc = rec["rc"]
        if executed:
            sigma, suspended, note = sigma_step_cbs(sigma, op_line, rc, False)
        else:
            note = "op did not execute (no record) -> spec charges nothing"
            suspended = False
        entry = {"op": op_line, "note": note,
                 "admitted": sum(bw for i, bw in sigma.A.items()
                                 if i not in sigma.unknown),
                 "anchored": anchored, "expected": None}
        if sigma.churning:
            # a background churner is running: nothing after it is judged
            entry["expected"] = None
        elif suspended:
            # one-shot perturber: this step is the anchor and is not judged
            if observed is not None and k < len(observed):
                sigma.baseline_bw = observed[k] - sum(
                    bw for i, bw in sigma.A.items()
                    if sigma.D.get(i, 0) == 0 and i not in sigma.unknown)
                anchored = True
                entry["note"] = (note + " | baseline re-anchored on this "
                                 "observation; later verdicts cannot report a "
                                 "break that happened here")
        else:
            entry["expected"] = sigma.admitted_total()
        entry["sigma_sig"] = sigma_signature(sigma)
        trace.append(entry)
    return trace


def cross_check_sigma(guest: list[dict], host: list[dict], steps: list[dict],
                      tol: int = 1000) -> dict:
    """Compare guest and host sigma per step; `absent` if no SIGMA records."""
    x = {"compared": 0, "agree": 0, "disagree": [], "state_disagree": [],
         "absent": not guest}
    if not guest:
        return x
    by_i = {g["i"]: g for g in guest}
    for k, st in enumerate(steps):
        g = by_i.get(st["i"])
        if g is None or k >= len(host):
            continue
        host_ok = host[k]["expected"] is not None
        guest_ok = g["state"] == "checked"
        if host_ok != guest_ok:
            x["state_disagree"].append({
                "step": st["i"], "op": host[k]["op"],
                "host": "checked" if host_ok else "suspended",
                "guest": g["state"]})
            continue
        if not guest_ok:
            continue
        x["compared"] += 1
        if abs((st["bw"] - host[k]["expected"]) - g["delta"]) <= tol:
            x["agree"] += 1
        else:
            x["disagree"].append({
                "step": st["i"], "op": host[k]["op"],
                "host_residual": st["bw"] - host[k]["expected"],
                "guest_delta": g["delta"]})
    return x


def check_stepwise(serial: str, ops: list[str], tol: int = 1000) -> dict:
    """The per-op O_CBS check: one sigma transition and one verdict per op."""
    om = read_omega_steps(serial)
    # a negative base_bw is the guest's -1 sentinel for an unreadable ledger
    if om["base"] is None or om["base"] < 0 or not om["steps"]:
        return {"error": "no baseline or no per-op samples -- NOT CHECKED",
                "checked": 0, "suspended": 0, "violations": [],
                "xcheck": {"absent": True}, "guest_summary": om["summary"]}
    host = host_sigma_trace(ops, om["setattr"], om["base"],
                            observed=[st["bw"] for st in om["steps"]],
                            skipped=om.get("skipped"))
    ev = []
    for k, st in enumerate(om["steps"]):
        if k >= len(host):
            break
        ev.append({"step": st["i"], "op": host[k]["op"], "note": host[k]["note"],
                   "expected": host[k]["expected"], "observed": st["bw"],
                   "admitted": host[k]["admitted"],
                   "anchored": host[k].get("anchored", False),
                   "sigma_sig": host[k].get("sigma_sig")})
    res = oracle_cbs_stepwise(ev, tol=tol)
    res["xcheck"] = cross_check_sigma(om["sigma"], host, om["steps"], tol)
    res["guest_summary"] = om["summary"]
    # hash of selected sigma fields, for deduplicating executions (not findings)
    res["sigma_sig"] = host[-1].get("sigma_sig") if host else None
    return res


def check_boundary(serial: str, tol: int = 1000) -> dict:
    """Boundary form of O_CBS: one verdict per program, at the sequence end."""
    mf = re.search(r"^final_bw=(-?\d+)", serial, re.M)
    me = re.search(r"^final_expected=(-?\d+) final_admitted=(-?\d+)", serial, re.M)
    mb = re.search(r"^base_bw=(-?\d+)", serial, re.M)
    if mf is None:
        return {"checked": 0, "fired": False, "residual": None,
                "reason": "no_final_bw",
                "why": "no final_bw record -- the program did not finish"}
    if mb is not None and int(mb.group(1)) < 0:
        return {"checked": 0, "fired": False, "residual": None,
                "reason": "no_baseline",
                "why": "no baseline -- base_bw is negative (-1 is the guest's "
                       "value for a ledger it could not read)"}
    if me is None:
        return {"checked": 0, "fired": False, "residual": None,
                "reason": "no_boundary_prediction",
                "why": "no final_expected record -- sigma has no boundary prediction"}
    admitted = int(me.group(2))
    if admitted:
        return {"checked": 0, "fired": False, "residual": None,
                "reason": "boundary_not_evaluable",
                "why": f"not evaluable: sigma still holds {admitted} admitted at "
                       f"the boundary, which the teardown is releasing as the "
                       f"sample is taken"}
    resid = int(mf.group(1)) - int(me.group(1))
    return {"checked": 1, "fired": abs(resid) > tol, "residual": resid,
            "expected": int(me.group(1)), "observed": int(mf.group(1)), "why": "",
            "reason": ""}

#!/bin/bash
# run_fuzzer.sh -- run the Linux SCHED_DEADLINE fuzzer.
# Usage:  KDIR=/path/to/bzImages  SEED=21  ./linux/run_fuzzer.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR="${KDIR:-$HERE/kernel}"
FUZZ="$HERE/fuzzer/fuzz_kernel.py"
seed="${SEED:-21}"

# Track what actually executed; exit 2 (= SKIP) if neither build is present.
stages_run=0
stages_failed=0
stages_empty=0

produced_anything() {
    grep -q "CRASH-SIG-IN-SERIAL" "$1" && return 0
    grep -qE "distinct triggers  : [1-9]" "$1" && return 0
    grep -q "NEVER evaluated" "$1" && return 1
    return 0
}

ledger_evaluated() {   # $1 = log -> 0 if O_CBS judged >=1 program
    grep -qE "^ *ledger: checked=0/" "$1" && return 1
    grep -q "NEVER evaluated" "$1" && return 1
    grep -qE "^ *ledger: checked=[1-9]" "$1" && return 0
    return 1
}

outdir="${CORPUS:-${TMPDIR:-/tmp}/schedfuzz_corpus}/runner-logs"
mkdir -p "$outdir"
out1="$outdir/noprove_smp2.log"; out2="$outdir/lockdep_smp4.log"

# fuzzer output lines kept in this transcript
KEEP='round |REL_[A-Z_]+[]:]|TOOL_SELF_CHECK|KERNEL:|cov=|applicability|checked=|per-op|cross-check|NEVER evaluated|says NOTHING|MODELS disagree'
# a REL_/KERNEL: summary line, as fuzz_kernel.py prints it
VIOL='^    (REL_[A-Z_]+|KERNEL:[A-Za-z0-9_]+): [0-9]+$'
viol_seen=0

CORPUS="${CORPUS:-${TMPDIR:-/tmp}/schedfuzz_corpus}"

echo "=== Linux fuzzer -- per-op stage (O_CBS) on the noprove build (PROVE_LOCKING off) ==="
if [ -f "$KDIR/bzImage.noprove" ]; then
  rc=0
  # --exclude-ops: no perturbers in this stage (PERTURBERS in fuzz_kernel.py)
  python3 "$FUZZ" --kernel "$KDIR/bzImage.noprove" --smp 2 --rounds 3 --batch 30 --seed "$seed" \
      --oracle-granularity perop --resume --exclude-ops H,D,P,F,Y,G --timeout 120 \
      --out "$CORPUS/noprove_smp2_seed$seed" > "$out1" 2>&1 || rc=$?
  grep -E "$KEEP" "$out1" | tail -30
  [ "$rc" -eq 0 ] && grep -E "$KEEP" "$out1" | tail -30 | grep -qE "$VIOL" && viol_seen=1
  if [ "$rc" -ne 0 ]; then
    echo "  !! the fuzzer FAILED (rc=$rc) -- this stage tested NOTHING."
    echo "     Full output: $out1"
    stages_failed=$((stages_failed+1))
  elif ! ledger_evaluated "$out1"; then
    echo "  !! O_CBS was evaluated on 0 programs (checked=0) -- this stage"
    echo "     established NOTHING; counted as NOT run. Full output: $out1"
    stages_empty=$((stages_empty+1))
  else
    stages_run=$((stages_run+1))
  fi
else
  echo "  SKIP: $KDIR/bzImage.noprove not found -- build it first (see README.md)"
fi

echo
echo "=== Linux fuzzer -- full-alphabet stage on the lockdep build ==="
if [ -f "$KDIR/bzImage.lockdep" ]; then
  rc=0
  python3 "$FUZZ" --kernel "$KDIR/bzImage.lockdep" --smp 4 --rounds 3 --batch 12 --seed "$seed" \
      --out "$CORPUS/lockdep_smp4_seed$seed" > "$out2" 2>&1 || rc=$?
  grep -E "$KEEP" "$out2" | tail -24
  [ "$rc" -eq 0 ] && grep -E "$KEEP" "$out2" | tail -24 | grep -qE "$VIOL" && viol_seen=1
  if [ "$rc" -ne 0 ]; then
    echo "  !! the fuzzer FAILED (rc=$rc) -- this stage tested NOTHING."
    echo "     Full output: $out2"
    stages_failed=$((stages_failed+1))
  elif ! produced_anything "$out2"; then
    echo "  !! this stage evaluated NO relation and found NO crash"
    echo "     -- counted as NOT run. Full output: $out2"
    stages_empty=$((stages_empty+1))
  else
    stages_run=$((stages_run+1))
  fi
else
  echo "  SKIP: $KDIR/bzImage.lockdep not found -- build it first (see README.md)"
fi

echo
if [ "$stages_empty" -gt 0 ] && [ "$stages_run" -eq 0 ]; then
  echo "[linux] every stage that ran evaluated NOTHING -- exiting non-zero."
  echo "        The absence of violations above says NOTHING about the kernel."
  exit 1
fi
if [ "$stages_failed" -gt 0 ]; then
  echo "[linux] $stages_failed stage(s) FAILED outright -- exiting non-zero so"
  echo "        run_all.sh cannot record this as a successful target."
  exit 1
fi
if [ "$stages_run" -eq 0 ]; then
  echo "[linux] SKIP: no kernel image under KDIR=$KDIR -- nothing was tested."
  echo "        The absence of violations above says NOTHING about the kernel."
  exit 2
fi
if [ "$viol_seen" -eq 1 ]; then
  echo "The count on each REL_ or KERNEL: line above is the number of distinct"
  echo "triggers its stage recorded for that relation or crash kind (witness or"
  echo "crash-line keys, not distinct bugs)."
else
  echo "No violation observed in this run."
fi
echo "($stages_run of 2 stages ran; see the 'oracle applicability' lines for"
echo " how many programs each relation was actually evaluated on.)"

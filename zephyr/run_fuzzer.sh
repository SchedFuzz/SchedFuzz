#!/bin/bash
# Build and run the Zephyr scheduler fuzzer (qemu_cortex_m3, EDF config).
# Usage: ZEPHYR_BASE=<zephyr v4.2.0> [SCHEDFUZZ_ITERS=N] ./zephyr/run_fuzzer.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
APP="$HERE"
ZBASE="${ZEPHYR_BASE:-/tmp/zephyrproject/zephyr}"
if [ ! -d "$ZBASE" ]; then
  echo "[zephyr] SKIP: set ZEPHYR_BASE to a Zephyr v4.2.0 checkout (have: $ZBASE)"; exit 2; fi
# SCHEDFUZZ_BOARD=native_sim/native/64 for a fast host build.
SF_BOARD="${SCHEDFUZZ_BOARD:-qemu_cortex_m3}"
case "$SF_BOARD" in
  native_sim*) export ZEPHYR_TOOLCHAIN_VARIANT=host ;;
  *) : "${ZEPHYR_TOOLCHAIN_VARIANT:=cross-compile}"
     : "${CROSS_COMPILE:=/usr/bin/arm-none-eabi-}"
     export ZEPHYR_TOOLCHAIN_VARIANT CROSS_COMPILE ;;
esac
export ZEPHYR_BASE="$ZBASE"
SF_BDIR="${SCHEDFUZZ_BUILD_DIR:-$APP}"
mkdir -p "$SF_BDIR"

# sf_run BDIR CAP_S OUT DONE_MARK [MID_MARK]: run until DONE_MARK or the cap.
# Sets SF_RUN_END (marker|cap), SF_RUN_SECS, SF_MID_SECS (first MID_MARK).
sf_run() {
  local bdir="$1" cap="$2" out="$3" done_mark="$4" mid_mark="${5:-}"
  local t0 pid
  t0=$(date +%s.%N)
  SF_RUN_END=cap; SF_MID_SECS=""
  if [ -x "$bdir/zephyr/zephyr.exe" ]; then
    timeout -k 5 "$cap" "$bdir/zephyr/zephyr.exe" > "$out" 2>&1 &
  else
    timeout -k 5 "$cap" qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb \
        -nographic -vga none -kernel "$bdir/zephyr/zephyr.elf" > "$out" 2>&1 &
  fi
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ -n "$mid_mark" ] && [ -z "$SF_MID_SECS" ] && grep -aqF -- "$mid_mark" "$out"; then
      SF_MID_SECS=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')
    fi
    if grep -aqF -- "$done_mark" "$out"; then
      SF_RUN_END=marker
      sleep 1
      kill -TERM "$pid" 2>/dev/null
      for _ in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
      pkill -KILL -P "$pid" 2>/dev/null; kill -KILL "$pid" 2>/dev/null
      break
    fi
    sleep 1
  done
  wait "$pid" 2>/dev/null
  SF_RUN_SECS=$(awk -v a="$t0" -v b="$(date +%s.%N)" 'BEGIN{printf "%.1f", b-a}')
  # The UART console emits CRLF; strip the CR so line-anchored greps work.
  sed -i 's/\r$//' "$out"
}
# Campaign budget; the app's built-in 50 iterations is only a smoke run.
SF_DEFAULT_ITERS=4000
SF_ITERS="${SCHEDFUZZ_ITERS:-$SF_DEFAULT_ITERS}"

# Always pass -DSF_PEROP_CHECK (0 or 1): a -D value persists in the CMake cache.
if [ "${SCHEDFUZZ_PEROP:-}" = 1 ]; then SF_PEROP=1; else SF_PEROP=0; fi

# Wall-clock cap in seconds; the run normally ends at the completion marker.
if [ "$SF_PEROP" = 1 ]; then
  SF_TMO=$(( SF_ITERS + 180 ))
else
  SF_TMO=$(( SF_ITERS / 2 + 180 ))
fi
echo "[zephyr] budget: $SF_ITERS iterations, ${SF_TMO}s cap (SCHEDFUZZ_ITERS to change)"
[ "$SF_PEROP" = 1 ] && echo "[zephyr] SCHEDFUZZ_PEROP=1: oracle check after every op (SF_PEROP_CHECK=1); its counts are raw per-op counts"

# Outside a west workspace, find the CMSIS HAL that Cortex-M boards need.
SF_MODULES="${ZEPHYR_MODULES:-}"
if [ -z "$SF_MODULES" ] && [ ! -f "$ZBASE/../.west/config" ]; then
  for _c in "$ZBASE/../modules/hal" "${ZBASE}-modules/hal"; do
    if [ -d "$_c/cmsis" ]; then
      SF_MODULES="$_c/cmsis"
      [ -d "$_c/cmsis_6" ] && SF_MODULES="$SF_MODULES;$_c/cmsis_6"
      break
    fi
  done
fi
[ -n "$SF_MODULES" ] && echo "[zephyr] ZEPHYR_MODULES=$SF_MODULES"
sf_cmsis_hint() {
  if grep -aq 'HAS_CMSIS_CORE' "$1" 2>/dev/null; then
    echo "[zephyr] hint: the CMSIS HAL was not found; set ZEPHYR_MODULES=\"<hal>/cmsis;<hal>/cmsis_6\" (e.g. <west-workspace>/modules/hal/cmsis and .../modules/hal/cmsis_6) and re-run."
  fi
}
_cmlog="$(mktemp)"
( cmake -S "$APP" -B "$SF_BDIR/build_fuzz" -GNinja -DBOARD="$SF_BOARD" \
       ${SF_MODULES:+-DZEPHYR_MODULES="$SF_MODULES"} -DSF_N_ITERS="$SF_ITERS" \
       -DSF_PEROP_CHECK="$SF_PEROP" \
  && ninja -C "$SF_BDIR/build_fuzz" ) > "$_cmlog" 2>&1 || {
    echo "[zephyr] build failed; last 20 lines of the build log:"
    tail -20 "$_cmlog" | sed 's/^/    /'
    echo "    (full log kept at $_cmlog)"
    sf_cmsis_hint "$_cmlog"
    exit 1; }
rm -f "$_cmlog"

zout="$(mktemp)"
sf_run "$SF_BDIR/build_fuzz" "$SF_TMO" "$zout" '=== fuzzer complete ===' \
       '--- PHASE 1 (testing) complete ---'

# Totals are phase 1 only: the PHASE-2 replays follow the phase-1 marker.
p1="$(mktemp)"
awk '/--- PHASE 1 \(testing\) complete ---/{exit} {print}' "$zout" > "$p1"
p1_done=0; grep -aqF -- '--- PHASE 1 (testing) complete ---' "$zout" && p1_done=1
agg_done=0; grep -aqF -- '=== aggregate:' "$zout" && agg_done=1

echo "--- Zephyr fuzzer: first O_WQ witnesses (WAITQ_STALE, with their iteration line) ---"
awk '/^  it=[0-9]+ seed=/{itl=$0; show=0; next}
     /\[WAITQ_STALE\]/{ if (++n > 3) exit; print "  " itl; print "  " $0; show=1; next }
     show && /^      m[0-9]+ queue:/{ print "  " $0; next }
     { show=0 }' "$p1"
grep -aq '\[WAITQ_STALE\]' "$p1" || echo "    (none in phase 1)"

# Phase-1 iteration lines: "  it=N seed=0x.. steps=K".
n_iter=$(grep -acE '^  it=[0-9]+ seed=' "$p1" || true)
: "${n_iter:=0}"
n_steps=$(grep -aoE '^  it=[0-9]+ seed=0x[0-9a-f]+ steps=[0-9]+' "$p1" \
          | awk -F'steps=' '{s+=$2} END{print s+0}')
# Numerator: sum of the "[WAITQ_STALE] new=N" witness counts.
n_stale=$(grep -aoE '\[WAITQ_STALE\] new=[0-9]+' "$p1" | awk -F'new=' '{s+=$2} END{print s+0}')
n_stale_it=$(grep -ac '\[WAITQ_STALE\]' "$p1" || true)
# Denominator: wqp= is cumulative, so its last phase-1 value is the total.
n_pairs=$(grep -aoE 'wqp=[0-9]+' "$p1" | tail -1 | cut -d= -f2)
: "${n_pairs:=0}"
_last() { grep -aoE "$1=[0-9]+" "$p1" | tail -1 | cut -d= -f2; }
n_setdiv=$(_last wqSETDIV); n_unres=$(_last wqUNRES); n_ovf=$(_last wqOVF)
first_wq_it=$(awk '/^  it=[0-9]+ seed=/{split($1,a,"="); it=a[2]} /\[WAITQ_STALE\]/{print it; exit}' "$p1")
# SIGMA_* are self-check counts and are never summed into the violation count.
n_sigma=$(grep -ac '\[SIGMA_' "$p1" || true)
n_disc=$(grep -ac '\[OBS_DISCARDED\]' "$p1" || true)
# "[FAULT] reason=" can land mid-line; count every occurrence.
n_fault=$(awk '{ n += gsub(/\[FAULT\] reason=/, "") } END { print n + 0 }' "$p1")

echo "--- Zephyr fuzzer: phase-1 totals ---"
if [ "$SF_RUN_END" = marker ]; then
  echo "    run: app finished; qemu stopped at its completion marker after ${SF_RUN_SECS}s host wall time"
else
  echo "    run: STOPPED BY THE ${SF_TMO}s CAP after ${SF_RUN_SECS}s -- the app did not finish"
fi
echo "    iterations completed: $n_iter of $SF_ITERS"
if [ "$n_pairs" -gt 0 ]; then
  _pct=$(awk -v a="$n_stale" -v b="$n_pairs" 'BEGIN{printf "%.1f%%", 100*a/b}')
else
  _pct="n/a"
fi
echo "    O_WQ: WAITQ_STALE=$n_stale over $n_pairs judged wait-queue pairs ($_pct), in $n_stale_it iteration(s)"
echo "      (numerator and denominator both phase 1; a queue with <2 waiters offers no pair)"
echo "    first WAITQ_STALE at: ${first_wq_it:+it=}${first_wq_it:-none}"
echo "    mutex queues NOT judged: set divergence=${n_setdiv:-0} unresolved waiter=${n_unres:-0} snapshot overflow=${n_ovf:-0}"
echo "    observations DISCARDED by the structural self-check: $n_disc  (O_WQ not evaluated on those)"
echo "    sigma self-check divergences, NOT findings: SIGMA_*=$n_sigma"
echo "    kernel faults: $n_fault"
_p1_secs="${SF_MID_SECS:-$SF_RUN_SECS}"
_ops=$(awk -v a="$n_steps" -v b="$_p1_secs" 'BEGIN{ if (b>0) printf "%.2f", a/b; else print "n/a"}')
echo "    throughput: $n_steps steps / ${_p1_secs}s = $_ops ops/s"
echo "      (host wall time from qemu launch to the end of phase 1, or to the cap: includes qemu"
echo "       boot, the time-slice baseline probe and each iteration's settle sleeps)"

echo "--- Zephyr end-of-run controls (app aggregate block) ---"
if [ "$agg_done" -eq 1 ]; then
  grep -aE '^  \[ts\] a=' "$zout" | awk 'NR==1{l="baseline"} NR==2{l="end    "} NR==3{l="noslots"} {sub(/^  /,""); print "    " l " " $0}'
  grep -aE '^  \[edf\] rounds=' "$zout" | sed 's/^  /    /'
  # The TIMESLICE line plus its one or two indented continuation lines.
  awk '/^  TIMESLICE  :/{p=1; print; next} p && /^               [^ ]/{print; next} {p=0}' \
      "$zout" | sed 's/^  /    /'
  grep -aE '^  EDF_ORDER  :' "$zout" | sed 's/^  /    /'
  grep -aE -A1 '^  WAITQ_STALE:' "$zout" | sed 's/^  /    /'
  grep -aE '^  obs discarded by self-check:' "$zout" | sed 's/^  /    /'
  echo "    (the aggregate WAITQ_STALE / pairs / discards above include the PHASE-2"
  echo "     replays; the phase-1 figures are the ones printed before)"
else
  echo "    WARNING: the aggregate block was NOT reached -- the TIMESLICE and EDF_ORDER"
  echo "             controls did not run, and only the phase-1 totals above exist."
  [ "$p1_done" -eq 0 ] && echo "             Phase 1 itself did not complete ($n_iter of $SF_ITERS iterations)."
fi

if [ "$SF_ITERS" -lt "$SF_DEFAULT_ITERS" ]; then
  echo "    NOTE: SCHEDFUZZ_ITERS=$SF_ITERS is below the default budget of $SF_DEFAULT_ITERS iterations;"
  echo "          fewer wait-queue pairs are judged at smaller budgets."
fi
if [ "$n_pairs" -eq 0 ] && [ "$n_iter" -gt 0 ]; then
  echo "    WARNING: ZERO wait-queue pairs were judged, so WAITQ_STALE=$n_stale says"
  echo "             NOTHING about wait-queue ordering in this run -- the relation"
  echo "             was never evaluable, which is not the same as satisfied."
fi
zrc=0
if [ "$n_iter" -eq 0 ]; then
  echo "    WARNING: ZERO iterations completed -- nothing was tested. The totals"
  echo "             above say NOTHING about this kernel; check the build."
  zrc=1
fi
if [ "$n_stale" -eq 0 ]; then
  echo "    NOTE: no O_WQ violation in this run -- report as 'none observed',"
  echo "          and check the build actually produced oracle output."
fi
rm -f "$zout" "$p1"
exit "$zrc"

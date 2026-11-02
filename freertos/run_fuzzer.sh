#!/bin/bash
# Run the FreeRTOS scheduler fuzzer (POSIX port); O_WQ is judged in its dequeue
# form in posix_fuzz/fuzz_opseq.c.
# Usage: FREERTOS_KERNEL=<FreeRTOS-Kernel checkout> ./freertos/run_fuzzer.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
FQ="$HERE/posix_fuzz"
export KERNEL="${FREERTOS_KERNEL:-/tmp/FreeRTOS-Kernel}"
if [ ! -d "$KERNEL" ]; then
  echo "[freertos] SKIP: set FREERTOS_KERNEL to a FreeRTOS-Kernel checkout (have: $KERNEL)"; exit 2; fi

blog="$(mktemp)"
if ! ( cd "$FQ" && make fuzz_opseq ) >"$blog" 2>&1; then
    echo "[freertos] build failed -- last lines of the build log:"
    tail -n 20 "$blog" | sed 's/^/    /'
    rm -f "$blog"
    exit 1
fi
rm -f "$blog"

# ---- op-sequence fuzzer against the shared C oracle ------------------------
echo "--- FreeRTOS op-sequence fuzzer (shared C oracle via core/) ---"
done_opseq=0
phase3=0
san=0
orc=0
oout="$(mktemp)"
timeout -k 5 300 "$FQ/fuzz_opseq" > "$oout" 2>&1 || orc=$?
grep -aq 'PHASE 1 (testing) complete' "$oout"      && done_opseq=1
grep -aq '=== PHASE 3 (control) complete ===' "$oout" && phase3=1

if [ "$done_opseq" -eq 1 ]; then
    sed -n '/=== op-sequence campaign done/,/=== PHASE 3 (control) complete ===/p' "$oout" | sed 's/^/    /'
    if [ "$phase3" -eq 0 ]; then
        echo "    !! PHASE 1 finished but PHASE 2/3 did NOT complete -- the control above is PARTIAL"
    fi
else
    echo "    !! the op-sequence run did NOT complete -- counts below are PARTIAL"
    grep -aE 'iterations|sigma divergences|invariant hits' "$oout" | sed 's/^/    /'
fi
# The default build carries no sanitizer; for a sanitizer run, build with
# `make SANITIZE=1` and run with ASAN_OPTIONS=use_sigaltstack=0.
if grep -aqE 'ERROR: AddressSanitizer|runtime error:' "$oout"; then
  san=1
  echo "  !! SANITIZER ERROR in the op-sequence run (investigate):"
  grep -aE 'ERROR: AddressSanitizer|runtime error:' "$oout" | head -3 | sed 's/^/     /'
fi

# Violation count reported by the negative control (must be 0).
neg="$(grep -a 'O_WQ dequeue violations:.*expected 0)' "$oout" | sed -E 's/.*violations:[[:space:]]*([0-9]+).*/\1/' | head -1)"

fail=0
if [ "$phase3" -eq 0 ]; then
    echo "!! PHASE 3 (control) was not reached. Nothing above is a complete result."
    fail=1
fi
if [ "${neg:-}" != "0" ]; then
    echo "!! negative control reported '${neg:-<none>}' violations (must be 0) -- the oracle"
    echo "   fired on a correctly ordered wait list, or the control did not run."
    fail=1
fi
if [ "$san" -eq 1 ] || [ "$fail" -ne 0 ] || [ "$orc" -ne 0 ]; then
    echo "   raw output of the op-sequence run kept at $oout (exit status $orc of the timed run; 124 or 137: stopped at the 300 s cap)"
else
    rm -f "$oout"
fi
if [ "$fail" -ne 0 ]; then
    echo "   Exiting 1."
    exit 1
fi
echo "[freertos] PHASE 3 reached; negative control $neg violations."
exit 0

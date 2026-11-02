#!/bin/bash
# run_all.sh -- run the SchedFuzz fuzzer on Linux (O_CBS), Zephyr (O_WQ direct)
# and FreeRTOS (O_WQ dequeue).
# Usage: KDIR=<bzImage dir> ZEPHYR_BASE=<dir> FREERTOS_KERNEL=<dir> ./run_all.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"

ran=0; skipped=0; failed=0
declare -a STATUS
RAN_LABELS=""
# Each runner's stdout is also kept for saw(); stderr passes through unchanged.
LOGS="$(mktemp -d)"
trap 'rm -rf "$LOGS"' EXIT

run_target() {   # run_target <label> <script...>
    local label="$1"; shift
    local rc
    "$@" | tee "$LOGS/$label.log"
    rc=${PIPESTATUS[0]}          # the runner's status, not tee's
    case "$rc" in
        0) ran=$((ran+1));     STATUS+=("$label: ran"); RAN_LABELS="$RAN_LABELS $label" ;;
        2) skipped=$((skipped+1)); STATUS+=("$label: SKIPPED (prerequisite missing)") ;;
        *) failed=$((failed+1));   STATUS+=("$label: FAILED (rc=$rc)") ;;
    esac
}

saw() {   # saw campaign|probe -> 0 if a target that ran printed such a line
    local kind="$1" l pat
    for l in $RAN_LABELS; do
        case "$kind:$l" in
            campaign:linux)    pat='^ *(REL_[A-Z0-9_]+|KERNEL:[A-Za-z0-9_]+): [1-9][0-9]*$' ;;
            campaign:zephyr)   pat='O_WQ: WAITQ_STALE=[1-9]|kernel faults: [1-9]' ;;
            campaign:freertos) pat='O_WQ deq violations: [1-9]|kernel asserts +: [1-9]' ;;
            probe:zephyr)      pat='(TIMESLICE|EDF_ORDER) +: [1-9]' ;;
            *) continue ;;
        esac
        grep -aqE "$pat" "$LOGS/$l.log" && return 0
    done
    return 1
}

echo "################ LINUX  -- SCHED_DEADLINE fuzzer, oracle O_CBS ################"
run_target "linux" env KDIR="${KDIR:-$HERE/linux/kernel}" bash "$HERE/linux/run_fuzzer.sh"

echo
echo "################ ZEPHYR -- EDF fuzzer, oracle O_WQ (direct) ##################"
run_target "zephyr" bash "$HERE/zephyr/run_fuzzer.sh"

echo
echo "################ FREERTOS -- fuzzer, oracle O_WQ (dequeue) ###################"
run_target "freertos" bash "$HERE/freertos/run_fuzzer.sh"

echo
echo "================================ RUN SUMMARY ================================"
for s in "${STATUS[@]}"; do echo "  $s"; done
echo "  totals: ran=$ran skipped=$skipped failed=$failed (of 3 targets)"

if [ "$ran" -eq 0 ]; then
    echo
    echo "NOTHING RAN. No oracle was applied to any scheduler, so the absence of"
    echo "reported violations above says NOTHING about these kernels. Set KDIR /"
    echo "ZEPHYR_BASE / FREERTOS_KERNEL (see README.md) and re-run."
    exit 1
fi

echo
said=0
if saw campaign; then
    echo "At least one target that ran printed a campaign count above zero (a"
    echo "relation violation, a Linux crash kind, Zephyr kernel faults or FreeRTOS"
    echo "kernel asserts); its lines above give the counts."
    said=1
fi
if saw probe; then
    echo "A Zephyr end-of-run probe (TIMESLICE / EDF_ORDER) reported a non-zero"
    echo "count above; those probes run outside the generated campaign."
    said=1
fi
[ "$said" -eq 0 ] && echo "No violation observed in this run."
echo "Linux judges O_CBS with oracle/schedfuzz_oracle.py; Zephyr judges O_WQ"
echo "(direct) in C; FreeRTOS judges O_WQ (dequeue) in C."
echo "NOTE: this statement covers the $ran target(s) that actually ran; any"
echo "skipped/failed target above was not exercised at all."
# Exit: 0 all ran; 1 a target failed or nothing ran; else 2 (a target skipped).
[ "$failed" -gt 0 ] && exit 1
if [ "$skipped" -gt 0 ]; then
    echo
    echo "PARTIAL RUN: $skipped of 3 target(s) were SKIPPED and never exercised."
    echo "Exiting 2 so this cannot be read as a clean full run. Provide the"
    echo "missing prerequisites (KDIR / ZEPHYR_BASE / FREERTOS_KERNEL) for a"
    echo "run that covers all three."
    exit 2
fi
exit 0

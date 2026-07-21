#!/usr/bin/env bash
# schedule_gate.sh — Decide whether a functional-sp1-proofs tick should run.
#
# The workflow cron ticks hourly because GitHub cannot read vars.* inside
# on.schedule.cron; this script turns those ticks into the real cadence and
# writes should_run=true|false to GITHUB_OUTPUT.
#
# Expected env vars (all injected by the workflow step):
#   EVENT_NAME      — github.event_name; anything but "schedule" always runs
#   INTERVAL_HOURS  — vars.SP1_FN_TESTS_INTERVAL_HOURS; falls back to 6 when
#                     unset or not a positive integer
#   CACHE_HIT       — "true" when the sp1-fn-tested-<sha> cache marker exists,
#                     i.e. this commit already passed
#   GITHUB_OUTPUT   — path to the GHA outputs file (set by the runner)

set -euo pipefail

should_run() {
  echo "should_run=$1" >> "$GITHUB_OUTPUT"
  exit 0
}

if [ "$EVENT_NAME" != "schedule" ]; then
  echo "Manual trigger — running"
  should_run true
fi

INTERVAL="${INTERVAL_HOURS:-6}"
case "$INTERVAL" in
  *[!0-9]* | 0)
    echo "Invalid SP1_FN_TESTS_INTERVAL_HOURS='$INTERVAL' — falling back to 6"
    INTERVAL=6
    ;;
esac

# Intervals dividing 24 give even spacing; others wrap unevenly at midnight UTC.
HOUR=$((10#$(date -u +%H)))
if [ $((HOUR % INTERVAL)) -ne 0 ]; then
  echo "Hour $HOUR is not a multiple of interval $INTERVAL — skipping"
  should_run false
fi

if [ "${CACHE_HIT:-}" = "true" ]; then
  echo "Commit already tested successfully — skipping"
  should_run false
fi

echo "Interval hour reached and commit not yet tested — running"
should_run true

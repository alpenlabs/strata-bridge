#!/usr/bin/env bash
# schedule_gate.sh — Decide whether a functional-sp1-proofs tick should run;
# the hourly cron becomes the real cadence here because GitHub cannot read
# vars.* inside on.schedule.cron. Reads EVENT_NAME, INTERVAL_HOURS, CACHE_HIT;
# writes should_run=true|false to GITHUB_OUTPUT.

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
  *[!0-9]*) INTERVAL=-1 ;;
  *) INTERVAL=$((10#$INTERVAL)) ;; # base 10: "08" would be bad octal
esac
if [ "$INTERVAL" -lt 1 ]; then
  echo "Invalid SP1_FN_TESTS_INTERVAL_HOURS='$INTERVAL_HOURS' — falling back to 6"
  INTERVAL=6
fi

# Epoch hours, not hour-of-day: the cadence must not reset at midnight.
EPOCH_HOUR=$(( $(date -u +%s) / 3600 ))
if [ $((EPOCH_HOUR % INTERVAL)) -ne 0 ]; then
  echo "Epoch hour $EPOCH_HOUR is not a multiple of interval $INTERVAL — skipping"
  should_run false
fi

if [ "${CACHE_HIT:-}" = "true" ]; then
  echo "Commit already tested successfully — skipping"
  should_run false
fi

echo "Interval hour reached and commit not yet tested — running"
should_run true

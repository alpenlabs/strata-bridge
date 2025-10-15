#!/usr/bin/env bash

ADDR=tb1q0vgqrryql5uwume6k0u7enrlwyx03dwq094z92

for i in {1..10000}; do
  echo "Sending tx #$i ..."
  bitcoin-cli sendtoaddress "$ADDR" 0.001 "" "" false
  sleep 1

  # check if fee estimate is available
  FEERATE=$(bitcoin-cli estimatesmartfee 1 | jq -r '.feerate // empty')
  if [ -n "$FEERATE" ]; then
    echo "✅ Fee estimate available: $FEERATE BTC/kvB"
    break
  fi
done

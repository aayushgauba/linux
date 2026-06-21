#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
make -C samples/tensor_native flow_tensor_producer flow_policy_consumer >/dev/null

echo "batch,iters,total_ms,us_per_flow,flows_per_sec"
for batch in 1024 4096 16384 65536; do
  iters=200
  if [ "$batch" -ge 16384 ]; then iters=80; fi
  if [ "$batch" -ge 65536 ]; then iters=30; fi

  rm -f /dev/shm/flow0 /dev/shm/flowact0
  ./samples/tensor_native/flow_policy_consumer /flow0 /flowact0 "$iters" >/tmp/flow_cons.log 2>&1 &
  cpid=$!
  start=$(date +%s%N)
  ./samples/tensor_native/flow_tensor_producer /flow0 /flowact0 "$batch" "$iters" >/tmp/flow_prod.log 2>&1
  end=$(date +%s%N)
  wait "$cpid"

  ns=$((end-start))
  total=$((batch*iters))
  echo "$batch,$iters,$(awk -v ns="$ns" 'BEGIN{printf "%.3f", ns/1000000.0}'),$(awk -v ns="$ns" -v t="$total" 'BEGIN{printf "%.3f", ns/1000.0/t}'),$(awk -v ns="$ns" -v t="$total" 'BEGIN{printf "%.0f", t*1000000000.0/ns}')"
done

rm -f /dev/shm/flow0 /dev/shm/flowact0

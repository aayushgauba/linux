#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
make -C samples/tensor_native nf_packet_producer nf_policy_consumer >/dev/null

echo "batch,iters,total_ms,us_per_packet,packets_per_sec"
for batch in 128 1024 4096 16384 65536; do
  iters=200
  if [ "$batch" -ge 16384 ]; then
    iters=80
  fi
  if [ "$batch" -ge 65536 ]; then
    iters=30
  fi

  rm -f /dev/shm/pkt0 /dev/shm/verdict0

  ./samples/tensor_native/nf_policy_consumer /pkt0 /verdict0 "$iters" >/tmp/nf_consumer_bench.log 2>&1 &
  cpid=$!
  start=$(date +%s%N)
  ./samples/tensor_native/nf_packet_producer /pkt0 /verdict0 "$batch" "$iters" >/tmp/nf_producer_bench.log 2>&1
  end=$(date +%s%N)
  wait "$cpid"

  ns=$((end-start))
  packets=$((batch * iters))
  total_ms=$(awk -v ns="$ns" 'BEGIN{printf "%.3f", ns/1000000.0}')
  uspp=$(awk -v ns="$ns" -v p="$packets" 'BEGIN{printf "%.3f", ns/1000.0/p}')
  pps=$(awk -v ns="$ns" -v p="$packets" 'BEGIN{printf "%.0f", p*1000000000.0/ns}')
  echo "$batch,$iters,$total_ms,$uspp,$pps"
done

rm -f /dev/shm/pkt0 /dev/shm/verdict0

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."
make -C samples/tensor_native nf_packet_producer nf_policy_consumer nf_bytes_producer nf_bytes_consumer >/dev/null

echo "mode,batch,iters,total_ms,us_per_packet,packets_per_sec"
for batch in 1024 4096 16384 65536; do
  iters=200
  if [ "$batch" -ge 16384 ]; then iters=80; fi
  if [ "$batch" -ge 65536 ]; then iters=30; fi

  rm -f /dev/shm/pkt0 /dev/shm/verdict0
  ./samples/tensor_native/nf_policy_consumer /pkt0 /verdict0 "$iters" >/tmp/tensor_cons.log 2>&1 &
  cpid=$!
  start=$(date +%s%N)
  ./samples/tensor_native/nf_packet_producer /pkt0 /verdict0 "$batch" "$iters" >/tmp/tensor_prod.log 2>&1
  end=$(date +%s%N)
  wait "$cpid"
  ns=$((end-start)); packets=$((batch*iters))
  echo "tensor,$batch,$iters,$(awk -v ns="$ns" 'BEGIN{printf "%.3f", ns/1000000.0}'),$(awk -v ns="$ns" -v p="$packets" 'BEGIN{printf "%.3f", ns/1000.0/p}'),$(awk -v ns="$ns" -v p="$packets" 'BEGIN{printf "%.0f", p*1000000000.0/ns}')"

  rm -f /dev/shm/pkt0 /dev/shm/verdict0
  ./samples/tensor_native/nf_bytes_consumer /pkt0 /verdict0 "$iters" >/tmp/bytes_cons.log 2>&1 &
  cpid=$!
  start=$(date +%s%N)
  ./samples/tensor_native/nf_bytes_producer /pkt0 /verdict0 "$batch" "$iters" >/tmp/bytes_prod.log 2>&1
  end=$(date +%s%N)
  wait "$cpid"
  ns=$((end-start)); packets=$((batch*iters))
  echo "bytes,$batch,$iters,$(awk -v ns="$ns" 'BEGIN{printf "%.3f", ns/1000000.0}'),$(awk -v ns="$ns" -v p="$packets" 'BEGIN{printf "%.3f", ns/1000.0/p}'),$(awk -v ns="$ns" -v p="$packets" 'BEGIN{printf "%.0f", p*1000000000.0/ns}')"
done

rm -f /dev/shm/pkt0 /dev/shm/verdict0

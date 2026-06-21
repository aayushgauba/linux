#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
	echo "run as root: sudo $0" >&2
	exit 1
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
tracefs=/sys/kernel/tracing

if [[ ! -d "$tracefs/events/tensor_native" ]]; then
	tracefs=/sys/kernel/debug/tracing
fi
if [[ ! -d "$tracefs/events/tensor_native" ]]; then
	echo "tensor_native trace events are unavailable" >&2
	exit 1
fi

cleanup()
{
	echo 0 >"$tracefs/events/tensor_native/enable"
	rm -f /tmp/tensor-native-trace-capture.log
}
trap cleanup EXIT

echo 0 >"$tracefs/tracing_on"
echo >"$tracefs/trace"
echo 1 >"$tracefs/events/tensor_native/enable"
echo 1 >"$tracefs/tracing_on"
"$root/samples/tensor_native/tensor_net_capture" \
	16 2 2 verdict >/tmp/tensor-native-trace-capture.log
echo 0 >"$tracefs/tracing_on"

for event in tensor_object_create tensor_object_release tensor_signal \
		tensor_net_queue tensor_net_batch tensor_net_verdict; do
	grep -q "tensor_native:$event:" "$tracefs/trace"
done

cat /tmp/tensor-native-trace-capture.log
grep 'tensor_native:' "$tracefs/trace" | tail -20

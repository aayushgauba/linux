#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
	echo "run as root: sudo $0" >&2
	exit 1
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
left="tensor-left-$$"
right="tensor-right-$$"

cleanup()
{
	ip netns del "$left" 2>/dev/null || true
	ip netns del "$right" 2>/dev/null || true
	rm -f "/tmp/$left.log" "/tmp/$right.log" \
		"/tmp/$left.status" "/tmp/$right.status"
}
trap cleanup EXIT

ip netns add "$left"
ip netns add "$right"
ip -n "$left" link set lo up
ip -n "$right" link set lo up

ip netns exec "$left" env TENSOR_NET_CONTROL=genl \
	"$root/samples/tensor_native/tensor_net_capture" 32 2 10 verdict \
	>"/tmp/$left.log" &
left_pid=$!
ip netns exec "$right" "$root/samples/tensor_native/tensor_net_capture" \
	48 3 10 verdict >"/tmp/$right.log" &
right_pid=$!

wait "$left_pid"
wait "$right_pid"
ip netns exec "$left" cat /proc/net/tensor_net_producer >"/tmp/$left.status"
ip netns exec "$right" cat /proc/net/tensor_net_producer >"/tmp/$right.status"

grep -qx "bound 0" "/tmp/$left.status"
grep -qx "captured_packets 320" "/tmp/$left.status"
grep -qx "pending_packets 0" "/tmp/$left.status"
grep -qx "timed_out_packets 0" "/tmp/$left.status"
grep -qx "bound 0" "/tmp/$right.status"
grep -qx "captured_packets 480" "/tmp/$right.status"
grep -qx "pending_packets 0" "/tmp/$right.status"
grep -qx "timed_out_packets 0" "/tmp/$right.status"

cat "/tmp/$left.log"
cat "/tmp/$right.log"
echo "$left status"
cat "/tmp/$left.status"
echo "$right status"
cat "/tmp/$right.status"

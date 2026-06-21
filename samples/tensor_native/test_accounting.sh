#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
	echo "run as root: sudo $0" >&2
	exit 1
fi

parameter=/sys/module/tensor_native/parameters
old_uid=$(<"$parameter/uid_limit_bytes")
old_cgroup=$(<"$parameter/cgroup_limit_bytes")

cleanup()
{
	echo "$old_uid" >"$parameter/uid_limit_bytes"
	echo "$old_cgroup" >"$parameter/cgroup_limit_bytes"
}
trap cleanup EXIT

echo 8192 >"$parameter/uid_limit_bytes"
echo 8192 >"$parameter/cgroup_limit_bytes"
"$(dirname "$0")/tensor_accounting_test"
grep -qx "total_bytes 0" /proc/tensor_native_accounting
cat /proc/tensor_native_accounting

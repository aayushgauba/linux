/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SAMPLES_NET_POLICY_H
#define _SAMPLES_NET_POLICY_H

#include <stdint.h>

#include "net_sidecar.h"

static inline uint8_t net_policy_drop_from_row(const float row[NET_PKT_FEATURES])
{
	if (row[NET_F_TTL] < 32.0f)
		return 1;
	if (row[NET_F_DST_PORT] == 23.0f)
		return 1;
	return 0;
}

#endif

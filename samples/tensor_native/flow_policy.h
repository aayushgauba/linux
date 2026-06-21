/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SAMPLES_FLOW_POLICY_H
#define _SAMPLES_FLOW_POLICY_H

#include <stdint.h>

#include "flow_sidecar.h"

static inline uint8_t flow_policy_action(const float row[FLOW_FEATURES])
{
	if (row[FLOW_F_DST_PORT] == 23.0f)
		return FLOW_ACTION_DROP;
	if (row[FLOW_F_BYTES] > 200000.0f && row[FLOW_F_AGE_MS] < 2000.0f)
		return FLOW_ACTION_SLOWPATH;
	if (row[FLOW_F_TCP_FLAGS] == 2.0f && row[FLOW_F_PACKETS] > 2000.0f)
		return FLOW_ACTION_SLOWPATH;
	return FLOW_ACTION_ALLOW;
}

#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SAMPLES_NET_BYTES_SHM_H
#define _SAMPLES_NET_BYTES_SHM_H

#include <stdatomic.h>
#include <stdint.h>

#define NET_MAX_PKT_BYTES 1600u

struct net_bytes_header {
	uint32_t magic;
	uint16_t version;
	uint16_t reserved;
	uint64_t batch;
	uint64_t pkt_stride;
	uint64_t data_offset;
	uint64_t lens_offset;
	atomic_uint_least64_t seq;
	atomic_uint_least32_t ready;
};

#define NET_BYTES_MAGIC 0x4e425954u /* NBYT */

#endif

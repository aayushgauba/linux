/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SAMPLES_NET_PACKET_ADAPTER_H
#define _SAMPLES_NET_PACKET_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#include "net_sidecar.h"

int net_packet_to_features(const uint8_t *pkt, size_t len,
			   float row[NET_PKT_FEATURES]);
size_t build_ipv4_tcp_packet(uint8_t *buf, size_t cap, uint16_t src_port,
			     uint16_t dst_port, uint8_t ttl, uint8_t tcp_flags,
			     uint16_t payload_len);

#endif

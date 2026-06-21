/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SAMPLES_NET_SIDECAR_H
#define _SAMPLES_NET_SIDECAR_H

#define NET_PKT_FEATURES 8u

/* Packet tensor feature indices (row-major):
 * 0: src_port, 1: dst_port, 2: protocol,
 * 3: ttl, 4: length, 5: tcp_syn, 6: tcp_ack, 7: reserved
 */
enum net_pkt_feature_index {
	NET_F_SRC_PORT = 0,
	NET_F_DST_PORT = 1,
	NET_F_PROTOCOL = 2,
	NET_F_TTL = 3,
	NET_F_LENGTH = 4,
	NET_F_TCP_SYN = 5,
	NET_F_TCP_ACK = 6,
	NET_F_RESERVED = 7,
};

#define NET_VERDICT_ACCEPT 0u
#define NET_VERDICT_DROP 1u

#endif

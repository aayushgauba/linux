// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <stdint.h>

#include "net_packet_adapter.h"

#define IPV4_MIN_IHL 20u
#define TCP_MIN_HLEN 20u

static uint16_t be16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8) | p[1];
}

int net_packet_to_features(const uint8_t *pkt, size_t len,
			   float row[NET_PKT_FEATURES])
{
	uint8_t version_ihl;
	uint8_t version;
	uint8_t ihl_bytes;
	uint16_t total_len;
	uint8_t proto;
	uint8_t ttl;
	uint16_t src_port = 0;
	uint16_t dst_port = 0;
	uint8_t tcp_syn = 0;
	uint8_t tcp_ack = 0;

	if (len < IPV4_MIN_IHL)
		return -1;

	version_ihl = pkt[0];
	version = version_ihl >> 4;
	if (version != 4)
		return -1;

	ihl_bytes = (version_ihl & 0x0f) * 4;
	if (ihl_bytes < IPV4_MIN_IHL || len < ihl_bytes)
		return -1;

	total_len = be16(&pkt[2]);
	if (total_len > len)
		return -1;

	ttl = pkt[8];
	proto = pkt[9];

	if (proto == 6) {
		const uint8_t *tcp = pkt + ihl_bytes;
		if (len < ihl_bytes + TCP_MIN_HLEN)
			return -1;
		src_port = be16(&tcp[0]);
		dst_port = be16(&tcp[2]);
		tcp_syn = (tcp[13] & 0x02) ? 1 : 0;
		tcp_ack = (tcp[13] & 0x10) ? 1 : 0;
	}

	row[NET_F_SRC_PORT] = (float)src_port;
	row[NET_F_DST_PORT] = (float)dst_port;
	row[NET_F_PROTOCOL] = (float)proto;
	row[NET_F_TTL] = (float)ttl;
	row[NET_F_LENGTH] = (float)total_len;
	row[NET_F_TCP_SYN] = (float)tcp_syn;
	row[NET_F_TCP_ACK] = (float)tcp_ack;
	row[NET_F_RESERVED] = 0.0f;
	return 0;
}

size_t build_ipv4_tcp_packet(uint8_t *buf, size_t cap, uint16_t src_port,
			     uint16_t dst_port, uint8_t ttl, uint8_t tcp_flags,
			     uint16_t payload_len)
{
	size_t total_len = IPV4_MIN_IHL + TCP_MIN_HLEN + payload_len;

	if (cap < total_len)
		return 0;

	buf[0] = 0x45;
	buf[1] = 0;
	buf[2] = (uint8_t)(total_len >> 8);
	buf[3] = (uint8_t)(total_len & 0xff);
	buf[4] = 0;
	buf[5] = 0;
	buf[6] = 0;
	buf[7] = 0;
	buf[8] = ttl;
	buf[9] = 6;
	buf[10] = 0;
	buf[11] = 0;
	buf[12] = 10;
	buf[13] = 0;
	buf[14] = 0;
	buf[15] = 1;
	buf[16] = 10;
	buf[17] = 0;
	buf[18] = 0;
	buf[19] = 2;

	buf[20] = (uint8_t)(src_port >> 8);
	buf[21] = (uint8_t)(src_port & 0xff);
	buf[22] = (uint8_t)(dst_port >> 8);
	buf[23] = (uint8_t)(dst_port & 0xff);
	buf[24] = 0;
	buf[25] = 0;
	buf[26] = 0;
	buf[27] = 0;
	buf[28] = 0;
	buf[29] = 0;
	buf[30] = 0;
	buf[31] = 0;
	buf[32] = 0x50;
	buf[33] = tcp_flags;
	buf[34] = 0;
	buf[35] = 0;
	buf[36] = 0;
	buf[37] = 0;
	buf[38] = 0;
	buf[39] = 0;

	for (size_t i = 0; i < payload_len; i++)
		buf[40 + i] = (uint8_t)(i & 0xff);

	return total_len;
}

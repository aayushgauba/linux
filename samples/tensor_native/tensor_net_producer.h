/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _TENSOR_NET_PRODUCER_H
#define _TENSOR_NET_PRODUCER_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define TENSOR_NET_FEATURES 8u
#define TENSOR_NET_MAX_SLOTS 64u
#define TENSOR_NET_GENL_NAME "TENSOR_NET"
#define TENSOR_NET_GENL_VERSION 1
#define TENSOR_NET_GENL_MCAST_EVENTS "events"

enum tensor_net_genl_command {
	TENSOR_NET_CMD_UNSPEC,
	TENSOR_NET_CMD_BIND,
	TENSOR_NET_CMD_UNBIND,
	TENSOR_NET_CMD_GET_STATS,
	TENSOR_NET_CMD_EVENT,
	__TENSOR_NET_CMD_MAX,
};

#define TENSOR_NET_CMD_MAX (__TENSOR_NET_CMD_MAX - 1)

enum tensor_net_genl_attribute {
	TENSOR_NET_A_UNSPEC,
	TENSOR_NET_A_PACKET_FD,
	TENSOR_NET_A_VERDICT_FD,
	TENSOR_NET_A_TIMEOUT_MS,
	TENSOR_NET_A_IFINDEX,
	TENSOR_NET_A_PROTOCOL,
	TENSOR_NET_A_SRC_PORT,
	TENSOR_NET_A_DST_PORT,
	TENSOR_NET_A_CAPTURED_PACKETS,
	TENSOR_NET_A_DROPPED_PACKETS,
	TENSOR_NET_A_COMPLETED_BATCHES,
	TENSOR_NET_A_SLOTS,
	TENSOR_NET_A_ROWS,
	TENSOR_NET_A_PRODUCER_SLOT,
	TENSOR_NET_A_CONSUMER_SLOT,
	TENSOR_NET_A_WRITE_INDEX,
	TENSOR_NET_A_SEQUENCE,
	TENSOR_NET_A_READY_SLOTS,
	TENSOR_NET_A_ACCEPTED_PACKETS,
	TENSOR_NET_A_VERDICT_DROPPED_PACKETS,
	TENSOR_NET_A_TIMED_OUT_PACKETS,
	TENSOR_NET_A_EVENT_TYPE,
	TENSOR_NET_A_PACKET_ID,
	TENSOR_NET_A_SLOT,
	__TENSOR_NET_A_MAX,
};

#define TENSOR_NET_A_MAX (__TENSOR_NET_A_MAX - 1)

enum tensor_net_genl_event {
	TENSOR_NET_EVENT_UNSPEC,
	TENSOR_NET_EVENT_BATCH,
	TENSOR_NET_EVENT_TIMEOUT,
};

struct tensor_net_bind {
	__s32 packet_tensor_fd;
	__s32 verdict_tensor_fd;
	__u32 timeout_ms;
	__u32 flags;
	__u32 ifindex;
	__u32 protocol;
	__u32 src_port;
	__u32 dst_port;
};

struct tensor_net_ack {
	__u32 slot;
	__u32 reserved;
	__u64 sequence;
};

struct tensor_net_dequeue {
	__u32 slot;
	__u32 reserved;
	__u64 sequence;
	__u64 rows;
};

struct tensor_net_stats {
	__u64 captured_packets;
	__u64 dropped_packets;
	__u64 completed_batches;
	__u64 slots;
	__u64 rows_per_batch;
	__u64 producer_slot;
	__u64 consumer_slot;
	__u64 write_index;
	__u64 sequence;
	__u64 ready_slots;
	__u64 accepted_packets;
	__u64 verdict_dropped_packets;
	__u64 timed_out_packets;
};

#define TENSOR_NET_BIND _IOW('N', 0x00, struct tensor_net_bind)
#define TENSOR_NET_ACK _IOW('N', 0x01, struct tensor_net_ack)
#define TENSOR_NET_GET_STATS _IOR('N', 0x02, struct tensor_net_stats)
#define TENSOR_NET_UNBIND _IO('N', 0x03)
#define TENSOR_NET_DEQUEUE _IOR('N', 0x04, struct tensor_net_dequeue)

#endif /* _TENSOR_NET_PRODUCER_H */

/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM tensor_native

#if !defined(_TRACE_TENSOR_NATIVE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TENSOR_NATIVE_H

#include <linux/tracepoint.h>

#define TENSOR_TRACE_CREATE_NATIVE 0
#define TENSOR_TRACE_CREATE_VIEW 1
#define TENSOR_TRACE_CREATE_DMABUF 2

#define TENSOR_TRACE_SIGNAL_USER 0
#define TENSOR_TRACE_SIGNAL_KERNEL 1

#define TENSOR_TRACE_VERDICT_USER 0
#define TENSOR_TRACE_VERDICT_TIMEOUT 1
#define TENSOR_TRACE_VERDICT_UNBIND 2

TRACE_EVENT(tensor_object_create,
	TP_PROTO(const void *object, const void *storage, u32 dtype, u32 ndim,
		 u64 bytes, u8 kind),
	TP_ARGS(object, storage, dtype, ndim, bytes, kind),
	TP_STRUCT__entry(
		__field(const void *, object)
		__field(const void *, storage)
		__field(u32, dtype)
		__field(u32, ndim)
		__field(u64, bytes)
		__field(u8, kind)
	),
	TP_fast_assign(
		__entry->object = object;
		__entry->storage = storage;
		__entry->dtype = dtype;
		__entry->ndim = ndim;
		__entry->bytes = bytes;
		__entry->kind = kind;
	),
	TP_printk("object=%p storage=%p dtype=%u ndim=%u bytes=%llu kind=%s",
		  __entry->object, __entry->storage, __entry->dtype,
		  __entry->ndim, __entry->bytes,
		  __print_symbolic(__entry->kind,
			{ TENSOR_TRACE_CREATE_NATIVE, "native" },
			{ TENSOR_TRACE_CREATE_VIEW, "view" },
			{ TENSOR_TRACE_CREATE_DMABUF, "dmabuf" }))
);

TRACE_EVENT(tensor_object_release,
	TP_PROTO(const void *object, const void *storage, u64 bytes),
	TP_ARGS(object, storage, bytes),
	TP_STRUCT__entry(
		__field(const void *, object)
		__field(const void *, storage)
		__field(u64, bytes)
	),
	TP_fast_assign(
		__entry->object = object;
		__entry->storage = storage;
		__entry->bytes = bytes;
	),
	TP_printk("object=%p storage=%p bytes=%llu", __entry->object,
		  __entry->storage, __entry->bytes)
);

TRACE_EVENT(tensor_signal,
	TP_PROTO(const void *storage, u64 sequence, u8 source),
	TP_ARGS(storage, sequence, source),
	TP_STRUCT__entry(
		__field(const void *, storage)
		__field(u64, sequence)
		__field(u8, source)
	),
	TP_fast_assign(
		__entry->storage = storage;
		__entry->sequence = sequence;
		__entry->source = source;
	),
	TP_printk("storage=%p sequence=%llu source=%s", __entry->storage,
		  __entry->sequence,
		  __print_symbolic(__entry->source,
			{ TENSOR_TRACE_SIGNAL_USER, "user" },
			{ TENSOR_TRACE_SIGNAL_KERNEL, "kernel" }))
);

TRACE_EVENT(tensor_net_queue,
	TP_PROTO(u32 netns, u32 packet_id, u32 slot, u32 row),
	TP_ARGS(netns, packet_id, slot, row),
	TP_STRUCT__entry(
		__field(u32, netns)
		__field(u32, packet_id)
		__field(u32, slot)
		__field(u32, row)
	),
	TP_fast_assign(
		__entry->netns = netns;
		__entry->packet_id = packet_id;
		__entry->slot = slot;
		__entry->row = row;
	),
	TP_printk("netns=%u packet_id=%u slot=%u row=%u", __entry->netns,
		  __entry->packet_id, __entry->slot, __entry->row)
);

TRACE_EVENT(tensor_net_batch,
	TP_PROTO(u32 netns, u32 slot, u64 rows, u64 sequence, u64 ready_slots),
	TP_ARGS(netns, slot, rows, sequence, ready_slots),
	TP_STRUCT__entry(
		__field(u32, netns)
		__field(u32, slot)
		__field(u64, rows)
		__field(u64, sequence)
		__field(u64, ready_slots)
	),
	TP_fast_assign(
		__entry->netns = netns;
		__entry->slot = slot;
		__entry->rows = rows;
		__entry->sequence = sequence;
		__entry->ready_slots = ready_slots;
	),
	TP_printk("netns=%u slot=%u rows=%llu sequence=%llu ready_slots=%llu",
		  __entry->netns, __entry->slot, __entry->rows,
		  __entry->sequence, __entry->ready_slots)
);

TRACE_EVENT(tensor_net_verdict,
	TP_PROTO(u32 netns, u32 packet_id, u8 verdict, u8 reason),
	TP_ARGS(netns, packet_id, verdict, reason),
	TP_STRUCT__entry(
		__field(u32, netns)
		__field(u32, packet_id)
		__field(u8, verdict)
		__field(u8, reason)
	),
	TP_fast_assign(
		__entry->netns = netns;
		__entry->packet_id = packet_id;
		__entry->verdict = verdict;
		__entry->reason = reason;
	),
	TP_printk("netns=%u packet_id=%u verdict=%s reason=%s", __entry->netns,
		  __entry->packet_id,
		  __print_symbolic(__entry->verdict,
			{ 0, "accept" }, { 1, "drop" }),
		  __print_symbolic(__entry->reason,
			{ TENSOR_TRACE_VERDICT_USER, "user" },
			{ TENSOR_TRACE_VERDICT_TIMEOUT, "timeout" },
			{ TENSOR_TRACE_VERDICT_UNBIND, "unbind" }))
);

TRACE_EVENT(tensor_net_timeout,
	TP_PROTO(u32 netns, u32 packet_id),
	TP_ARGS(netns, packet_id),
	TP_STRUCT__entry(
		__field(u32, netns)
		__field(u32, packet_id)
	),
	TP_fast_assign(
		__entry->netns = netns;
		__entry->packet_id = packet_id;
	),
	TP_printk("netns=%u packet_id=%u", __entry->netns,
		  __entry->packet_id)
);

#endif

#include <trace/define_trace.h>

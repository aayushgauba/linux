// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/bitmap.h>
#include <linux/fs.h>
#include <linux/ip.h>
#include <linux/iosys-map.h>
#include <linux/jiffies.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>
#include <linux/tensor_native.h>
#include <linux/uaccess.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <net/ip.h>
#include <net/genetlink.h>
#include <net/netfilter/nf_queue.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/netns/netfilter.h>
#include <trace/events/tensor_native.h>

#include "tensor_net_producer.h"

#define TENSOR_NET_MAX_PENDING 4096u
#define TENSOR_NET_DEFAULT_TIMEOUT_MS 100u
#define TENSOR_NET_MAX_TIMEOUT_MS 5000u
#define TENSOR_NET_TIMEOUT_SCAN_MS 10u

#ifndef kzalloc_obj
#define kzalloc_obj(object, flags) kzalloc(sizeof(object), flags)
#endif

enum tensor_net_feature {
	TENSOR_NET_SRC_PORT,
	TENSOR_NET_DST_PORT,
	TENSOR_NET_PROTOCOL,
	TENSOR_NET_TTL,
	TENSOR_NET_LENGTH,
	TENSOR_NET_TCP_SYN,
	TENSOR_NET_TCP_ACK,
	TENSOR_NET_RESERVED,
};

struct tensor_net_pending {
	struct nf_queue_entry *entry;
	unsigned long expires;
	u32 packet_id;
};

struct tensor_net_state {
	/* Protects state shared by control ioctls and the packet hook. */
	spinlock_t lock;
	/* Serializes bind and unbind operations that may sleep. */
	struct mutex control_lock;
	struct tensor_native_handle *handle;
	struct tensor_native_mapping *mapping;
	struct tensor_native_handle *verdict_handle;
	struct tensor_native_mapping *verdict_mapping;
	struct net *net;
	struct nf_hook_ops hook_ops;
	struct iosys_map map;
	struct iosys_map verdict_map;
	struct tensor_net_pending *pending;
	struct delayed_work timeout_work;
	u64 slot_sequence[TENSOR_NET_MAX_SLOTS];
	unsigned long ready_bitmap[BITS_TO_LONGS(TENSOR_NET_MAX_SLOTS)];
	u64 slots;
	u64 rows;
	u64 producer_slot;
	u64 consumer_slot;
	u64 write_index;
	u64 sequence;
	u64 ready_slots;
	u64 captured_packets;
	u64 dropped_packets;
	u64 completed_batches;
	u64 accepted_packets;
	u64 verdict_dropped_packets;
	u64 timed_out_packets;
	u64 pending_packets;
	u32 next_packet_id;
	unsigned long timeout_jiffies;
	u32 ifindex;
	u32 protocol;
	u32 src_port;
	u32 dst_port;
	bool hook_registered;
	bool stopping;
};

static unsigned int tensor_net_id;
static struct genl_family tensor_net_genl_family;

#define tensor_net (*state)

static unsigned int tensor_net_hook(void *private, struct sk_buff *skb,
				    const struct nf_hook_state *hook_state);

static void tensor_net_genl_event(struct net *net, u32 event, u32 packet_id,
				  u32 slot, u64 sequence, gfp_t allocation)
{
	struct sk_buff *msg;
	void *header;

	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, allocation);
	if (!msg)
		return;
	header = genlmsg_put(msg, 0, 0, &tensor_net_genl_family, 0,
			     TENSOR_NET_CMD_EVENT);
	if (!header)
		goto free_msg;
	if (nla_put_u32(msg, TENSOR_NET_A_EVENT_TYPE, event) ||
	    (packet_id && nla_put_u32(msg, TENSOR_NET_A_PACKET_ID, packet_id)) ||
	    nla_put_u32(msg, TENSOR_NET_A_SLOT, slot) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_SEQUENCE, sequence,
			      TENSOR_NET_A_UNSPEC))
		goto cancel_msg;
	genlmsg_end(msg, header);
	genlmsg_multicast_netns(&tensor_net_genl_family, net, msg, 0, 0,
				GFP_ATOMIC);
	return;

cancel_msg:
	genlmsg_cancel(msg, header);
free_msg:
	nlmsg_free(msg);
}

static struct nf_queue_entry *
tensor_net_queue_entry(struct sk_buff *skb, const struct nf_hook_state *state)
{
	const struct nf_hook_entries *hooks;
	struct nf_queue_entry *entry;
	unsigned int index;

	hooks = rcu_dereference(state->net->nf.hooks_ipv4[state->hook]);
	if (!hooks)
		return NULL;
	for (index = 0; index < hooks->num_hook_entries; index++) {
		if (hooks->hooks[index].hook == tensor_net_hook)
			break;
	}
	if (index == hooks->num_hook_entries)
		return NULL;
	entry = kzalloc_obj(*entry, GFP_ATOMIC);
	if (!entry)
		return NULL;
	entry->skb = skb;
	entry->state = *state;
	entry->hook_index = index;
	entry->size = sizeof(*entry);
	if (!nf_queue_entry_get_refs(entry)) {
		kfree(entry);
		return NULL;
	}
	return entry;
}

static void tensor_net_reinject(struct nf_queue_entry *entry,
				unsigned int verdict)
{
	const struct nf_hook_entries *hooks;
	struct sk_buff *skb = entry->skb;
	int ret = 1;

	if (verdict == NF_DROP) {
		kfree_skb(skb);
		goto free_entry;
	}
	rcu_read_lock();
	hooks = rcu_dereference(entry->state.net->nf.hooks_ipv4[entry->state.hook]);
	if (hooks && entry->hook_index < hooks->num_hook_entries)
		ret = nf_hook_slow(skb, &entry->state, hooks,
				   entry->hook_index + 1);
	if (ret == 1) {
		local_bh_disable();
		entry->state.okfn(entry->state.net, entry->state.sk, skb);
		local_bh_enable();
	}
	rcu_read_unlock();
free_entry:
	nf_queue_entry_free(entry);
}

static void tensor_net_reinject_list(struct list_head *entries,
				     unsigned int verdict)
{
	struct nf_queue_entry *entry;
	struct nf_queue_entry *next;

	list_for_each_entry_safe(entry, next, entries, list) {
		list_del(&entry->list);
		tensor_net_reinject(entry, verdict);
	}
}

static void tensor_net_packet_features(struct sk_buff *skb,
				       u32 row[TENSOR_NET_FEATURES])
{
	struct tcphdr tcp_buffer;
	struct udphdr udp_buffer;
	struct iphdr ip_buffer;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	const struct iphdr *ip;
	unsigned int network_offset = skb_network_offset(skb);
	unsigned int transport_offset;

	memset(row, 0, sizeof(u32) * TENSOR_NET_FEATURES);
	ip = skb_header_pointer(skb, network_offset, sizeof(ip_buffer), &ip_buffer);
	if (!ip || ip->version != 4 || ip->ihl < 5)
		return;
	row[TENSOR_NET_PROTOCOL] = ip->protocol;
	row[TENSOR_NET_TTL] = ip->ttl;
	row[TENSOR_NET_LENGTH] = ntohs(ip->tot_len);
	if (ip_is_fragment(ip))
		return;
	transport_offset = network_offset + ip->ihl * 4;
	if (ip->protocol == IPPROTO_TCP) {
		tcp = skb_header_pointer(skb, transport_offset, sizeof(tcp_buffer),
					 &tcp_buffer);
		if (!tcp)
			return;
		row[TENSOR_NET_SRC_PORT] = ntohs(tcp->source);
		row[TENSOR_NET_DST_PORT] = ntohs(tcp->dest);
		row[TENSOR_NET_TCP_SYN] = tcp->syn;
		row[TENSOR_NET_TCP_ACK] = tcp->ack;
	} else if (ip->protocol == IPPROTO_UDP) {
		udp = skb_header_pointer(skb, transport_offset, sizeof(udp_buffer),
					 &udp_buffer);
		if (!udp)
			return;
		row[TENSOR_NET_SRC_PORT] = ntohs(udp->source);
		row[TENSOR_NET_DST_PORT] = ntohs(udp->dest);
	}
}

static unsigned int tensor_net_hook(void *private, struct sk_buff *skb,
				    const struct nf_hook_state *hook_state)
{
	struct tensor_net_state *state = private;
	struct nf_queue_entry *entry = NULL;
	u32 row[TENSOR_NET_FEATURES];
	unsigned long flags;
	unsigned int verdict = NF_ACCEPT;
	size_t pending_index;
	size_t offset;

	tensor_net_packet_features(skb, row);
	spin_lock_irqsave(&tensor_net.lock, flags);
	if (!tensor_net.mapping)
		goto unlock;
	if ((tensor_net.ifindex &&
	     (!hook_state->in ||
	      hook_state->in->ifindex != tensor_net.ifindex)) ||
	    (tensor_net.protocol &&
	     row[TENSOR_NET_PROTOCOL] != tensor_net.protocol) ||
	    (tensor_net.src_port &&
	     row[TENSOR_NET_SRC_PORT] != tensor_net.src_port) ||
	    (tensor_net.dst_port &&
	     row[TENSOR_NET_DST_PORT] != tensor_net.dst_port))
		goto unlock;
	if (test_bit(tensor_net.producer_slot, tensor_net.ready_bitmap)) {
		tensor_net.dropped_packets++;
		goto unlock;
	}
	pending_index = tensor_net.producer_slot * tensor_net.rows +
			tensor_net.write_index;
	if (tensor_net.pending) {
		entry = tensor_net_queue_entry(skb, hook_state);
		if (!entry) {
			tensor_net.dropped_packets++;
			goto unlock;
		}
		tensor_net.next_packet_id++;
		if (!tensor_net.next_packet_id)
			tensor_net.next_packet_id++;
		row[TENSOR_NET_RESERVED] = tensor_net.next_packet_id;
		tensor_net.pending[pending_index].entry = entry;
		tensor_net.pending[pending_index].expires =
			jiffies + tensor_net.timeout_jiffies;
		tensor_net.pending[pending_index].packet_id =
			tensor_net.next_packet_id;
		tensor_net.pending_packets++;
		trace_tensor_net_queue(tensor_net.net->ns.inum,
				       tensor_net.next_packet_id,
				       tensor_net.producer_slot,
				       tensor_net.write_index);
		verdict = NF_STOLEN;
	}
	offset = (tensor_net.producer_slot * tensor_net.rows +
		  tensor_net.write_index) * TENSOR_NET_FEATURES * sizeof(u32);
	iosys_map_memcpy_to(&tensor_net.map, offset, row, sizeof(row));
	tensor_net.write_index++;
	tensor_net.captured_packets++;
	if (tensor_net.write_index == tensor_net.rows) {
		tensor_net.completed_batches++;
		tensor_net.sequence = tensor_native_signal(tensor_net.handle);
		tensor_net.slot_sequence[tensor_net.producer_slot] =
			tensor_net.sequence;
		__set_bit(tensor_net.producer_slot, tensor_net.ready_bitmap);
		tensor_net.ready_slots++;
		trace_tensor_net_batch(tensor_net.net->ns.inum,
				       tensor_net.producer_slot, tensor_net.rows,
				       tensor_net.sequence,
				       tensor_net.ready_slots);
		tensor_net_genl_event(tensor_net.net, TENSOR_NET_EVENT_BATCH, 0,
				      tensor_net.producer_slot,
				      tensor_net.sequence, GFP_ATOMIC);
		tensor_net.producer_slot =
			(tensor_net.producer_slot + 1) % tensor_net.slots;
		tensor_net.write_index = 0;
	}
unlock:
	spin_unlock_irqrestore(&tensor_net.lock, flags);
	return verdict;
}

static void tensor_net_timeout_work(struct work_struct *work)
{
	struct tensor_net_state *state;
	struct nf_queue_entry *entry;
	u32 packet_id;
	unsigned long flags;
	LIST_HEAD(expired);
	u64 pending_count;
	u64 index;

	state = container_of(to_delayed_work(work), struct tensor_net_state,
			     timeout_work);

	spin_lock_irqsave(&tensor_net.lock, flags);
	pending_count = tensor_net.slots * tensor_net.rows;
	for (index = 0; tensor_net.pending && index < pending_count; index++) {
		entry = tensor_net.pending[index].entry;
		if (!entry)
			continue;
		if (time_before(jiffies, tensor_net.pending[index].expires))
			continue;
		packet_id = tensor_net.pending[index].packet_id;
		tensor_net.pending[index].entry = NULL;
		tensor_net.pending[index].packet_id = 0;
		list_add_tail(&entry->list, &expired);
		tensor_net.pending_packets--;
		tensor_net.timed_out_packets++;
		tensor_net.accepted_packets++;
		trace_tensor_net_timeout(tensor_net.net->ns.inum, packet_id);
		trace_tensor_net_verdict(tensor_net.net->ns.inum, packet_id, 0,
					 TENSOR_TRACE_VERDICT_TIMEOUT);
		tensor_net_genl_event(tensor_net.net, TENSOR_NET_EVENT_TIMEOUT,
				      packet_id, index / tensor_net.rows,
				      tensor_net.sequence, GFP_ATOMIC);
	}
	spin_unlock_irqrestore(&tensor_net.lock, flags);
	tensor_net_reinject_list(&expired, NF_ACCEPT);
	if (!READ_ONCE(tensor_net.stopping))
		schedule_delayed_work(&tensor_net.timeout_work,
				      msecs_to_jiffies(TENSOR_NET_TIMEOUT_SCAN_MS));
}

static void tensor_net_unbind(struct tensor_net_state *state)
{
	struct tensor_native_mapping *verdict_mapping;
	struct tensor_native_handle *verdict_handle;
	struct tensor_native_mapping *mapping;
	struct tensor_native_handle *handle;
	struct net *net;
	struct tensor_net_pending *pending;
	struct nf_queue_entry *entry;
	unsigned long flags;
	LIST_HEAD(queued);
	u64 pending_count;
	u64 index;
	bool hook_registered;

	spin_lock_irqsave(&tensor_net.lock, flags);
	mapping = tensor_net.mapping;
	handle = tensor_net.handle;
	verdict_mapping = tensor_net.verdict_mapping;
	verdict_handle = tensor_net.verdict_handle;
	pending = tensor_net.pending;
	net = tensor_net.net;
	hook_registered = tensor_net.hook_registered;
	pending_count = tensor_net.slots * tensor_net.rows;
	for (index = 0; pending && index < pending_count; index++) {
		entry = pending[index].entry;
		if (entry) {
			list_add_tail(&entry->list, &queued);
			tensor_net.accepted_packets++;
			trace_tensor_net_verdict(net->ns.inum,
						 pending[index].packet_id, 0,
						 TENSOR_TRACE_VERDICT_UNBIND);
		}
	}
	tensor_net.mapping = NULL;
	tensor_net.handle = NULL;
	tensor_net.verdict_mapping = NULL;
	tensor_net.verdict_handle = NULL;
	tensor_net.pending = NULL;
	tensor_net.hook_registered = false;
	iosys_map_clear(&tensor_net.map);
	iosys_map_clear(&tensor_net.verdict_map);
	bitmap_zero(tensor_net.ready_bitmap, TENSOR_NET_MAX_SLOTS);
	tensor_net.slots = 0;
	tensor_net.rows = 0;
	tensor_net.producer_slot = 0;
	tensor_net.consumer_slot = 0;
	tensor_net.write_index = 0;
	tensor_net.ready_slots = 0;
	tensor_net.pending_packets = 0;
	tensor_net.ifindex = 0;
	tensor_net.protocol = 0;
	tensor_net.src_port = 0;
	tensor_net.dst_port = 0;
	spin_unlock_irqrestore(&tensor_net.lock, flags);

	tensor_net_reinject_list(&queued, NF_ACCEPT);
	if (hook_registered)
		nf_unregister_net_hook(net, &tensor_net.hook_ops);
	kfree(pending);
	tensor_native_unmap(verdict_mapping);
	tensor_native_put(verdict_handle);
	tensor_native_unmap(mapping);
	tensor_native_put(handle);
}

static long tensor_net_bind_request(struct tensor_net_state *state,
				    const struct tensor_net_bind *bind)
{
	struct tensor_native_mapping *verdict_mapping = NULL;
	struct tensor_native_handle *verdict_handle = NULL;
	struct tensor_native_mapping *mapping;
	struct tensor_native_handle *handle;
	struct tensor_native_hdr verdict_tensor;
	struct tensor_native_hdr tensor;
	struct tensor_net_pending *pending = NULL;
	struct tensor_net_bind request = *bind;
	struct net *net = NULL;
	unsigned long flags;
	u64 pending_count;
	u32 timeout_ms;
	int ret;

	if (request.flags || request.timeout_ms > TENSOR_NET_MAX_TIMEOUT_MS ||
	    request.protocol > U8_MAX || request.src_port > U16_MAX ||
	    request.dst_port > U16_MAX)
		return -EINVAL;
	timeout_ms = request.timeout_ms ?: TENSOR_NET_DEFAULT_TIMEOUT_MS;
	handle = tensor_native_get(request.packet_tensor_fd);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = tensor_native_get_metadata(handle, &tensor);
	if (ret)
		goto put_handle;
	if (tensor.dtype != TENSOR_NATIVE_DTYPE_U32 || tensor.ndim != 3 ||
	    !tensor.shape[0] || tensor.shape[0] > TENSOR_NET_MAX_SLOTS ||
	    tensor.shape[2] != TENSOR_NET_FEATURES ||
	    tensor.stride_bytes[2] != sizeof(u32) ||
	    tensor.stride_bytes[1] != TENSOR_NET_FEATURES * sizeof(u32) ||
	    tensor.stride_bytes[0] !=
		tensor.shape[1] * TENSOR_NET_FEATURES * sizeof(u32)) {
		ret = -EINVAL;
		goto put_handle;
	}
	pending_count = tensor.shape[0] * tensor.shape[1];
	if (request.verdict_tensor_fd >= 0 &&
	    pending_count > TENSOR_NET_MAX_PENDING) {
		ret = -E2BIG;
		goto put_handle;
	}
	mapping = tensor_native_map(handle, TENSOR_ACCESS_WRITE);
	if (IS_ERR(mapping)) {
		ret = PTR_ERR(mapping);
		goto put_handle;
	}
	if (request.verdict_tensor_fd >= 0) {
		verdict_handle = tensor_native_get(request.verdict_tensor_fd);
		if (IS_ERR(verdict_handle)) {
			ret = PTR_ERR(verdict_handle);
			verdict_handle = NULL;
			goto unmap_packet;
		}
		ret = tensor_native_get_metadata(verdict_handle, &verdict_tensor);
		if (ret)
			goto put_verdict;
		if (verdict_tensor.dtype != TENSOR_NATIVE_DTYPE_U8 ||
		    verdict_tensor.ndim != 2 ||
		    verdict_tensor.shape[0] != tensor.shape[0] ||
		    verdict_tensor.shape[1] != tensor.shape[1] ||
		    verdict_tensor.stride_bytes[1] != sizeof(u8) ||
		    verdict_tensor.stride_bytes[0] != tensor.shape[1]) {
			ret = -EINVAL;
			goto put_verdict;
		}
		verdict_mapping = tensor_native_map(verdict_handle,
						    TENSOR_ACCESS_READ);
		if (IS_ERR(verdict_mapping)) {
			ret = PTR_ERR(verdict_mapping);
			verdict_mapping = NULL;
			goto put_verdict;
		}
		pending = kcalloc(pending_count, sizeof(*pending), GFP_KERNEL);
		if (!pending) {
			ret = -ENOMEM;
			goto unmap_verdict;
		}
	}

	net = tensor_net.net;
	mutex_lock(&tensor_net.control_lock);
	spin_lock_irqsave(&tensor_net.lock, flags);
	if (tensor_net.mapping) {
		ret = -EBUSY;
		spin_unlock_irqrestore(&tensor_net.lock, flags);
		goto unlock_control;
	}
	spin_unlock_irqrestore(&tensor_net.lock, flags);
	ret = nf_register_net_hook(net, &tensor_net.hook_ops);
	if (!ret) {
		spin_lock_irqsave(&tensor_net.lock, flags);
		tensor_net.handle = handle;
		tensor_net.mapping = mapping;
		tensor_net.map = *tensor_native_mapping_map(mapping);
		tensor_net.verdict_handle = verdict_handle;
		tensor_net.verdict_mapping = verdict_mapping;
		if (verdict_mapping)
			tensor_net.verdict_map =
				*tensor_native_mapping_map(verdict_mapping);
		tensor_net.pending = pending;
		tensor_net.net = net;
		tensor_net.hook_registered = true;
		tensor_net.slots = tensor.shape[0];
		tensor_net.rows = tensor.shape[1];
		tensor_net.producer_slot = 0;
		tensor_net.consumer_slot = 0;
		tensor_net.write_index = 0;
		tensor_net.ready_slots = 0;
		tensor_net.timeout_jiffies = msecs_to_jiffies(timeout_ms);
		tensor_net.ifindex = request.ifindex;
		tensor_net.protocol = request.protocol;
		tensor_net.src_port = request.src_port;
		tensor_net.dst_port = request.dst_port;
		bitmap_zero(tensor_net.ready_bitmap, TENSOR_NET_MAX_SLOTS);
		memset(tensor_net.slot_sequence, 0,
		       sizeof(tensor_net.slot_sequence));
		spin_unlock_irqrestore(&tensor_net.lock, flags);
	}
unlock_control:
	mutex_unlock(&tensor_net.control_lock);
	if (!ret)
		return 0;
	kfree(pending);
unmap_verdict:
	tensor_native_unmap(verdict_mapping);
put_verdict:
	tensor_native_put(verdict_handle);
unmap_packet:
	tensor_native_unmap(mapping);
put_handle:
	tensor_native_put(handle);
	return ret;
}

static long tensor_net_bind(struct tensor_net_state *state, void __user *argp)
{
	struct tensor_net_bind request;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	return tensor_net_bind_request(state, &request);
}

static long tensor_net_ack(struct tensor_net_state *state, void __user *argp)
{
	struct nf_queue_entry *entry;
	struct tensor_net_ack ack;
	u32 packet_id;
	unsigned long flags;
	LIST_HEAD(accepted);
	LIST_HEAD(dropped);
	u8 *verdicts = NULL;
	u64 rows;
	u64 index;
	int ret = 0;

	if (copy_from_user(&ack, argp, sizeof(ack)))
		return -EFAULT;
	mutex_lock(&tensor_net.control_lock);
	spin_lock_irqsave(&tensor_net.lock, flags);
	if (!tensor_net.mapping || ack.reserved ||
	    ack.slot != tensor_net.consumer_slot ||
	    !test_bit(ack.slot, tensor_net.ready_bitmap) ||
	    ack.sequence != tensor_net.slot_sequence[ack.slot]) {
		ret = -EINVAL;
		goto unlock;
	}
	rows = tensor_net.rows;
	if (tensor_net.verdict_mapping) {
		spin_unlock_irqrestore(&tensor_net.lock, flags);
		verdicts = kmalloc(rows, GFP_KERNEL);
		if (!verdicts) {
			ret = -ENOMEM;
			goto unlock_mutex;
		}
		iosys_map_memcpy_from(verdicts, &tensor_net.verdict_map,
				      ack.slot * rows, rows);
		spin_lock_irqsave(&tensor_net.lock, flags);
		for (index = 0; index < rows; index++) {
			entry = tensor_net.pending[ack.slot * rows + index].entry;
			if (!entry)
				continue;
			packet_id =
				tensor_net.pending[ack.slot * rows + index].packet_id;
			tensor_net.pending[ack.slot * rows + index].entry = NULL;
			tensor_net.pending[ack.slot * rows + index].packet_id = 0;
			tensor_net.pending_packets--;
			if (verdicts[index] == 1) {
				list_add_tail(&entry->list, &dropped);
				tensor_net.verdict_dropped_packets++;
				trace_tensor_net_verdict(tensor_net.net->ns.inum,
							 packet_id, 1,
							 TENSOR_TRACE_VERDICT_USER);
			} else {
				list_add_tail(&entry->list, &accepted);
				tensor_net.accepted_packets++;
				trace_tensor_net_verdict(tensor_net.net->ns.inum,
							 packet_id, 0,
							 TENSOR_TRACE_VERDICT_USER);
			}
		}
	}
	__clear_bit(ack.slot, tensor_net.ready_bitmap);
	tensor_net.slot_sequence[ack.slot] = 0;
	tensor_net.ready_slots--;
	tensor_net.consumer_slot =
		(tensor_net.consumer_slot + 1) % tensor_net.slots;
unlock:
	spin_unlock_irqrestore(&tensor_net.lock, flags);

unlock_mutex:
	mutex_unlock(&tensor_net.control_lock);
	kfree(verdicts);
	tensor_net_reinject_list(&accepted, NF_ACCEPT);
	tensor_net_reinject_list(&dropped, NF_DROP);
	return ret;
}

static long tensor_net_dequeue(struct tensor_net_state *state,
			       void __user *argp)
{
	struct tensor_net_dequeue dequeue;
	unsigned long flags;
	int ret = 0;

	spin_lock_irqsave(&tensor_net.lock, flags);
	if (!tensor_net.mapping) {
		ret = -ENODEV;
	} else if (!tensor_net.ready_slots) {
		ret = -EAGAIN;
	} else if (!test_bit(tensor_net.consumer_slot,
				    tensor_net.ready_bitmap)) {
		ret = -EIO;
	} else {
		dequeue.slot = tensor_net.consumer_slot;
		dequeue.reserved = 0;
		dequeue.sequence =
			tensor_net.slot_sequence[tensor_net.consumer_slot];
		dequeue.rows = tensor_net.rows;
	}
	spin_unlock_irqrestore(&tensor_net.lock, flags);
	if (ret)
		return ret;
	return copy_to_user(argp, &dequeue, sizeof(dequeue)) ? -EFAULT : 0;
}

static void tensor_net_collect_stats(struct tensor_net_state *state,
				     struct tensor_net_stats *stats)
{
	unsigned long flags;

	spin_lock_irqsave(&tensor_net.lock, flags);
	stats->captured_packets = tensor_net.captured_packets;
	stats->dropped_packets = tensor_net.dropped_packets;
	stats->completed_batches = tensor_net.completed_batches;
	stats->slots = tensor_net.slots;
	stats->rows_per_batch = tensor_net.rows;
	stats->producer_slot = tensor_net.producer_slot;
	stats->consumer_slot = tensor_net.consumer_slot;
	stats->write_index = tensor_net.write_index;
	stats->sequence = tensor_net.sequence;
	stats->ready_slots = tensor_net.ready_slots;
	stats->accepted_packets = tensor_net.accepted_packets;
	stats->verdict_dropped_packets = tensor_net.verdict_dropped_packets;
	stats->timed_out_packets = tensor_net.timed_out_packets;
	spin_unlock_irqrestore(&tensor_net.lock, flags);
}

static long tensor_net_stats(struct tensor_net_state *state, void __user *argp)
{
	struct tensor_net_stats stats;

	tensor_net_collect_stats(state, &stats);
	return copy_to_user(argp, &stats, sizeof(stats)) ? -EFAULT : 0;
}

static long tensor_net_ioctl(struct file *file, unsigned int command,
			     unsigned long argument)
{
	struct tensor_net_state *state;
	void __user *argp = (void __user *)argument;

	state = net_generic(current->nsproxy->net_ns, tensor_net_id);

	switch (command) {
	case TENSOR_NET_BIND:
		return tensor_net_bind(state, argp);
	case TENSOR_NET_ACK:
		return tensor_net_ack(state, argp);
	case TENSOR_NET_GET_STATS:
		return tensor_net_stats(state, argp);
	case TENSOR_NET_DEQUEUE:
		return tensor_net_dequeue(state, argp);
	case TENSOR_NET_UNBIND:
		mutex_lock(&tensor_net.control_lock);
		tensor_net_unbind(state);
		mutex_unlock(&tensor_net.control_lock);
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tensor_net_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tensor_net_ioctl,
	.compat_ioctl = tensor_net_ioctl,
	.llseek = noop_llseek,
};

#ifdef CONFIG_PROC_FS
struct tensor_net_proc_snapshot {
	u64 slots;
	u64 rows;
	u64 producer_slot;
	u64 consumer_slot;
	u64 write_index;
	u64 sequence;
	u64 ready_slots;
	u64 captured_packets;
	u64 dropped_packets;
	u64 completed_batches;
	u64 accepted_packets;
	u64 verdict_dropped_packets;
	u64 timed_out_packets;
	u64 pending_packets;
	u32 timeout_ms;
	u32 ifindex;
	u32 protocol;
	u32 src_port;
	u32 dst_port;
	bool bound;
	bool verdict_mode;
};

static int tensor_net_proc_show(struct seq_file *seq, void *unused)
{
	struct tensor_net_proc_snapshot snapshot;
	struct net *net = seq->private;
	struct tensor_net_state *state;
	unsigned long flags;

	state = net_generic(net, tensor_net_id);
	spin_lock_irqsave(&tensor_net.lock, flags);
	snapshot.slots = tensor_net.slots;
	snapshot.rows = tensor_net.rows;
	snapshot.producer_slot = tensor_net.producer_slot;
	snapshot.consumer_slot = tensor_net.consumer_slot;
	snapshot.write_index = tensor_net.write_index;
	snapshot.sequence = tensor_net.sequence;
	snapshot.ready_slots = tensor_net.ready_slots;
	snapshot.captured_packets = tensor_net.captured_packets;
	snapshot.dropped_packets = tensor_net.dropped_packets;
	snapshot.completed_batches = tensor_net.completed_batches;
	snapshot.accepted_packets = tensor_net.accepted_packets;
	snapshot.verdict_dropped_packets = tensor_net.verdict_dropped_packets;
	snapshot.timed_out_packets = tensor_net.timed_out_packets;
	snapshot.pending_packets = tensor_net.pending_packets;
	snapshot.timeout_ms = jiffies_to_msecs(tensor_net.timeout_jiffies);
	snapshot.ifindex = tensor_net.ifindex;
	snapshot.protocol = tensor_net.protocol;
	snapshot.src_port = tensor_net.src_port;
	snapshot.dst_port = tensor_net.dst_port;
	snapshot.bound = !!tensor_net.mapping;
	snapshot.verdict_mode = !!tensor_net.verdict_mapping;
	spin_unlock_irqrestore(&tensor_net.lock, flags);

	seq_printf(seq, "bound %u\n", snapshot.bound);
	seq_printf(seq, "verdict_mode %u\n", snapshot.verdict_mode);
	seq_printf(seq, "slots %llu\n", snapshot.slots);
	seq_printf(seq, "rows %llu\n", snapshot.rows);
	seq_printf(seq, "producer_slot %llu\n", snapshot.producer_slot);
	seq_printf(seq, "consumer_slot %llu\n", snapshot.consumer_slot);
	seq_printf(seq, "write_index %llu\n", snapshot.write_index);
	seq_printf(seq, "sequence %llu\n", snapshot.sequence);
	seq_printf(seq, "ready_slots %llu\n", snapshot.ready_slots);
	seq_printf(seq, "pending_packets %llu\n", snapshot.pending_packets);
	seq_printf(seq, "captured_packets %llu\n", snapshot.captured_packets);
	seq_printf(seq, "dropped_packets %llu\n", snapshot.dropped_packets);
	seq_printf(seq, "completed_batches %llu\n", snapshot.completed_batches);
	seq_printf(seq, "accepted_packets %llu\n", snapshot.accepted_packets);
	seq_printf(seq, "verdict_dropped_packets %llu\n",
		   snapshot.verdict_dropped_packets);
	seq_printf(seq, "timed_out_packets %llu\n",
		   snapshot.timed_out_packets);
	seq_printf(seq, "timeout_ms %u\n", snapshot.timeout_ms);
	seq_printf(seq, "ifindex %u\n", snapshot.ifindex);
	seq_printf(seq, "protocol %u\n", snapshot.protocol);
	seq_printf(seq, "src_port %u\n", snapshot.src_port);
	seq_printf(seq, "dst_port %u\n", snapshot.dst_port);
	return 0;
}
#endif

static struct miscdevice tensor_net_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "tensor_net_producer",
	.fops = &tensor_net_fops,
	.mode = 0600,
};

static const struct nla_policy tensor_net_genl_policy[TENSOR_NET_A_MAX + 1] = {
	[TENSOR_NET_A_PACKET_FD] = { .type = NLA_S32 },
	[TENSOR_NET_A_VERDICT_FD] = { .type = NLA_S32 },
	[TENSOR_NET_A_TIMEOUT_MS] = { .type = NLA_U32 },
	[TENSOR_NET_A_IFINDEX] = { .type = NLA_U32 },
	[TENSOR_NET_A_PROTOCOL] = { .type = NLA_U32 },
	[TENSOR_NET_A_SRC_PORT] = { .type = NLA_U32 },
	[TENSOR_NET_A_DST_PORT] = { .type = NLA_U32 },
};

static int tensor_net_genl_bind(struct sk_buff *skb, struct genl_info *info)
{
	struct tensor_net_state *state;
	struct tensor_net_bind request = {
		.verdict_tensor_fd = -1,
	};

	if (!info->attrs[TENSOR_NET_A_PACKET_FD])
		return -EINVAL;
	request.packet_tensor_fd =
		nla_get_s32(info->attrs[TENSOR_NET_A_PACKET_FD]);
	if (info->attrs[TENSOR_NET_A_VERDICT_FD])
		request.verdict_tensor_fd =
			nla_get_s32(info->attrs[TENSOR_NET_A_VERDICT_FD]);
	if (info->attrs[TENSOR_NET_A_TIMEOUT_MS])
		request.timeout_ms =
			nla_get_u32(info->attrs[TENSOR_NET_A_TIMEOUT_MS]);
	if (info->attrs[TENSOR_NET_A_IFINDEX])
		request.ifindex = nla_get_u32(info->attrs[TENSOR_NET_A_IFINDEX]);
	if (info->attrs[TENSOR_NET_A_PROTOCOL])
		request.protocol = nla_get_u32(info->attrs[TENSOR_NET_A_PROTOCOL]);
	if (info->attrs[TENSOR_NET_A_SRC_PORT])
		request.src_port = nla_get_u32(info->attrs[TENSOR_NET_A_SRC_PORT]);
	if (info->attrs[TENSOR_NET_A_DST_PORT])
		request.dst_port = nla_get_u32(info->attrs[TENSOR_NET_A_DST_PORT]);

	state = net_generic(genl_info_net(info), tensor_net_id);
	return tensor_net_bind_request(state, &request);
}

static int tensor_net_genl_unbind(struct sk_buff *skb, struct genl_info *info)
{
	struct tensor_net_state *state;

	state = net_generic(genl_info_net(info), tensor_net_id);
	mutex_lock(&tensor_net.control_lock);
	tensor_net_unbind(state);
	mutex_unlock(&tensor_net.control_lock);
	return 0;
}

static int tensor_net_genl_put_stats(struct sk_buff *msg,
				     const struct tensor_net_stats *stats)
{
	if (nla_put_u64_64bit(msg, TENSOR_NET_A_CAPTURED_PACKETS,
			      stats->captured_packets, TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_DROPPED_PACKETS,
			      stats->dropped_packets, TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_COMPLETED_BATCHES,
			      stats->completed_batches, TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_SLOTS, stats->slots,
			      TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_ROWS, stats->rows_per_batch,
			      TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_PRODUCER_SLOT,
			      stats->producer_slot, TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_CONSUMER_SLOT,
			      stats->consumer_slot, TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_WRITE_INDEX, stats->write_index,
			      TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_SEQUENCE, stats->sequence,
			      TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_READY_SLOTS, stats->ready_slots,
			      TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_ACCEPTED_PACKETS,
			      stats->accepted_packets, TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_VERDICT_DROPPED_PACKETS,
			      stats->verdict_dropped_packets,
			      TENSOR_NET_A_UNSPEC) ||
	    nla_put_u64_64bit(msg, TENSOR_NET_A_TIMED_OUT_PACKETS,
			      stats->timed_out_packets, TENSOR_NET_A_UNSPEC))
		return -EMSGSIZE;
	return 0;
}

static int tensor_net_genl_get_stats(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct tensor_net_stats stats;
	struct tensor_net_state *state;
	struct sk_buff *msg;
	void *header;
	int ret;

	state = net_generic(genl_info_net(info), tensor_net_id);
	tensor_net_collect_stats(state, &stats);
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	header = genlmsg_put_reply(msg, info, &tensor_net_genl_family, 0,
				   TENSOR_NET_CMD_GET_STATS);
	if (!header) {
		ret = -EMSGSIZE;
		goto free_msg;
	}
	ret = tensor_net_genl_put_stats(msg, &stats);
	if (ret)
		goto cancel_msg;
	genlmsg_end(msg, header);
	return genlmsg_reply(msg, info);

cancel_msg:
	genlmsg_cancel(msg, header);
free_msg:
	nlmsg_free(msg);
	return ret;
}

static const struct genl_ops tensor_net_genl_ops[] = {
	{
		.cmd = TENSOR_NET_CMD_BIND,
		.flags = GENL_ADMIN_PERM,
		.doit = tensor_net_genl_bind,
	},
	{
		.cmd = TENSOR_NET_CMD_UNBIND,
		.flags = GENL_ADMIN_PERM,
		.doit = tensor_net_genl_unbind,
	},
	{
		.cmd = TENSOR_NET_CMD_GET_STATS,
		.doit = tensor_net_genl_get_stats,
	},
};

static const struct genl_multicast_group tensor_net_genl_groups[] = {
	{ .name = TENSOR_NET_GENL_MCAST_EVENTS },
};

static struct genl_family tensor_net_genl_family = {
	.name = TENSOR_NET_GENL_NAME,
	.version = TENSOR_NET_GENL_VERSION,
	.maxattr = TENSOR_NET_A_MAX,
	.policy = tensor_net_genl_policy,
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = tensor_net_genl_ops,
	.n_ops = ARRAY_SIZE(tensor_net_genl_ops),
	.mcgrps = tensor_net_genl_groups,
	.n_mcgrps = ARRAY_SIZE(tensor_net_genl_groups),
};

static int __net_init tensor_net_net_init(struct net *net)
{
	struct tensor_net_state *state = net_generic(net, tensor_net_id);

	spin_lock_init(&tensor_net.lock);
	mutex_init(&tensor_net.control_lock);
	tensor_net.net = net;
	tensor_net.hook_ops = (struct nf_hook_ops) {
		.hook = tensor_net_hook,
		.priv = state,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	};
	INIT_DELAYED_WORK(&tensor_net.timeout_work, tensor_net_timeout_work);
#ifdef CONFIG_PROC_FS
	if (!proc_create_net_single("tensor_net_producer", 0444, net->proc_net,
				    tensor_net_proc_show, NULL))
		return -ENOMEM;
#endif
	schedule_delayed_work(&tensor_net.timeout_work,
			      msecs_to_jiffies(TENSOR_NET_TIMEOUT_SCAN_MS));
	return 0;
}

static void __net_exit tensor_net_net_exit(struct net *net)
{
	struct tensor_net_state *state = net_generic(net, tensor_net_id);

#ifdef CONFIG_PROC_FS
	remove_proc_entry("tensor_net_producer", net->proc_net);
#endif
	WRITE_ONCE(tensor_net.stopping, true);
	cancel_delayed_work_sync(&tensor_net.timeout_work);
	mutex_lock(&tensor_net.control_lock);
	tensor_net_unbind(state);
	mutex_unlock(&tensor_net.control_lock);
}

static struct pernet_operations tensor_net_pernet_ops = {
	.init = tensor_net_net_init,
	.exit = tensor_net_net_exit,
	.id = &tensor_net_id,
	.size = sizeof(struct tensor_net_state),
};

static int __init tensor_net_init(void)
{
	int ret;

	ret = misc_register(&tensor_net_device);
	if (ret)
		return ret;
	ret = register_pernet_subsys(&tensor_net_pernet_ops);
	if (ret) {
		misc_deregister(&tensor_net_device);
		return ret;
	}
	ret = genl_register_family(&tensor_net_genl_family);
	if (ret) {
		unregister_pernet_subsys(&tensor_net_pernet_ops);
		misc_deregister(&tensor_net_device);
	}
	return ret;
}

static void __exit tensor_net_exit(void)
{
	genl_unregister_family(&tensor_net_genl_family);
	misc_deregister(&tensor_net_device);
	unregister_pernet_subsys(&tensor_net_pernet_ops);
}

module_init(tensor_net_init);
module_exit(tensor_net_exit);

MODULE_DESCRIPTION("Netfilter packet tensor producer sample");
MODULE_LICENSE("GPL");

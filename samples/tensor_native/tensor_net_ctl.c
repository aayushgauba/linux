// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tensor_net_producer.h"
#include "tensor_net_genl.h"

#define MESSAGE_BYTES 4096

static void *attribute_data(const struct nlattr *attribute)
{
	return (char *)attribute + NLA_HDRLEN;
}

static int attribute_ok(const struct nlattr *attribute, int remaining)
{
	return remaining >= (int)sizeof(*attribute) &&
	       attribute->nla_len >= sizeof(*attribute) &&
	       attribute->nla_len <= remaining;
}

static struct nlattr *attribute_next(const struct nlattr *attribute,
				     int *remaining)
{
	int bytes = NLA_ALIGN(attribute->nla_len);

	*remaining -= bytes;
	return (struct nlattr *)((char *)attribute + bytes);
}

static int add_attribute(struct nlmsghdr *header, size_t capacity, __u16 type,
			 const void *data, __u16 bytes)
{
	struct nlattr *attribute;
	size_t offset = NLMSG_ALIGN(header->nlmsg_len);
	size_t length = NLA_HDRLEN + bytes;

	if (offset + NLA_ALIGN(length) > capacity)
		return -1;
	attribute = (struct nlattr *)((char *)header + offset);
	attribute->nla_type = type;
	attribute->nla_len = length;
	memcpy((char *)attribute + NLA_HDRLEN, data, bytes);
	header->nlmsg_len = offset + NLA_ALIGN(length);
	return 0;
}

static int exchange(int socket_fd, struct nlmsghdr *request, void *response,
		    size_t response_bytes)
{
	struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
	ssize_t received;

	if (sendto(socket_fd, request, request->nlmsg_len, 0,
		   (struct sockaddr *)&kernel, sizeof(kernel)) < 0)
		return -1;
	received = recv(socket_fd, response, response_bytes, 0);
	if (received < 0)
		return -1;
	return received;
}

static int netlink_error(const struct nlmsghdr *header)
{
	const struct nlmsgerr *error;

	if (header->nlmsg_type != NLMSG_ERROR)
		return 0;
	error = NLMSG_DATA(header);
	if (!error->error)
		return 0;
	errno = -error->error;
	return -1;
}

static int resolve_family(int socket_fd)
{
	char request_buffer[MESSAGE_BYTES] = { 0 };
	char response_buffer[MESSAGE_BYTES];
	struct nlmsghdr *request = (struct nlmsghdr *)request_buffer;
	struct genlmsghdr *generic;
	struct nlmsghdr *response;
	struct nlattr *attribute;
	__u16 family;
	int remaining;
	int received;

	request->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	request->nlmsg_type = GENL_ID_CTRL;
	request->nlmsg_flags = NLM_F_REQUEST;
	request->nlmsg_seq = 1;
	generic = NLMSG_DATA(request);
	generic->cmd = CTRL_CMD_GETFAMILY;
	generic->version = 1;
	if (add_attribute(request, sizeof(request_buffer), CTRL_ATTR_FAMILY_NAME,
			  TENSOR_NET_GENL_NAME,
			  sizeof(TENSOR_NET_GENL_NAME)) < 0)
		return -1;
	received = exchange(socket_fd, request, response_buffer,
			    sizeof(response_buffer));
	if (received < 0)
		return -1;
	response = (struct nlmsghdr *)response_buffer;
	if (netlink_error(response) < 0)
		return -1;
	generic = NLMSG_DATA(response);
	remaining = response->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	attribute = (struct nlattr *)((char *)generic + GENL_HDRLEN);
	while (attribute_ok(attribute, remaining)) {
		if (attribute->nla_type == CTRL_ATTR_FAMILY_ID) {
			memcpy(&family, attribute_data(attribute), sizeof(family));
			return family;
		}
		attribute = attribute_next(attribute, &remaining);
	}
	errno = ENOENT;
	return -1;
}

static void parse_stat(const struct nlattr *attribute,
		       struct tensor_net_stats *stats)
{
	__u16 type = attribute->nla_type & NLA_TYPE_MASK;
	__u64 value;

	if (attribute->nla_len < NLA_HDRLEN + sizeof(value))
		return;
	memcpy(&value, attribute_data(attribute), sizeof(value));
	switch (type) {
	case TENSOR_NET_A_CAPTURED_PACKETS:
		stats->captured_packets = value;
		break;
	case TENSOR_NET_A_DROPPED_PACKETS:
		stats->dropped_packets = value;
		break;
	case TENSOR_NET_A_COMPLETED_BATCHES:
		stats->completed_batches = value;
		break;
	case TENSOR_NET_A_SLOTS:
		stats->slots = value;
		break;
	case TENSOR_NET_A_ROWS:
		stats->rows_per_batch = value;
		break;
	case TENSOR_NET_A_PRODUCER_SLOT:
		stats->producer_slot = value;
		break;
	case TENSOR_NET_A_CONSUMER_SLOT:
		stats->consumer_slot = value;
		break;
	case TENSOR_NET_A_WRITE_INDEX:
		stats->write_index = value;
		break;
	case TENSOR_NET_A_SEQUENCE:
		stats->sequence = value;
		break;
	case TENSOR_NET_A_READY_SLOTS:
		stats->ready_slots = value;
		break;
	case TENSOR_NET_A_ACCEPTED_PACKETS:
		stats->accepted_packets = value;
		break;
	case TENSOR_NET_A_VERDICT_DROPPED_PACKETS:
		stats->verdict_dropped_packets = value;
		break;
	case TENSOR_NET_A_TIMED_OUT_PACKETS:
		stats->timed_out_packets = value;
		break;
	default:
		break;
	}
}

static int send_command(int socket_fd, int family, __u8 command,
			struct tensor_net_stats *stats)
{
	char request_buffer[MESSAGE_BYTES] = { 0 };
	char response_buffer[MESSAGE_BYTES];
	struct nlmsghdr *request = (struct nlmsghdr *)request_buffer;
	struct genlmsghdr *generic;
	struct nlmsghdr *response;
	struct nlattr *attribute;
	int remaining;
	int received;

	request->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	request->nlmsg_type = family;
	request->nlmsg_flags = NLM_F_REQUEST;
	if (command != TENSOR_NET_CMD_GET_STATS)
		request->nlmsg_flags |= NLM_F_ACK;
	request->nlmsg_seq = 2;
	generic = NLMSG_DATA(request);
	generic->cmd = command;
	generic->version = TENSOR_NET_GENL_VERSION;
	received = exchange(socket_fd, request, response_buffer,
			    sizeof(response_buffer));
	if (received < 0)
		return -1;
	response = (struct nlmsghdr *)response_buffer;
	if (netlink_error(response) < 0)
		return -1;
	if (command != TENSOR_NET_CMD_GET_STATS)
		return 0;
	generic = NLMSG_DATA(response);
	remaining = response->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	attribute = (struct nlattr *)((char *)generic + GENL_HDRLEN);
	while (attribute_ok(attribute, remaining)) {
		parse_stat(attribute, stats);
		attribute = attribute_next(attribute, &remaining);
	}
	return 0;
}

int tensor_net_genl_open(struct tensor_net_genl *client)
{
	struct sockaddr_nl local = { .nl_family = AF_NETLINK };

	client->socket_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
				   NETLINK_GENERIC);
	if (client->socket_fd < 0 ||
	    bind(client->socket_fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		return -1;
	client->family = resolve_family(client->socket_fd);
	return client->family < 0 ? -1 : 0;
}

void tensor_net_genl_close(struct tensor_net_genl *client)
{
	if (client->socket_fd >= 0)
		close(client->socket_fd);
}

int tensor_net_genl_unbind(struct tensor_net_genl *client)
{
	return send_command(client->socket_fd, client->family,
			    TENSOR_NET_CMD_UNBIND, NULL);
}

int tensor_net_genl_stats(struct tensor_net_genl *client,
			  struct tensor_net_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	return send_command(client->socket_fd, client->family,
			    TENSOR_NET_CMD_GET_STATS, stats);
}

int tensor_net_genl_bind(struct tensor_net_genl *client,
			 const struct tensor_net_bind *bind_request)
{
	char request_buffer[MESSAGE_BYTES] = { 0 };
	char response_buffer[MESSAGE_BYTES];
	struct nlmsghdr *request = (struct nlmsghdr *)request_buffer;
	struct genlmsghdr *generic;
	struct nlmsghdr *response;
	int received;

	request->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	request->nlmsg_type = client->family;
	request->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	request->nlmsg_seq = 3;
	generic = NLMSG_DATA(request);
	generic->cmd = TENSOR_NET_CMD_BIND;
	generic->version = TENSOR_NET_GENL_VERSION;
	if (add_attribute(request, sizeof(request_buffer), TENSOR_NET_A_PACKET_FD,
			  &bind_request->packet_tensor_fd,
			  sizeof(bind_request->packet_tensor_fd)) ||
	    add_attribute(request, sizeof(request_buffer), TENSOR_NET_A_VERDICT_FD,
			  &bind_request->verdict_tensor_fd,
			  sizeof(bind_request->verdict_tensor_fd)) ||
	    add_attribute(request, sizeof(request_buffer), TENSOR_NET_A_TIMEOUT_MS,
			  &bind_request->timeout_ms,
			  sizeof(bind_request->timeout_ms)) ||
	    add_attribute(request, sizeof(request_buffer), TENSOR_NET_A_IFINDEX,
			  &bind_request->ifindex, sizeof(bind_request->ifindex)) ||
	    add_attribute(request, sizeof(request_buffer), TENSOR_NET_A_PROTOCOL,
			  &bind_request->protocol, sizeof(bind_request->protocol)) ||
	    add_attribute(request, sizeof(request_buffer), TENSOR_NET_A_SRC_PORT,
			  &bind_request->src_port, sizeof(bind_request->src_port)) ||
	    add_attribute(request, sizeof(request_buffer), TENSOR_NET_A_DST_PORT,
			  &bind_request->dst_port, sizeof(bind_request->dst_port)))
		return -1;
	received = exchange(client->socket_fd, request, response_buffer,
			    sizeof(response_buffer));
	if (received < 0)
		return -1;
	response = (struct nlmsghdr *)response_buffer;
	return netlink_error(response);
}

#ifndef TENSOR_NET_GENL_NO_MAIN
int main(int argc, char **argv)
{
	struct tensor_net_genl client = { .socket_fd = -1 };
	struct tensor_net_stats stats;
	__u8 command;
	int ret;

	if (argc != 2 ||
	    (strcmp(argv[1], "stats") && strcmp(argv[1], "unbind"))) {
		fprintf(stderr, "Usage: %s <stats|unbind>\n", argv[0]);
		return 1;
	}
	command = !strcmp(argv[1], "stats") ? TENSOR_NET_CMD_GET_STATS :
		  TENSOR_NET_CMD_UNBIND;
	if (tensor_net_genl_open(&client) < 0) {
		perror("resolve " TENSOR_NET_GENL_NAME);
		return 1;
	}
	ret = command == TENSOR_NET_CMD_GET_STATS ?
		tensor_net_genl_stats(&client, &stats) : tensor_net_genl_unbind(&client);
	if (ret < 0)
		perror(argv[1]);
	if (!ret && command == TENSOR_NET_CMD_GET_STATS)
		printf("captured_packets %llu\ndropped_packets %llu\n"
		       "completed_batches %llu\nsequence %llu\n",
		       (unsigned long long)stats.captured_packets,
		       (unsigned long long)stats.dropped_packets,
		       (unsigned long long)stats.completed_batches,
		       (unsigned long long)stats.sequence);
	tensor_net_genl_close(&client);
	return ret < 0;
}
#endif

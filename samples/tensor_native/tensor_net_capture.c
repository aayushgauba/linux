// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../../include/uapi/linux/tensor_native.h"
#include "tensor_net_producer.h"
#include "tensor_net_genl.h"

static int create_loopback_sockets(int *sender, int *receiver,
				   struct sockaddr_in *destination)
{
	socklen_t length = sizeof(*destination);

	*receiver = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	*sender = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (*receiver < 0 || *sender < 0)
		return -1;
	*destination = (struct sockaddr_in) {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	if (bind(*receiver, (struct sockaddr *)destination,
		 sizeof(*destination)) < 0 ||
	    getsockname(*receiver, (struct sockaddr *)destination, &length) < 0)
		return -1;
	return 0;
}

int main(int argc, char **argv)
{
	struct tensor_native_create create = {
		.dtype = TENSOR_NATIVE_DTYPE_U32,
		.ndim = 2,
	};
	struct tensor_native_create verdict_create = {
		.dtype = TENSOR_NATIVE_DTYPE_U8,
		.ndim = 2,
		.fd = -1,
	};
	struct tensor_native_access access = { .flags = TENSOR_ACCESS_READ };
	struct tensor_native_access write_access = { .flags = TENSOR_ACCESS_WRITE };
	struct tensor_native_wait wait = { .timeout_ns = 2000000000LL };
	struct tensor_net_bind bind_request;
	struct tensor_net_stats stats;
	struct tensor_net_stats initial_stats;
	struct tensor_net_dequeue dequeue;
	struct tensor_net_ack ack;
	struct tensor_net_genl genl = { .socket_fd = -1 };
	struct sockaddr_in destination;
	struct pollfd pollfd;
	struct timespec started;
	struct timespec finished;
	unsigned long batches;
	unsigned long slots;
	unsigned long rows;
	unsigned long batch;
	unsigned long window;
	unsigned long long expected_received = 0;
	unsigned long long received = 0;
	unsigned long long timeout_sent = 0;
	bool enforce;
	bool found_udp;
	bool timeout_mode;
	bool use_genl;
	char payload[32] = { 0 };
	char drain[64];
	__u32 *data;
	__u8 *verdict_data = NULL;
	double seconds;
	unsigned long long captured;
	int control_fd;
	int producer_fd;
	int receiver;
	int sender;

	if (argc != 4 && argc != 5) {
		fprintf(stderr,
			"Usage: %s <rows> <slots> <batches> [verdict|timeout]\n",
			argv[0]);
		return 1;
	}
	rows = strtoul(argv[1], NULL, 10);
	slots = strtoul(argv[2], NULL, 10);
	batches = strtoul(argv[3], NULL, 10);
	if (!rows || !slots || slots > TENSOR_NET_MAX_SLOTS || !batches)
		return 1;
	timeout_mode = argc == 5 && !strcmp(argv[4], "timeout");
	enforce = argc == 5 && (!strcmp(argv[4], "verdict") || timeout_mode);
	if (argc == 5 && !enforce)
		return 1;
	use_genl = getenv("TENSOR_NET_CONTROL") &&
		   !strcmp(getenv("TENSOR_NET_CONTROL"), "genl");
	create.ndim = 3;
	create.shape[0] = slots;
	create.shape[1] = rows;
	create.shape[2] = TENSOR_NET_FEATURES;
	verdict_create.shape[0] = slots;
	verdict_create.shape[1] = rows;
	if (create_loopback_sockets(&sender, &receiver, &destination) < 0) {
		perror("loopback sockets");
		return 1;
	}

	control_fd = open("/dev/tensor_native", O_RDWR | O_CLOEXEC);
	producer_fd = open("/dev/tensor_net_producer", O_RDWR | O_CLOEXEC);
	if (control_fd < 0 || producer_fd < 0) {
		perror("open tensor devices");
		return 1;
	}
	if (ioctl(control_fd, TENSOR_CREATE, &create) < 0) {
		perror("TENSOR_CREATE");
		return 1;
	}
	if (enforce && ioctl(control_fd, TENSOR_CREATE, &verdict_create) < 0) {
		perror("TENSOR_CREATE verdict");
		return 1;
	}
	data = mmap(NULL, create.tensor.data_bytes, PROT_READ | PROT_WRITE,
		    MAP_SHARED, create.fd, 0);
	if (data == MAP_FAILED) {
		perror("mmap packet tensor");
		return 1;
	}
	if (enforce) {
		verdict_data = mmap(NULL, verdict_create.tensor.data_bytes,
				    PROT_READ | PROT_WRITE, MAP_SHARED,
				    verdict_create.fd, 0);
		if (verdict_data == MAP_FAILED) {
			perror("mmap verdict tensor");
			return 1;
		}
	}
	bind_request = (struct tensor_net_bind) {
		.packet_tensor_fd = create.fd,
		.verdict_tensor_fd = enforce ? verdict_create.fd : -1,
		.timeout_ms = 1000,
		.ifindex = if_nametoindex("lo"),
		.protocol = IPPROTO_UDP,
		.dst_port = ntohs(destination.sin_port),
	};
	if (!bind_request.ifindex) {
		perror("if_nametoindex lo");
		return 1;
	}
	if (use_genl && tensor_net_genl_open(&genl) < 0) {
		perror("open TENSOR_NET");
		return 1;
	}
	if ((use_genl ? tensor_net_genl_bind(&genl, &bind_request) :
		ioctl(producer_fd, TENSOR_NET_BIND, &bind_request)) < 0) {
		perror("TENSOR_NET_BIND");
		return 1;
	}
	if ((use_genl ? tensor_net_genl_stats(&genl, &initial_stats) :
		ioctl(producer_fd, TENSOR_NET_GET_STATS, &initial_stats)) < 0 ||
	    clock_gettime(CLOCK_MONOTONIC, &started) < 0) {
		perror("initial tensor net stats");
		return 1;
	}

	for (batch = 0; batch < batches; batch += window) {
		window = batches - batch < slots ? batches - batch : slots;
		for (unsigned long packet = 0; packet < rows * window; packet++) {
			if (sendto(sender, payload, sizeof(payload), 0,
				   (struct sockaddr *)&destination,
				   sizeof(destination)) != (ssize_t)sizeof(payload)) {
				perror("sendto");
				return 1;
			}
		}
		if (timeout_mode) {
			timeout_sent = rows * window;
			usleep(1500000);
			while (recv(receiver, drain, sizeof(drain), 0) > 0)
				received++;
			goto capture_done;
		}
		for (unsigned long ready = 0; ready < window; ready++) {
			while (ioctl(producer_fd, TENSOR_NET_DEQUEUE, &dequeue) < 0) {
				if (errno != EAGAIN) {
					perror("TENSOR_NET_DEQUEUE");
					return 1;
				}
				pollfd = (struct pollfd) {
					.fd = create.fd,
					.events = POLLIN,
				};
				if (poll(&pollfd, 1, 2000) != 1 ||
				    ioctl(create.fd, TENSOR_WAIT, &wait) < 0) {
					fprintf(stderr,
						"timed out waiting for packet tensor\n");
					return 1;
				}
			}
			if (ioctl(create.fd, TENSOR_BEGIN_ACCESS, &access) < 0) {
				perror("TENSOR_BEGIN_ACCESS packet tensor");
				return 1;
			}
			found_udp = false;
			if (enforce &&
			    ioctl(verdict_create.fd, TENSOR_BEGIN_ACCESS,
				  &write_access) < 0) {
				perror("TENSOR_BEGIN_ACCESS verdict tensor");
				return 1;
			}
			for (unsigned long row = 0; row < dequeue.rows; row++) {
				size_t offset;
				bool own_udp;
				__u8 drop;

				offset = (dequeue.slot * rows + row) *
					 TENSOR_NET_FEATURES;
				own_udp = data[offset + 2] == IPPROTO_UDP &&
					  data[offset + 1] ==
					  ntohs(destination.sin_port);

				found_udp |= own_udp;
				if (enforce) {
					drop = own_udp && (data[offset + 7] & 1);
					verdict_data[dequeue.slot * rows + row] = drop;
					if (own_udp && !drop)
						expected_received++;
				}
			}
			if (enforce &&
			    ioctl(verdict_create.fd, TENSOR_END_ACCESS,
				  &write_access) < 0) {
				perror("TENSOR_END_ACCESS verdict tensor");
				return 1;
			}
			if (ioctl(create.fd, TENSOR_END_ACCESS, &access) < 0) {
				perror("TENSOR_END_ACCESS packet tensor");
				return 1;
			}
			if (!found_udp) {
				fprintf(stderr, "packet tensor contained no UDP rows\n");
				return 1;
			}
			ack = (struct tensor_net_ack) {
				.slot = dequeue.slot,
				.sequence = dequeue.sequence,
			};
			if (ioctl(producer_fd, TENSOR_NET_ACK, &ack) < 0) {
				perror("TENSOR_NET_ACK");
				return 1;
			}
			wait.sequence = dequeue.sequence;
		}
		while (recv(receiver, drain, sizeof(drain), 0) > 0)
			received++;
	}

capture_done:
	if (clock_gettime(CLOCK_MONOTONIC, &finished) < 0 ||
	    (use_genl ? tensor_net_genl_stats(&genl, &stats) :
	     ioctl(producer_fd, TENSOR_NET_GET_STATS, &stats)) < 0) {
		perror("TENSOR_NET_GET_STATS");
		return 1;
	}
	seconds = finished.tv_sec - started.tv_sec +
		  (finished.tv_nsec - started.tv_nsec) / 1000000000.0;
	captured = stats.captured_packets - initial_stats.captured_packets;
	printf("captured=%llu dropped=%llu batches=%llu slots=%lu rows=%lu packets_per_sec=%.0f\n",
	       captured,
	       (unsigned long long)(stats.dropped_packets -
				    initial_stats.dropped_packets),
	       (unsigned long long)(stats.completed_batches -
				    initial_stats.completed_batches),
	       slots, rows, captured / seconds);
	if (enforce) {
		printf("accepted=%llu verdict_dropped=%llu timed_out=%llu ",
		       (unsigned long long)(stats.accepted_packets -
					    initial_stats.accepted_packets),
		       (unsigned long long)(stats.verdict_dropped_packets -
					    initial_stats.verdict_dropped_packets),
		       (unsigned long long)(stats.timed_out_packets -
					    initial_stats.timed_out_packets));
		printf("received=%llu expected=%llu\n", received,
		       timeout_mode ? timeout_sent : expected_received);
		if (timeout_mode) {
			if (stats.timed_out_packets ==
			    initial_stats.timed_out_packets ||
			    received != timeout_sent)
				return 1;
		} else if (received != expected_received ||
			   stats.timed_out_packets !=
				   initial_stats.timed_out_packets) {
			return 1;
		}
	}
	if (use_genl) {
		tensor_net_genl_unbind(&genl);
		tensor_net_genl_close(&genl);
	} else {
		ioctl(producer_fd, TENSOR_NET_UNBIND);
	}
	munmap(data, create.tensor.data_bytes);
	if (enforce)
		munmap(verdict_data, verdict_create.tensor.data_bytes);
	close(create.fd);
	if (enforce)
		close(verdict_create.fd);
	close(producer_fd);
	close(control_fd);
	close(sender);
	close(receiver);
	return 0;
}

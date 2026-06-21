// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include "../../include/uapi/linux/tensor_native.h"
#include <linux/netfilter.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "net_packet_adapter.h"
#include "net_sidecar.h"
#include "tensor_shm.h"

#ifndef NFQNL_COPY_TENSOR
#define NFQNL_COPY_TENSOR 3
#endif

static volatile sig_atomic_t stop;

struct stats {
	uint64_t seen;
	uint64_t dropped;
};

struct shm_ctx {
	struct tensor_shm_header *pkt_hdr;
	struct tensor_shm_header *verdict_hdr;
	float *features;
	uint8_t *verdicts;
	uint64_t seq;
};

static void on_sigint(int signo)
{
	(void)signo;
	stop = 1;
}

#define VERDICT_WAIT_USEC 50

static int open_map_rw(const char *name, size_t bytes, void **out)
{
	int fd = shm_open(name, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		perror("shm_open");
		return -1;
	}
	if (ftruncate(fd, bytes) < 0) {
		perror("ftruncate");
		close(fd);
		return -1;
	}
	*out = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (*out == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int init_tensor_shm(struct shm_ctx *ctx, const char *pkt_name,
			   const char *verdict_name)
{
	size_t pkt_bytes = sizeof(*ctx->pkt_hdr) +
		NET_PKT_FEATURES * sizeof(float);
	size_t verdict_bytes = sizeof(*ctx->verdict_hdr) + sizeof(uint8_t);
	void *pkt_base = NULL;
	void *verdict_base = NULL;

	if (open_map_rw(pkt_name, pkt_bytes, &pkt_base) < 0)
		return -1;
	if (open_map_rw(verdict_name, verdict_bytes, &verdict_base) < 0)
		return -1;

	ctx->pkt_hdr = pkt_base;
	ctx->features = (float *)((char *)pkt_base + sizeof(*ctx->pkt_hdr));
	ctx->verdict_hdr = verdict_base;
	ctx->verdicts = (uint8_t *)((char *)verdict_base + sizeof(*ctx->verdict_hdr));
	ctx->seq = 0;

	{
		const uint64_t pkt_shape[] = { 1, NET_PKT_FEATURES };
		const uint64_t verdict_shape[] = { 1 };

		if (tensor_shm_init(ctx->pkt_hdr, TENSOR_DTYPE_F32, 2,
				    pkt_shape) < 0 ||
		    tensor_shm_init(ctx->verdict_hdr, TENSOR_DTYPE_U8, 1,
				    verdict_shape) < 0)
			return -1;
	}
	return 0;
}

struct app_ctx {
	struct stats st;
	struct shm_ctx shm;
};

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	struct app_ctx *app = data;
	struct stats *st = &app->st;
	struct nfqnl_msg_packet_hdr *ph;
	unsigned char *payload = NULL;
	int len;
	uint32_t id = 0;
	struct shm_ctx *ctx = &app->shm;
	uint8_t drop = 0;
	uint32_t verdict = NF_ACCEPT;

	(void)nfmsg;
	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
		id = ntohl(ph->packet_id);

	len = nfq_get_payload(nfa, &payload);
	if (len > 0) {
		const struct tensor_native_hdr *th = (const void *)payload;
		const uint32_t *u32_data = NULL;

		atomic_store(&ctx->pkt_hdr->ready, 0);
		ctx->seq += 1;
		atomic_store(&ctx->pkt_hdr->seq, ctx->seq);

		if ((size_t)len >= sizeof(*th) &&
		    th->magic == TENSOR_NATIVE_MAGIC &&
		    th->version == TENSOR_NATIVE_VERSION &&
		    th->ndim == 2 &&
		    th->dtype == TENSOR_NATIVE_DTYPE_U32 &&
		    !th->reserved &&
		    th->shape[1] == NET_PKT_FEATURES &&
		    th->data_offset + th->data_bytes <= (uint64_t)len &&
		    th->data_bytes >= NET_PKT_FEATURES * sizeof(uint32_t)) {
			u32_data = (const uint32_t *)((const char *)payload + th->data_offset);
			for (unsigned i = 0; i < NET_PKT_FEATURES; i++)
				ctx->features[i] = (float)u32_data[i];
		} else {
			if (net_packet_to_features(payload, (size_t)len, ctx->features) != 0)
				goto out;
		}
		ctx->seq += 1;
		atomic_store(&ctx->pkt_hdr->seq, ctx->seq);
		atomic_store(&ctx->pkt_hdr->ready, 1);

		while (!atomic_load(&ctx->verdict_hdr->ready))
			usleep(VERDICT_WAIT_USEC);
		drop = (ctx->verdicts[0] == NET_VERDICT_DROP);
		atomic_store(&ctx->verdict_hdr->ready, 0);
	}

out:

	if (drop) {
		verdict = NF_DROP;
		st->dropped++;
	}
	st->seen++;
	return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <queue_num> <packet_shm_name> <verdict_shm_name>\n",
		prog);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	char buf[8192];
	int rv;
	unsigned long qnum;
	struct app_ctx ctx = {{0}, {0}};

	if (argc != 4) {
		usage(argv[0]);
		return 1;
	}

	qnum = strtoul(argv[1], NULL, 10);
	if (init_tensor_shm(&ctx.shm, argv[2], argv[3]) < 0)
		return 1;
	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);

	h = nfq_open();
	if (!h) {
		perror("nfq_open");
		return 1;
	}

	if (nfq_unbind_pf(h, AF_INET) < 0)
		fprintf(stderr, "warning: nfq_unbind_pf failed\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nfq_bind_pf failed (need CAP_NET_ADMIN/root)\n");
		nfq_close(h);
		return 1;
	}

	qh = nfq_create_queue(h, (uint16_t)qnum, &cb, &ctx);
	if (!qh) {
		fprintf(stderr, "nfq_create_queue failed\n");
		nfq_close(h);
		return 1;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_TENSOR, 0) < 0) {
		if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
			fprintf(stderr, "nfq_set_mode failed\n");
			nfq_destroy_queue(qh);
			nfq_close(h);
			return 1;
		}
	}

	fd = nfq_fd(h);
	while (!stop && (rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		nfq_handle_packet(h, buf, rv);

	printf("nfqueue stats: seen=%llu dropped=%llu accepted=%llu\n",
	       (unsigned long long)ctx.st.seen,
	       (unsigned long long)ctx.st.dropped,
	       (unsigned long long)(ctx.st.seen - ctx.st.dropped));

	nfq_destroy_queue(qh);
	nfq_close(h);
	return 0;
}

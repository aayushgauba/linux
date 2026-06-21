// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net_packet_adapter.h"
#include "net_sidecar.h"
#include "tensor_shm.h"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <packet_shm_name> <verdict_shm_name> <batch> [iters]\n",
		prog);
}

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

int main(int argc, char **argv)
{
	const char *pkt_name, *verdict_name;
	unsigned long batch_ul, iters = 1;
	size_t pkt_bytes, verdict_bytes;
	void *pkt_base, *verdict_base;
	struct tensor_shm_header *pkt_hdr, *verdict_hdr;
	float *features;
	uint8_t *verdicts;
	uint8_t pktbuf[1600];
	size_t pkt_len;
	uint64_t i;
	uint64_t pkt_shape[2];
	uint64_t verdict_shape[1];
	unsigned dropped = 0;

	if (argc != 4 && argc != 5) {
		usage(argv[0]);
		return 1;
	}

	pkt_name = argv[1];
	verdict_name = argv[2];
	batch_ul = strtoul(argv[3], NULL, 10);
	if (!batch_ul)
		return 1;
	if (argc == 5) {
		iters = strtoul(argv[4], NULL, 10);
		if (!iters)
			return 1;
	}

	pkt_bytes = sizeof(*pkt_hdr) + batch_ul * NET_PKT_FEATURES * sizeof(float);
	verdict_bytes = sizeof(*verdict_hdr) + batch_ul;

	if (open_map_rw(pkt_name, pkt_bytes, &pkt_base) < 0)
		return 1;
	if (open_map_rw(verdict_name, verdict_bytes, &verdict_base) < 0)
		return 1;

	pkt_hdr = pkt_base;
	features = (float *)((char *)pkt_base + sizeof(*pkt_hdr));
	verdict_hdr = verdict_base;
	verdicts = (uint8_t *)((char *)verdict_base + sizeof(*verdict_hdr));

	pkt_shape[0] = batch_ul;
	pkt_shape[1] = NET_PKT_FEATURES;
	verdict_shape[0] = batch_ul;
	if (tensor_shm_init(pkt_hdr, TENSOR_DTYPE_F32, 2, pkt_shape) < 0 ||
	    tensor_shm_init(verdict_hdr, TENSOR_DTYPE_U8, 1, verdict_shape) < 0)
		return 1;

	for (unsigned long iter = 0; iter < iters; iter++) {
		atomic_store_explicit(&pkt_hdr->ready, 0, memory_order_relaxed);
		atomic_store_explicit(&pkt_hdr->seq, (iter * 2) + 1,
				      memory_order_relaxed);

		for (i = 0; i < batch_ul; i++) {
			float *row = &features[i * NET_PKT_FEATURES];
			uint16_t src_port = 10000 + ((i + iter) % 50000);
			uint16_t dst_port = ((i + iter) % 16 == 0) ? 23 : 443;
			uint8_t ttl = ((i + iter) % 10 == 0) ? 16 : 64;
			uint8_t flags = ((i + iter) % 2 == 0) ? 0x02 : 0x10;
			uint16_t payload_len = (uint16_t)((i + iter) % 1200);

			pkt_len = build_ipv4_tcp_packet(pktbuf, sizeof(pktbuf), src_port,
							dst_port, ttl, flags, payload_len);
			if (!pkt_len || net_packet_to_features(pktbuf, pkt_len, row) < 0)
				return 1;
		}

		atomic_store_explicit(&pkt_hdr->seq, (iter * 2) + 2,
				      memory_order_release);
		atomic_store_explicit(&pkt_hdr->ready, 1, memory_order_release);

		while (!atomic_load_explicit(&verdict_hdr->ready, memory_order_acquire))
			usleep(50);

		for (i = 0; i < batch_ul; i++) {
			if (verdicts[i] == NET_VERDICT_DROP)
				dropped++;
		}

		atomic_store_explicit(&verdict_hdr->ready, 0, memory_order_release);
	}

	printf("packet batch=%lu iters=%lu verdicts: accept=%lu drop=%u\n",
	       batch_ul, iters, (batch_ul * iters) - dropped, dropped);
	return 0;
}

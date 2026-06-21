// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "net_bytes_shm.h"
#include "net_packet_adapter.h"
#include "net_sidecar.h"
#include "tensor_shm.h"

static int open_map_rw(const char *name, size_t bytes, void **out)
{
	int fd = shm_open(name, O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		return -1;
	if (ftruncate(fd, bytes) < 0)
		return -1;
	*out = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	return *out == MAP_FAILED ? -1 : 0;
}

int main(int argc, char **argv)
{
	const char *pkt_name, *verdict_name;
	unsigned long batch, iters = 1;
	void *pkt_base, *verdict_base;
	struct net_bytes_header *pkt_hdr;
	struct tensor_shm_header *verdict_hdr;
	uint16_t *lens;
	uint8_t *pkt_data, *verdicts;
	uint64_t verdict_shape[1];
	size_t pkt_bytes, verdict_bytes;
	unsigned dropped = 0;

	if (argc != 4 && argc != 5)
		return 1;
	pkt_name = argv[1];
	verdict_name = argv[2];
	batch = strtoul(argv[3], NULL, 10);
	if (!batch)
		return 1;
	if (argc == 5) {
		iters = strtoul(argv[4], NULL, 10);
		if (!iters)
			return 1;
	}

	pkt_bytes = sizeof(*pkt_hdr) + batch * sizeof(uint16_t) +
		batch * NET_MAX_PKT_BYTES;
	verdict_bytes = sizeof(*verdict_hdr) + batch;
	if (open_map_rw(pkt_name, pkt_bytes, &pkt_base) < 0)
		return 1;
	if (open_map_rw(verdict_name, verdict_bytes, &verdict_base) < 0)
		return 1;

	pkt_hdr = pkt_base;
	lens = (uint16_t *)((char *)pkt_base + sizeof(*pkt_hdr));
	pkt_data = (uint8_t *)((char *)lens + batch * sizeof(uint16_t));
	verdict_hdr = verdict_base;
	verdicts = (uint8_t *)((char *)verdict_base + sizeof(*verdict_hdr));

	memset(pkt_hdr, 0, sizeof(*pkt_hdr));
	pkt_hdr->magic = NET_BYTES_MAGIC;
	pkt_hdr->version = 1;
	pkt_hdr->batch = batch;
	pkt_hdr->pkt_stride = NET_MAX_PKT_BYTES;
	pkt_hdr->lens_offset = sizeof(*pkt_hdr);
	pkt_hdr->data_offset = sizeof(*pkt_hdr) + batch * sizeof(uint16_t);

	verdict_shape[0] = batch;
	if (tensor_shm_init(verdict_hdr, TENSOR_DTYPE_U8, 1,
			    verdict_shape) < 0)
		return 1;

	atomic_store(&pkt_hdr->ready, 0);

	for (unsigned long iter = 0; iter < iters; iter++) {
		atomic_store(&pkt_hdr->ready, 0);
		atomic_store(&pkt_hdr->seq, iter * 2 + 1);
		for (uint64_t i = 0; i < batch; i++) {
			uint8_t *slot = pkt_data + i * NET_MAX_PKT_BYTES;
			uint16_t src_port = 10000 + ((i + iter) % 50000);
			uint16_t dst_port = ((i + iter) % 16 == 0) ? 23 : 443;
			uint8_t ttl = ((i + iter) % 10 == 0) ? 16 : 64;
			uint8_t flags = ((i + iter) % 2 == 0) ? 0x02 : 0x10;
			uint16_t payload_len = (uint16_t)((i + iter) % 1200);
			size_t plen = build_ipv4_tcp_packet(slot, NET_MAX_PKT_BYTES, src_port,
							 dst_port, ttl, flags, payload_len);
			if (!plen)
				return 1;
			lens[i] = (uint16_t)plen;
		}
		atomic_store(&pkt_hdr->seq, iter * 2 + 2);
		atomic_store(&pkt_hdr->ready, 1);
		while (!atomic_load(&verdict_hdr->ready))
			usleep(50);
		for (uint64_t i = 0; i < batch; i++)
			if (verdicts[i] == NET_VERDICT_DROP)
				dropped++;
		atomic_store(&verdict_hdr->ready, 0);
	}

	printf("bytes batch=%lu iters=%lu verdicts: accept=%lu drop=%u\n",
	       batch, iters, (batch * iters) - dropped, dropped);
	return 0;
}

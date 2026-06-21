// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net_bytes_shm.h"
#include "net_packet_adapter.h"
#include "net_policy.h"
#include "net_sidecar.h"
#include "tensor_shm.h"

static int map_region(const char *name, int prot, void **out, struct stat *st)
{
	int fd;
	for (;;) {
		fd = shm_open(name, (prot & PROT_WRITE) ? O_RDWR : O_RDONLY, 0);
		if (fd >= 0)
			break;
		usleep(1000);
	}
	if (fstat(fd, st) < 0)
		return -1;
	*out = mmap(NULL, st->st_size, prot, MAP_SHARED, fd, 0);
	close(fd);
	return *out == MAP_FAILED ? -1 : 0;
}

int main(int argc, char **argv)
{
	const char *pkt_name, *verdict_name;
	unsigned long iters = 1;
	void *pkt_base, *verdict_base;
	struct stat st;
	struct net_bytes_header *pkt_hdr;
	struct tensor_shm_header *verdict_hdr;
	uint16_t *lens;
	uint8_t *pkt_data, *verdicts;
	uint64_t n;

	if (argc != 3 && argc != 4)
		return 1;
	pkt_name = argv[1];
	verdict_name = argv[2];
	if (argc == 4) {
		iters = strtoul(argv[3], NULL, 10);
		if (!iters)
			return 1;
	}

	if (map_region(pkt_name, PROT_READ, &pkt_base, &st) < 0)
		return 1;
	if (map_region(verdict_name, PROT_READ | PROT_WRITE, &verdict_base, &st) < 0)
		return 1;

	pkt_hdr = pkt_base;
	verdict_hdr = verdict_base;
	if (pkt_hdr->magic != NET_BYTES_MAGIC)
		return 1;
	n = pkt_hdr->batch;
	lens = (uint16_t *)((char *)pkt_base + pkt_hdr->lens_offset);
	pkt_data = (uint8_t *)((char *)pkt_base + pkt_hdr->data_offset);
	verdicts = (uint8_t *)((char *)verdict_base + sizeof(*verdict_hdr));

	for (unsigned long iter = 0; iter < iters; iter++) {
		while (!atomic_load(&pkt_hdr->ready))
			usleep(50);
		for (uint64_t i = 0; i < n; i++) {
			float row[NET_PKT_FEATURES];
			if (net_packet_to_features(pkt_data + i * pkt_hdr->pkt_stride,
						   lens[i], row) < 0)
				return 1;
			uint8_t drop = net_policy_drop_from_row(row);
			verdicts[i] = drop ? NET_VERDICT_DROP : NET_VERDICT_ACCEPT;
		}
		atomic_store(&verdict_hdr->ready, 1);
		while (atomic_load(&verdict_hdr->ready))
			usleep(50);
	}
	return 0;
}

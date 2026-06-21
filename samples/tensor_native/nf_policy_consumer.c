// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "net_policy.h"
#include "net_sidecar.h"
#include "tensor_shm.h"

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s <packet_shm_name> <verdict_shm_name> [iters]\n"
		"  iters=0 runs until interrupted\n",
		prog);
}

static int map_region(const char *name, int prot, void **out, struct stat *st)
{
	int flags = (prot & PROT_WRITE) ? O_RDWR : O_RDONLY;
	int fd;
	unsigned tries = 0;

	for (;;) {
		fd = shm_open(name, flags, 0);
		if (fd >= 0)
			break;
		if (tries++ > 1000) {
			perror("shm_open");
			return -1;
		}
		usleep(1000);
	}
	if (fstat(fd, st) < 0) {
		perror("fstat");
		close(fd);
		return -1;
	}
	*out = mmap(NULL, st->st_size, prot, MAP_SHARED, fd, 0);
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
	unsigned long iters = 1;
	void *pkt_base, *verdict_base;
	struct stat pkt_st, verdict_st;
	struct tensor_shm_header *pkt_hdr, *verdict_hdr;
	const float *features;
	uint8_t *verdicts;
	uint64_t n, i;

	if (argc != 3 && argc != 4) {
		usage(argv[0]);
		return 1;
	}

	pkt_name = argv[1];
	verdict_name = argv[2];
	if (argc == 4) {
		char *end = NULL;
		iters = strtoul(argv[3], &end, 10);
		if (end == argv[3])
			return 1;
	}

	if (map_region(pkt_name, PROT_READ, &pkt_base, &pkt_st) < 0)
		return 1;
	if (map_region(verdict_name, PROT_READ | PROT_WRITE, &verdict_base,
		       &verdict_st) < 0)
		return 1;

	pkt_hdr = pkt_base;
	verdict_hdr = verdict_base;
	if (tensor_shm_validate(pkt_hdr, pkt_st.st_size) < 0 ||
	    pkt_hdr->tensor.dtype != TENSOR_DTYPE_F32 ||
	    pkt_hdr->tensor.ndim != 2 ||
	    pkt_hdr->tensor.shape[1] != NET_PKT_FEATURES)
		return 1;
	if (tensor_shm_validate(verdict_hdr, verdict_st.st_size) < 0 ||
	    verdict_hdr->tensor.dtype != TENSOR_DTYPE_U8 ||
	    verdict_hdr->tensor.ndim != 1 ||
	    verdict_hdr->tensor.shape[0] != pkt_hdr->tensor.shape[0])
		return 1;

	features = (const float *)((const char *)pkt_base + pkt_hdr->tensor.data_offset);
	verdicts = (uint8_t *)((char *)verdict_base + verdict_hdr->tensor.data_offset);
	n = pkt_hdr->tensor.shape[0];

	for (unsigned long iter = 0; iters == 0 || iter < iters; iter++) {
		while (!atomic_load_explicit(&pkt_hdr->ready, memory_order_acquire))
			usleep(50);

		for (i = 0; i < n; i++) {
			const float *row = &features[i * NET_PKT_FEATURES];
			uint8_t drop = net_policy_drop_from_row(row);
			verdicts[i] = drop ? NET_VERDICT_DROP : NET_VERDICT_ACCEPT;
		}

		atomic_store_explicit(&verdict_hdr->ready, 1, memory_order_release);
		while (atomic_load_explicit(&verdict_hdr->ready, memory_order_acquire))
			usleep(50);
	}
	printf("policy evaluated batch=%" PRIu64 " iters=%lu\n", n, iters);
	return 0;
}

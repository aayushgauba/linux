// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tensor_shm.h"

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <name>\n", prog);
}

int main(int argc, char **argv)
{
	const char *name;
	int fd;
	struct stat st;
	void *base;
	struct tensor_shm_header *hdr;
	const float *data;
	uint64_t seq0, seq1 = 0;
	double sum = 0;
	uint64_t i, count;

	if (argc != 2) {
		usage(argv[0]);
		return 1;
	}

	name = argv[1];
	fd = shm_open(name, O_RDONLY, 0);
	if (fd < 0) {
		perror("shm_open");
		return 1;
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		close(fd);
		return 1;
	}

	base = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	hdr = base;
	if (tensor_shm_validate(hdr, st.st_size) < 0 ||
	    hdr->tensor.dtype != TENSOR_DTYPE_F32 || hdr->tensor.ndim != 2) {
		fprintf(stderr, "unexpected tensor format\n");
		return 1;
	}

	while (!atomic_load_explicit(&hdr->ready, memory_order_acquire))
		usleep(1000);

	do {
		seq0 = atomic_load_explicit(&hdr->seq, memory_order_acquire);
		if (seq0 & 1)
			continue;
		data = (const float *)((const char *)base + hdr->tensor.data_offset);
		count = hdr->tensor.shape[0] * hdr->tensor.shape[1];
		sum = 0;
		for (i = 0; i < count; i++)
			sum += data[i];
		seq1 = atomic_load_explicit(&hdr->seq, memory_order_acquire);
	} while (seq0 != seq1 || (seq1 & 1));

	printf("tensor %s: shape=%" PRIu64 "x%" PRIu64 " sum=%.2f\n", name,
	       (uint64_t)hdr->tensor.shape[0],
	       (uint64_t)hdr->tensor.shape[1], sum);
	return 0;
}

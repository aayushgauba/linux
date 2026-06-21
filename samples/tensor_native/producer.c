// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tensor_shm.h"

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <name> <rows> <cols>\n", prog);
}

int main(int argc, char **argv)
{
	const char *name;
	unsigned long rows, cols;
	int fd;
	void *base;
	size_t bytes;
	struct tensor_shm_header *hdr;
	float *data;
	uint64_t shape[2];
	unsigned long r, c;
	uint64_t seq;

	if (argc != 4) {
		usage(argv[0]);
		return 1;
	}

	name = argv[1];
	rows = strtoul(argv[2], NULL, 10);
	cols = strtoul(argv[3], NULL, 10);
	if (!rows || !cols) {
		fprintf(stderr, "rows/cols must be non-zero\n");
		return 1;
	}

	bytes = sizeof(*hdr) + rows * cols * sizeof(float);
	fd = shm_open(name, O_CREAT | O_RDWR, 0600);
	if (fd < 0) {
		perror("shm_open");
		return 1;
	}

	if (ftruncate(fd, bytes) < 0) {
		perror("ftruncate");
		close(fd);
		return 1;
	}

	base = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (base == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	hdr = base;
	data = (float *)((char *)base + sizeof(*hdr));

	shape[0] = rows;
	shape[1] = cols;
	if (tensor_shm_init(hdr, TENSOR_DTYPE_F32, 2, shape) < 0) {
		fprintf(stderr, "invalid tensor shape\n");
		return 1;
	}

	seq = atomic_load_explicit(&hdr->seq, memory_order_relaxed);
	atomic_store_explicit(&hdr->ready, 0, memory_order_relaxed);
	atomic_store_explicit(&hdr->seq, seq + 1, memory_order_relaxed);

	for (r = 0; r < rows; r++) {
		for (c = 0; c < cols; c++)
			data[r * cols + c] = (float)(r * cols + c);
	}

	atomic_store_explicit(&hdr->seq, seq + 2, memory_order_release);
	atomic_store_explicit(&hdr->ready, 1, memory_order_release);

	printf("tensor written to %s (%lux%lu f32, %zu bytes)\n", name, rows, cols,
	       bytes);
	printf("keep producer alive so mapping stays observable; press Ctrl+C to exit\n");
	for (;;)
		pause();
}

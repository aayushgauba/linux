// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "flow_policy.h"
#include "flow_sidecar.h"
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
	const char *flow_name, *action_name;
	unsigned long iters = 1;
	void *flow_base, *act_base;
	struct stat flow_st, act_st;
	struct tensor_shm_header *flow_hdr, *act_hdr;
	const float *rows;
	uint8_t *actions;
	uint64_t batch;

	if (argc != 3 && argc != 4)
		return 1;
	flow_name = argv[1];
	action_name = argv[2];
	if (argc == 4) {
		iters = strtoul(argv[3], NULL, 10);
		if (!iters)
			return 1;
	}

	if (map_region(flow_name, PROT_READ, &flow_base, &flow_st) < 0)
		return 1;
	if (map_region(action_name, PROT_READ | PROT_WRITE, &act_base, &act_st) < 0)
		return 1;

	flow_hdr = flow_base;
	act_hdr = act_base;
	if (tensor_shm_validate(flow_hdr, flow_st.st_size) < 0 ||
	    flow_hdr->tensor.dtype != TENSOR_DTYPE_F32 ||
	    flow_hdr->tensor.ndim != 2 ||
	    flow_hdr->tensor.shape[1] != FLOW_FEATURES)
		return 1;
	if (tensor_shm_validate(act_hdr, act_st.st_size) < 0 ||
	    act_hdr->tensor.dtype != TENSOR_DTYPE_U8 ||
	    act_hdr->tensor.ndim != 1 ||
	    act_hdr->tensor.shape[0] != flow_hdr->tensor.shape[0])
		return 1;

	rows = (const float *)((const char *)flow_base + flow_hdr->tensor.data_offset);
	actions = (uint8_t *)((char *)act_base + act_hdr->tensor.data_offset);
	batch = flow_hdr->tensor.shape[0];

	for (unsigned long iter = 0; iter < iters; iter++) {
		while (!atomic_load_explicit(&flow_hdr->ready, memory_order_acquire))
			usleep(50);
		for (uint64_t i = 0; i < batch; i++) {
			const float *r = &rows[i * FLOW_FEATURES];
			actions[i] = flow_policy_action(r);
		}
		atomic_store_explicit(&act_hdr->ready, 1, memory_order_release);
		while (atomic_load_explicit(&act_hdr->ready, memory_order_acquire))
			usleep(50);
	}
	return 0;
}

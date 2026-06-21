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

#include "flow_sidecar.h"
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
	const char *flow_name, *action_name;
	unsigned long batch, iters = 1;
	void *flow_base, *act_base;
	struct tensor_shm_header *flow_hdr, *act_hdr;
	float *rows;
	uint8_t *actions;
	unsigned allow = 0, slow = 0, drop = 0;
	size_t flow_bytes, act_bytes;
	uint64_t flow_shape[2];
	uint64_t act_shape[1];

	if (argc != 4 && argc != 5)
		return 1;
	flow_name = argv[1];
	action_name = argv[2];
	batch = strtoul(argv[3], NULL, 10);
	if (!batch)
		return 1;
	if (argc == 5) {
		iters = strtoul(argv[4], NULL, 10);
		if (!iters)
			return 1;
	}

	flow_bytes = sizeof(*flow_hdr) + batch * FLOW_FEATURES * sizeof(float);
	act_bytes = sizeof(*act_hdr) + batch;
	if (open_map_rw(flow_name, flow_bytes, &flow_base) < 0)
		return 1;
	if (open_map_rw(action_name, act_bytes, &act_base) < 0)
		return 1;

	flow_hdr = flow_base;
	rows = (float *)((char *)flow_base + sizeof(*flow_hdr));
	act_hdr = act_base;
	actions = (uint8_t *)((char *)act_base + sizeof(*act_hdr));

	flow_shape[0] = batch;
	flow_shape[1] = FLOW_FEATURES;
	act_shape[0] = batch;
	if (tensor_shm_init(flow_hdr, TENSOR_DTYPE_F32, 2, flow_shape) < 0 ||
	    tensor_shm_init(act_hdr, TENSOR_DTYPE_U8, 1, act_shape) < 0)
		return 1;

	for (unsigned long iter = 0; iter < iters; iter++) {
		atomic_store_explicit(&flow_hdr->ready, 0, memory_order_relaxed);
		atomic_store_explicit(&flow_hdr->seq, iter * 2 + 1,
				      memory_order_relaxed);
		for (uint64_t i = 0; i < batch; i++) {
			float *r = &rows[i * FLOW_FEATURES];
			r[FLOW_F_SRC_IP] = (float)(0x0a000001u + ((i + iter) % 65535));
			r[FLOW_F_DST_IP] = (float)(0x0a000100u + ((i + iter) % 65535));
			r[FLOW_F_SRC_PORT] = (float)(10000 + ((i + iter) % 50000));
			r[FLOW_F_DST_PORT] = ((i + iter) % 32 == 0) ? 23.0f : 443.0f;
			r[FLOW_F_PROTO] = 6.0f;
			r[FLOW_F_PACKETS] = 100.0f + (float)((i + iter) % 5000);
			r[FLOW_F_BYTES] = 1000.0f + (float)((i + iter) * 50 % 300000);
			r[FLOW_F_TCP_FLAGS] = ((i + iter) % 2 == 0) ? 2.0f : 16.0f;
			r[FLOW_F_AGE_MS] = (float)((i + iter) % 5000);
			r[FLOW_F_STATE] = (float)((i + iter) % 5);
		}
		atomic_store_explicit(&flow_hdr->seq, iter * 2 + 2,
				      memory_order_release);
		atomic_store_explicit(&flow_hdr->ready, 1, memory_order_release);
		while (!atomic_load_explicit(&act_hdr->ready, memory_order_acquire))
			usleep(50);
		for (uint64_t i = 0; i < batch; i++) {
			if (actions[i] == FLOW_ACTION_ALLOW)
				allow++;
			else if (actions[i] == FLOW_ACTION_SLOWPATH)
				slow++;
			else
				drop++;
		}
		atomic_store_explicit(&act_hdr->ready, 0, memory_order_release);
	}

	printf("flow batch=%lu iters=%lu actions: allow=%u slowpath=%u drop=%u\n",
	       batch, iters, allow, slow, drop);
	return 0;
}

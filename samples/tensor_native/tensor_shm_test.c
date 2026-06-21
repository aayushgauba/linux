// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "tensor_shm.h"

struct test_region {
	struct tensor_shm_header header;
	uint8_t data[64];
};

int main(void)
{
	const uint64_t shape[] = { 2, 8 };
	struct test_region region = { 0 };

	_Static_assert(offsetof(struct tensor_shm_header, seq) ==
		       sizeof(struct tensor_native_hdr),
		       "shared-memory control fields must follow the UAPI header");

	assert(tensor_shm_init(&region.header, TENSOR_NATIVE_DTYPE_F32, 2,
			       shape) == 0);
	assert(region.header.tensor.data_offset == sizeof(region.header));
	assert(region.header.tensor.data_bytes == sizeof(region.data));
	assert(tensor_shm_validate(&region.header, sizeof(region)) == 0);

	region.header.tensor.ndim = TENSOR_NATIVE_MAX_DIMS + 1;
	assert(tensor_shm_validate(&region.header, sizeof(region)) < 0);
	region.header.tensor.ndim = 2;

	region.header.tensor.data_bytes++;
	assert(tensor_shm_validate(&region.header, sizeof(region)) < 0);
	region.header.tensor.data_bytes--;

	region.header.tensor.shape[1] = 0;
	assert(tensor_shm_validate(&region.header, sizeof(region)) < 0);

	puts("tensor SHM ABI validation passed");
	return 0;
}

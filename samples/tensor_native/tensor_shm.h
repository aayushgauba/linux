/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SAMPLES_TENSOR_SHM_H
#define _SAMPLES_TENSOR_SHM_H

#include <stdint.h>
#include <stdatomic.h>
#include <stddef.h>

#include "../../include/uapi/linux/tensor_native.h"

#define TENSOR_SHM_MAGIC TENSOR_NATIVE_MAGIC
#define TENSOR_DTYPE_F32 TENSOR_NATIVE_DTYPE_F32
#define TENSOR_DTYPE_U8 TENSOR_NATIVE_DTYPE_U8

struct tensor_shm_header {
	struct tensor_native_hdr tensor;
	atomic_uint_least64_t seq;
	atomic_uint_least32_t ready;
};

static inline size_t tensor_shm_dtype_size(uint32_t dtype)
{
	switch (dtype) {
	case TENSOR_NATIVE_DTYPE_F32:
		return sizeof(float);
	case TENSOR_NATIVE_DTYPE_U8:
		return sizeof(uint8_t);
	case TENSOR_NATIVE_DTYPE_U32:
		return sizeof(uint32_t);
	default:
		return 0;
	}
}

static inline int tensor_shm_init(struct tensor_shm_header *header,
				  uint32_t dtype, uint16_t ndim,
				  const uint64_t *shape)
{
	struct tensor_native_hdr *tensor = &header->tensor;
	uint64_t stride = tensor_shm_dtype_size(dtype);
	int dim;

	if (!stride || !ndim || ndim > TENSOR_NATIVE_MAX_DIMS)
		return -1;

	*tensor = (struct tensor_native_hdr) {
		.magic = TENSOR_NATIVE_MAGIC,
		.version = TENSOR_NATIVE_VERSION,
		.ndim = ndim,
		.dtype = dtype,
		.data_offset = sizeof(*header),
	};

	for (dim = ndim - 1; dim >= 0; dim--) {
		if (!shape[dim] || shape[dim] > UINT64_MAX / stride)
			return -1;
		tensor->shape[dim] = shape[dim];
		tensor->stride_bytes[dim] = stride;
		stride *= shape[dim];
	}
	tensor->data_bytes = stride;
	atomic_init(&header->seq, 0);
	atomic_init(&header->ready, 0);
	return 0;
}

static inline int tensor_shm_validate(const struct tensor_shm_header *header,
				      size_t mapping_bytes)
{
	const struct tensor_native_hdr *tensor = &header->tensor;
	uint64_t extent;
	size_t element_bytes;
	uint16_t dim;

	if (tensor->magic != TENSOR_NATIVE_MAGIC ||
	    tensor->version != TENSOR_NATIVE_VERSION ||
	    !tensor->ndim || tensor->ndim > TENSOR_NATIVE_MAX_DIMS ||
	    tensor->reserved ||
	    tensor->data_offset < sizeof(*header) ||
	    tensor->data_offset > UINT64_MAX - tensor->data_bytes)
		return -1;

	element_bytes = tensor_shm_dtype_size(tensor->dtype);
	if (!element_bytes || tensor->data_bytes < element_bytes ||
	    tensor->data_offset + tensor->data_bytes > mapping_bytes)
		return -1;

	extent = element_bytes;
	for (dim = 0; dim < tensor->ndim; dim++) {
		uint64_t span;

		if (!tensor->shape[dim] || tensor->stride_bytes[dim] < element_bytes ||
		    tensor->shape[dim] - 1 > UINT64_MAX / tensor->stride_bytes[dim])
			return -1;
		span = (tensor->shape[dim] - 1) * tensor->stride_bytes[dim];
		if (extent > UINT64_MAX - span)
			return -1;
		extent += span;
	}

	return extent <= tensor->data_bytes ? 0 : -1;
}

#endif

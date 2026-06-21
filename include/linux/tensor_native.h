/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_TENSOR_NATIVE_H
#define _LINUX_TENSOR_NATIVE_H

#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/string.h>
#include <linux/types.h>

#include <uapi/linux/tensor_native.h>

struct iosys_map;
struct tensor_native_handle;
struct tensor_native_mapping;

struct tensor_native_handle *tensor_native_get(int fd);
void tensor_native_put(struct tensor_native_handle *handle);
int tensor_native_get_metadata(struct tensor_native_handle *handle,
			       struct tensor_native_hdr *tensor);
struct tensor_native_mapping *
tensor_native_map(struct tensor_native_handle *handle, u32 access_flags);
const struct iosys_map *
tensor_native_mapping_map(struct tensor_native_mapping *mapping);
void tensor_native_unmap(struct tensor_native_mapping *mapping);
u64 tensor_native_signal(struct tensor_native_handle *handle);

static inline size_t tensor_native_dtype_size(u32 dtype)
{
	switch (dtype) {
	case TENSOR_NATIVE_DTYPE_F32:
		return sizeof(u32);
	case TENSOR_NATIVE_DTYPE_U8:
		return sizeof(u8);
	case TENSOR_NATIVE_DTYPE_U32:
		return sizeof(u32);
	default:
		return 0;
	}
}

static inline int tensor_native_init_contiguous(struct tensor_native_hdr *hdr,
						u32 dtype, u16 ndim,
						 const u64 *shape,
						 u64 data_offset)
{
	u64 stride;
	int dim;

	if (!ndim || ndim > TENSOR_NATIVE_MAX_DIMS)
		return -EINVAL;

	stride = tensor_native_dtype_size(dtype);
	if (!stride)
		return -EINVAL;

	memset(hdr, 0, sizeof(*hdr));
	hdr->magic = TENSOR_NATIVE_MAGIC;
	hdr->version = TENSOR_NATIVE_VERSION;
	hdr->ndim = ndim;
	hdr->dtype = dtype;
	hdr->data_offset = data_offset;

	for (dim = ndim - 1; dim >= 0; dim--) {
		if (!shape[dim])
			return -EINVAL;
		hdr->shape[dim] = shape[dim];
		hdr->stride_bytes[dim] = stride;
		if (check_mul_overflow(stride, shape[dim], &stride))
			return -EOVERFLOW;
	}
	hdr->data_bytes = stride;
	return 0;
}

static inline int tensor_native_init_hdr_u32_2d(struct tensor_native_hdr *hdr,
						u64 rows, u64 cols)
{
	const u64 shape[] = { rows, cols };

	return tensor_native_init_contiguous(hdr, TENSOR_NATIVE_DTYPE_U32,
					     2, shape, sizeof(*hdr));
}

#endif /* _LINUX_TENSOR_NATIVE_H */

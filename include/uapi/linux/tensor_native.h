/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_TENSOR_NATIVE_H
#define _UAPI_LINUX_TENSOR_NATIVE_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define TENSOR_NATIVE_MAGIC 0x54454e53u /* 'TENS' */
#define TENSOR_NATIVE_VERSION 1u
#define TENSOR_NATIVE_MAX_DIMS 4

#define TENSOR_NATIVE_DTYPE_F32 1u
#define TENSOR_NATIVE_DTYPE_U8 2u
#define TENSOR_NATIVE_DTYPE_U32 3u

#define TENSOR_ACCESS_READ (1u << 0)
#define TENSOR_ACCESS_WRITE (1u << 1)

struct tensor_native_hdr {
	__u32 magic;
	__u16 version;
	__u16 ndim;
	__u32 dtype;
	__u32 reserved;
	__u64 shape[TENSOR_NATIVE_MAX_DIMS];
	__u64 stride_bytes[TENSOR_NATIVE_MAX_DIMS];
	__u64 data_offset;
	__u64 data_bytes;
};

struct tensor_native_create {
	__u32 dtype;
	__u16 ndim;
	__u16 flags;
	__u64 shape[TENSOR_NATIVE_MAX_DIMS];
	__s32 fd;
	__u32 reserved;
	struct tensor_native_hdr tensor;
};

struct tensor_native_info {
	struct tensor_native_hdr tensor;
	__u64 sequence;
};

struct tensor_native_signal {
	__u64 sequence;
};

struct tensor_native_wait {
	__u64 sequence;
	__s64 timeout_ns;
};

struct tensor_native_clone_view {
	__u64 offset_bytes;
	__u16 ndim;
	__u16 flags;
	__u32 reserved;
	__u64 shape[TENSOR_NATIVE_MAX_DIMS];
	__u64 stride_bytes[TENSOR_NATIVE_MAX_DIMS];
	__s32 fd;
	__u32 reserved2;
	struct tensor_native_hdr tensor;
};

struct tensor_native_dma_buf {
	__s32 fd;
	__u32 flags;
};

struct tensor_native_import_dma_buf {
	__s32 dma_buf_fd;
	__u16 ndim;
	__u16 flags;
	__u32 dtype;
	__u32 reserved;
	__u64 shape[TENSOR_NATIVE_MAX_DIMS];
	__u64 stride_bytes[TENSOR_NATIVE_MAX_DIMS];
	__s32 fd;
	__u32 reserved2;
	struct tensor_native_hdr tensor;
};

struct tensor_native_access {
	__u32 flags;
	__u32 reserved;
};

#define TENSOR_NATIVE_IOC_MAGIC 'T'
#define TENSOR_CREATE _IOWR(TENSOR_NATIVE_IOC_MAGIC, 0x00, \
			    struct tensor_native_create)
#define TENSOR_GET_INFO _IOR(TENSOR_NATIVE_IOC_MAGIC, 0x01, \
			     struct tensor_native_info)
#define TENSOR_SIGNAL _IOWR(TENSOR_NATIVE_IOC_MAGIC, 0x02, \
			    struct tensor_native_signal)
#define TENSOR_WAIT _IOWR(TENSOR_NATIVE_IOC_MAGIC, 0x03, \
			  struct tensor_native_wait)
#define TENSOR_CLONE_VIEW _IOWR(TENSOR_NATIVE_IOC_MAGIC, 0x04, \
				struct tensor_native_clone_view)
#define TENSOR_EXPORT_DMABUF _IOWR(TENSOR_NATIVE_IOC_MAGIC, 0x05, \
				   struct tensor_native_dma_buf)
#define TENSOR_IMPORT_DMABUF _IOWR(TENSOR_NATIVE_IOC_MAGIC, 0x06, \
				   struct tensor_native_import_dma_buf)
#define TENSOR_BEGIN_ACCESS _IOW(TENSOR_NATIVE_IOC_MAGIC, 0x07, \
				 struct tensor_native_access)
#define TENSOR_END_ACCESS _IOW(TENSOR_NATIVE_IOC_MAGIC, 0x08, \
			       struct tensor_native_access)

#endif /* _UAPI_LINUX_TENSOR_NATIVE_H */

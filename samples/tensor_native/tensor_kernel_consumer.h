/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _TENSOR_KERNEL_CONSUMER_H
#define _TENSOR_KERNEL_CONSUMER_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct tensor_kernel_consume {
	__s32 tensor_fd;
	__u32 access_flags;
	__u64 offset_bytes;
	__u32 expected;
	__u32 observed;
	__u64 sequence;
};

#define TENSOR_KERNEL_CONSUME _IOWR('K', 0x00, struct tensor_kernel_consume)

#endif /* _TENSOR_KERNEL_CONSUMER_H */

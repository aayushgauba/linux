// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/iosys-map.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/tensor_native.h>
#include <linux/uaccess.h>

#include "tensor_kernel_consumer.h"

static long tensor_kernel_ioctl(struct file *file, unsigned int command,
				unsigned long argument)
{
	struct tensor_native_mapping *mapping;
	struct tensor_native_handle *handle;
	struct tensor_kernel_consume request;
	struct tensor_native_hdr tensor;
	const struct iosys_map *map;
	void __user *argp = (void __user *)argument;
	int ret;

	if (command != TENSOR_KERNEL_CONSUME)
		return -ENOTTY;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	handle = tensor_native_get(request.tensor_fd);
	if (IS_ERR(handle))
		return PTR_ERR(handle);
	ret = tensor_native_get_metadata(handle, &tensor);
	if (ret)
		goto put_handle;
	if (request.offset_bytes > tensor.data_bytes ||
	    sizeof(request.observed) > tensor.data_bytes - request.offset_bytes) {
		ret = -ERANGE;
		goto put_handle;
	}
	mapping = tensor_native_map(handle, request.access_flags);
	if (IS_ERR(mapping)) {
		ret = PTR_ERR(mapping);
		goto put_handle;
	}
	map = tensor_native_mapping_map(mapping);
	iosys_map_memcpy_from(&request.observed, map, request.offset_bytes,
			      sizeof(request.observed));
	tensor_native_unmap(mapping);
	if (request.observed != request.expected) {
		ret = -EILSEQ;
		goto copy_result;
	}
	request.sequence = tensor_native_signal(handle);
	ret = 0;

copy_result:
	if (copy_to_user(argp, &request, sizeof(request)))
		ret = -EFAULT;
put_handle:
	tensor_native_put(handle);
	return ret;
}

static const struct file_operations tensor_kernel_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tensor_kernel_ioctl,
	.compat_ioctl = tensor_kernel_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice tensor_kernel_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "tensor_kernel_consumer",
	.fops = &tensor_kernel_fops,
	.mode = 0600,
};

module_misc_device(tensor_kernel_device);

MODULE_DESCRIPTION("Kernel tensor API sample consumer");
MODULE_LICENSE("GPL");

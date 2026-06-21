// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../../include/uapi/linux/tensor_native.h"

int main(void)
{
	struct tensor_native_create create = {
		.dtype = TENSOR_NATIVE_DTYPE_U8,
		.ndim = 1,
		.shape = { 1 },
	};
	int tensors[2];
	int control;
	int index;

	control = open("/dev/tensor_native", O_RDWR | O_CLOEXEC);
	if (control < 0)
		return 1;
	for (index = 0; index < 2; index++) {
		if (ioctl(control, TENSOR_CREATE, &create) < 0)
			return 1;
		tensors[index] = create.fd;
	}
	errno = 0;
	if (!ioctl(control, TENSOR_CREATE, &create) || errno != EDQUOT)
		return 1;
	for (index = 0; index < 2; index++)
		close(tensors[index]);
	close(control);
	puts("tensor accounting quota enforced");
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../../include/uapi/linux/tensor_native.h"
#include "tensor_kernel_consumer.h"

static int send_fd(int socket_fd, int fd)
{
	char control[CMSG_SPACE(sizeof(fd))] = { 0 };
	char byte = 0;
	struct iovec iov = { .iov_base = &byte, .iov_len = sizeof(byte) };
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *header = CMSG_FIRSTHDR(&message);

	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(fd));
	memcpy(CMSG_DATA(header), &fd, sizeof(fd));
	return sendmsg(socket_fd, &message, 0) == 1 ? 0 : -1;
}

static int receive_fd(int socket_fd)
{
	char control[CMSG_SPACE(sizeof(int))] = { 0 };
	char byte;
	struct iovec iov = { .iov_base = &byte, .iov_len = sizeof(byte) };
	struct msghdr message = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control,
		.msg_controllen = sizeof(control),
	};
	struct cmsghdr *header;
	int fd;

	if (recvmsg(socket_fd, &message, 0) != 1)
		return -1;
	header = CMSG_FIRSTHDR(&message);
	if (!header || header->cmsg_level != SOL_SOCKET ||
	    header->cmsg_type != SCM_RIGHTS ||
	    header->cmsg_len != CMSG_LEN(sizeof(fd))) {
		errno = EPROTO;
		return -1;
	}
	memcpy(&fd, CMSG_DATA(header), sizeof(fd));
	return fd;
}

static int run_fd_receiver(int socket_fd)
{
	struct tensor_native_access access = { .flags = TENSOR_ACCESS_READ };
	struct tensor_native_info info;
	struct tensor_native_signal signal = { 0 };
	void *mapping;
	float *data;
	int fd;

	fd = receive_fd(socket_fd);
	if (fd < 0)
		return 1;
	if (ioctl(fd, TENSOR_GET_INFO, &info) < 0 ||
	    ioctl(fd, TENSOR_BEGIN_ACCESS, &access) < 0)
		return 1;
	mapping = mmap(NULL, info.tensor.data_offset + info.tensor.data_bytes,
		       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mapping == MAP_FAILED)
		return 1;
	data = mapping + info.tensor.data_offset;
	if (data[8] != 8.0f || ioctl(fd, TENSOR_END_ACCESS, &access) < 0 ||
	    ioctl(fd, TENSOR_SIGNAL, &signal) < 0)
		return 1;
	munmap(mapping, info.tensor.data_offset + info.tensor.data_bytes);
	close(fd);
	return 0;
}

int main(void)
{
	struct tensor_native_create create = {
		.dtype = TENSOR_NATIVE_DTYPE_F32,
		.ndim = 2,
		.shape = { 2, 8 },
	};
	struct tensor_native_clone_view view = {
		.offset_bytes = 8 * sizeof(float),
		.ndim = 1,
		.shape = { 4 },
	};
	struct tensor_native_dma_buf export = { .fd = -1 };
	struct tensor_native_access access = { .flags = TENSOR_ACCESS_READ };
	struct tensor_native_import_dma_buf import = {
		.dma_buf_fd = -1,
		.ndim = 2,
		.dtype = TENSOR_NATIVE_DTYPE_F32,
		.shape = { 2, 8 },
		.fd = -1,
	};
	struct tensor_native_info info;
	struct tensor_native_signal signal = { 0 };
	struct tensor_native_wait wait = { .sequence = 0, .timeout_ns = 0 };
	struct tensor_kernel_consume kernel_consume = {
		.access_flags = TENSOR_ACCESS_READ,
		.offset_bytes = 8 * sizeof(float),
	};
	struct pollfd pollfd;
	void *dma_mapping;
	void *import_mapping;
	void *view_mapping;
	float *dma_data;
	float *data;
	float *import_data;
	float *view_data;
	int control_fd;
	int consumer_fd;
	int sockets[2];
	int status;
	int ret;
	pid_t child;

	control_fd = open("/dev/tensor_native", O_RDWR | O_CLOEXEC);
	if (control_fd < 0) {
		perror("open /dev/tensor_native");
		return 1;
	}

	if (ioctl(control_fd, TENSOR_CREATE, &create) < 0) {
		perror("TENSOR_CREATE");
		return 1;
	}
	data = mmap(NULL, create.tensor.data_bytes, PROT_READ | PROT_WRITE,
		    MAP_SHARED, create.fd, 0);
	if (data == MAP_FAILED) {
		perror("mmap tensor");
		return 1;
	}

	for (size_t index = 0; index < 16; index++)
		data[index] = index;

	errno = 0;
	if (ioctl(create.fd, TENSOR_WAIT, &wait) == 0 || errno != EAGAIN) {
		fprintf(stderr, "nonblocking wait did not return EAGAIN\n");
		return 1;
	}

	if (ioctl(create.fd, TENSOR_SIGNAL, &signal) < 0) {
		perror("TENSOR_SIGNAL");
		return 1;
	}

	pollfd = (struct pollfd) { .fd = create.fd, .events = POLLIN };
	ret = poll(&pollfd, 1, 0);
	if (ret != 1 || !(pollfd.revents & POLLIN)) {
		fprintf(stderr, "signaled tensor was not pollable\n");
		return 1;
	}

	if (ioctl(create.fd, TENSOR_WAIT, &wait) < 0) {
		perror("TENSOR_WAIT");
		return 1;
	}
	if (wait.sequence != signal.sequence) {
		fprintf(stderr, "wait observed the wrong sequence\n");
		return 1;
	}

	memset(&info, 0, sizeof(info));
	if (ioctl(create.fd, TENSOR_GET_INFO, &info) < 0) {
		perror("TENSOR_GET_INFO");
		return 1;
	}
	if (info.sequence != signal.sequence ||
	    info.tensor.data_bytes != create.tensor.data_bytes) {
		fprintf(stderr, "tensor info mismatch\n");
		return 1;
	}

	if (ioctl(create.fd, TENSOR_CLONE_VIEW, &view) < 0) {
		perror("TENSOR_CLONE_VIEW");
		return 1;
	}
	view_mapping = mmap(NULL, view.tensor.data_offset + view.tensor.data_bytes,
			    PROT_READ | PROT_WRITE, MAP_SHARED, view.fd, 0);
	if (view_mapping == MAP_FAILED) {
		perror("mmap tensor view");
		return 1;
	}
	view_data = view_mapping + view.tensor.data_offset;
	for (size_t index = 0; index < 4; index++) {
		if (view_data[index] != data[index + 8]) {
			fprintf(stderr, "tensor view did not alias parent storage\n");
			return 1;
		}
	}

	signal.sequence = 0;
	if (ioctl(view.fd, TENSOR_SIGNAL, &signal) < 0) {
		perror("TENSOR_SIGNAL view");
		return 1;
	}
	wait.sequence = info.sequence;
	if (ioctl(create.fd, TENSOR_WAIT, &wait) < 0 ||
	    wait.sequence != signal.sequence) {
		perror("TENSOR_WAIT shared view sequence");
		return 1;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
		perror("socketpair");
		return 1;
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (!child) {
		close(sockets[0]);
		close(create.fd);
		_exit(run_fd_receiver(sockets[1]));
	}
	close(sockets[1]);
	if (send_fd(sockets[0], create.fd) < 0) {
		perror("sendmsg tensor fd");
		return 1;
	}
	wait.sequence = signal.sequence;
	wait.timeout_ns = -1;
	if (ioctl(create.fd, TENSOR_WAIT, &wait) < 0) {
		perror("TENSOR_WAIT cross-process");
		return 1;
	}
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status)) {
		fprintf(stderr, "SCM_RIGHTS tensor receiver failed\n");
		return 1;
	}
	close(sockets[0]);

	consumer_fd = open("/dev/tensor_kernel_consumer", O_RDWR | O_CLOEXEC);
	if (consumer_fd < 0) {
		perror("open /dev/tensor_kernel_consumer");
		return 1;
	}
	kernel_consume.tensor_fd = create.fd;
	memcpy(&kernel_consume.expected, &data[8], sizeof(kernel_consume.expected));
	if (ioctl(consumer_fd, TENSOR_KERNEL_CONSUME, &kernel_consume) < 0) {
		perror("TENSOR_KERNEL_CONSUME");
		return 1;
	}
	if (kernel_consume.observed != kernel_consume.expected ||
	    kernel_consume.sequence <= wait.sequence) {
		fprintf(stderr, "kernel tensor consumer result mismatch\n");
		return 1;
	}
	wait.sequence = kernel_consume.sequence;
	close(consumer_fd);

	if (ioctl(create.fd, TENSOR_EXPORT_DMABUF, &export) < 0) {
		perror("TENSOR_EXPORT_DMABUF");
		return 1;
	}
	dma_mapping = mmap(NULL, create.tensor.data_bytes,
			   PROT_READ | PROT_WRITE, MAP_SHARED, export.fd, 0);
	if (dma_mapping == MAP_FAILED) {
		perror("mmap dma-buf");
		return 1;
	}
	dma_data = dma_mapping;
	if (dma_data[8] != data[8]) {
		fprintf(stderr, "dma-buf export did not alias tensor storage\n");
		return 1;
	}

	import.dma_buf_fd = export.fd;
	if (ioctl(control_fd, TENSOR_IMPORT_DMABUF, &import) < 0) {
		perror("TENSOR_IMPORT_DMABUF");
		return 1;
	}
	import_mapping = mmap(NULL, import.tensor.data_bytes,
			      PROT_READ | PROT_WRITE, MAP_SHARED, import.fd, 0);
	if (import_mapping == MAP_FAILED) {
		perror("mmap imported tensor");
		return 1;
	}
	import_data = import_mapping + import.tensor.data_offset;
	if (ioctl(import.fd, TENSOR_BEGIN_ACCESS, &access) < 0) {
		perror("TENSOR_BEGIN_ACCESS");
		return 1;
	}
	if (import_data[8] != data[8]) {
		fprintf(stderr, "imported tensor did not alias dma-buf storage\n");
		return 1;
	}
	if (ioctl(import.fd, TENSOR_END_ACCESS, &access) < 0) {
		perror("TENSOR_END_ACCESS");
		return 1;
	}

	printf("tensor object fd=%d view=%d dma-buf=%d import=%d bytes=%llu sequence=%llu\n",
	       create.fd, view.fd, export.fd, import.fd,
	       (unsigned long long)create.tensor.data_bytes,
	       (unsigned long long)wait.sequence);
	munmap(import_mapping, import.tensor.data_bytes);
	munmap(dma_mapping, create.tensor.data_bytes);
	munmap(view_mapping, view.tensor.data_offset + view.tensor.data_bytes);
	munmap(data, create.tensor.data_bytes);
	close(import.fd);
	close(export.fd);
	close(view.fd);
	close(create.fd);
	close(control_fd);
	return 0;
}

// SPDX-License-Identifier: GPL-2.0
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/dma-buf.h>
#include <linux/dma-mapping.h>
#include <linux/dma-resv.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/iosys-map.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/refcount.h>
#include <linux/sched/user.h>
#include <linux/seq_file.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/tensor_native.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#define CREATE_TRACE_POINTS
#include <trace/events/tensor_native.h>

#define TENSOR_NATIVE_MAX_OBJECT_BYTES (64UL * 1024 * 1024)
#define TENSOR_NATIVE_MAX_TOTAL_BYTES (256UL * 1024 * 1024)
#define TENSOR_NATIVE_DEFAULT_UID_BYTES (128UL * 1024 * 1024)
#define TENSOR_NATIVE_DEFAULT_CGROUP_BYTES (256UL * 1024 * 1024)
#define TENSOR_NATIVE_ACCOUNT_BITS 6

#ifndef kzalloc_obj
#define kzalloc_obj(object, flags) kzalloc(sizeof(object), flags)
#endif

enum tensor_native_storage_type {
	TENSOR_STORAGE_VMALLOC,
	TENSOR_STORAGE_DMABUF,
};

struct tensor_native_storage {
	refcount_t refs;
	enum tensor_native_storage_type type;
	size_t bytes;
	size_t allocation_bytes;
	atomic64_t sequence;
	wait_queue_head_t waitq;
	struct dma_resv resv;
	kuid_t owner_uid;
	u64 cgroup_id;
	struct tensor_native_account *account;
	union {
		void *data;
		struct dma_buf *dmabuf;
	};
};

struct tensor_native_account {
	struct hlist_node node;
	struct cgroup *cgroup;
	kuid_t uid;
	size_t bytes;
	u64 objects;
};

struct tensor_native_object {
	struct tensor_native_hdr tensor;
	struct tensor_native_storage *storage;
	size_t storage_offset;
	size_t mapping_offset;
	size_t mapping_bytes;
};

struct tensor_native_file {
	struct tensor_native_object *object;
	u64 seen_sequence;
	/* Serializes begin/end access state for this file description. */
	struct mutex access_lock;
	enum dma_data_direction access_direction;
	bool access_active;
};

struct tensor_native_dma_export {
	struct tensor_native_storage *storage;
	size_t offset;
	size_t bytes;
};

struct tensor_native_handle {
	struct file *file;
	struct tensor_native_object *object;
};

struct tensor_native_mapping {
	struct file *file;
	struct tensor_native_object *object;
	struct iosys_map map;
	struct iosys_map dma_map;
	enum dma_data_direction direction;
	bool dmabuf_mapped;
};

static atomic_long_t tensor_native_total_bytes = ATOMIC_LONG_INIT(0);
static DEFINE_HASHTABLE(tensor_native_accounts, TENSOR_NATIVE_ACCOUNT_BITS);
static DEFINE_MUTEX(tensor_native_account_lock);
static unsigned long tensor_native_uid_limit_bytes =
	TENSOR_NATIVE_DEFAULT_UID_BYTES;
static unsigned long tensor_native_cgroup_limit_bytes =
	TENSOR_NATIVE_DEFAULT_CGROUP_BYTES;

module_param_named(uid_limit_bytes, tensor_native_uid_limit_bytes, ulong, 0644);
MODULE_PARM_DESC(uid_limit_bytes, "Maximum native tensor bytes per UID");
module_param_named(cgroup_limit_bytes, tensor_native_cgroup_limit_bytes,
		   ulong, 0644);
MODULE_PARM_DESC(cgroup_limit_bytes,
		 "Maximum native tensor bytes per default cgroup");

EXPORT_TRACEPOINT_SYMBOL_GPL(tensor_net_queue);
EXPORT_TRACEPOINT_SYMBOL_GPL(tensor_net_batch);
EXPORT_TRACEPOINT_SYMBOL_GPL(tensor_net_verdict);
EXPORT_TRACEPOINT_SYMBOL_GPL(tensor_net_timeout);

static struct tensor_native_account *
tensor_native_reserve_bytes(size_t bytes)
{
	struct tensor_native_account *new_account;
	struct tensor_native_account *account;
	struct tensor_native_account *matched = NULL;
	struct cgroup *cgroup;
	kuid_t uid = current_uid();
	size_t uid_bytes = 0;
	size_t cgroup_bytes = 0;
	u64 key;
	int bucket;

	new_account = kzalloc_obj(*new_account, GFP_KERNEL);
	if (!new_account)
		return ERR_PTR(-ENOMEM);
	cgroup = task_dfl_cgroup(current);
	cgroup_get(cgroup);
	key = hash_64(cgroup_id(cgroup) ^ __kuid_val(uid),
		      TENSOR_NATIVE_ACCOUNT_BITS);

	mutex_lock(&tensor_native_account_lock);
	hash_for_each(tensor_native_accounts, bucket, account, node) {
		if (uid_eq(account->uid, uid))
			uid_bytes += account->bytes;
		if (account->cgroup == cgroup)
			cgroup_bytes += account->bytes;
		if (account->cgroup == cgroup && uid_eq(account->uid, uid))
			matched = account;
	}
	if (bytes > TENSOR_NATIVE_MAX_TOTAL_BYTES ||
	    bytes > tensor_native_uid_limit_bytes ||
	    bytes > tensor_native_cgroup_limit_bytes ||
	    atomic_long_read(&tensor_native_total_bytes) >
		TENSOR_NATIVE_MAX_TOTAL_BYTES - bytes ||
	    uid_bytes > tensor_native_uid_limit_bytes - bytes ||
	    cgroup_bytes > tensor_native_cgroup_limit_bytes - bytes) {
		mutex_unlock(&tensor_native_account_lock);
		kfree(new_account);
		cgroup_put(cgroup);
		return ERR_PTR(-EDQUOT);
	}
	if (!matched) {
		account = new_account;
		account->cgroup = cgroup;
		account->uid = uid;
		hash_add(tensor_native_accounts, &account->node, key);
	} else {
		account = matched;
		kfree(new_account);
		cgroup_put(cgroup);
	}
	account->bytes += bytes;
	account->objects++;
	atomic_long_add(bytes, &tensor_native_total_bytes);
	mutex_unlock(&tensor_native_account_lock);
	return account;
}

static void tensor_native_release_bytes(struct tensor_native_account *account,
					size_t bytes)
{
	struct cgroup *cgroup = NULL;

	mutex_lock(&tensor_native_account_lock);
	account->bytes -= bytes;
	account->objects--;
	atomic_long_sub(bytes, &tensor_native_total_bytes);
	if (!account->objects) {
		hash_del(&account->node);
		cgroup = account->cgroup;
		kfree(account);
	}
	mutex_unlock(&tensor_native_account_lock);
	if (cgroup)
		cgroup_put(cgroup);
}

static void tensor_native_storage_get(struct tensor_native_storage *storage)
{
	refcount_inc(&storage->refs);
}

static void tensor_native_storage_put(struct tensor_native_storage *storage)
{
	if (!refcount_dec_and_test(&storage->refs))
		return;

	if (storage->type == TENSOR_STORAGE_VMALLOC) {
		dma_resv_fini(&storage->resv);
		tensor_native_release_bytes(storage->account,
					    storage->allocation_bytes);
		vfree(storage->data);
	} else {
		dma_buf_put(storage->dmabuf);
	}
	kfree(storage);
}

static bool has_new_seq(struct tensor_native_storage *storage, u64 seq)
{
	return atomic64_read(&storage->sequence) > seq;
}

static int tensor_native_init_layout(struct tensor_native_hdr *tensor,
				     u32 dtype, u16 ndim, const u64 *shape,
				     const u64 *stride_bytes, u64 data_offset)
{
	u64 element_bytes = tensor_native_dtype_size(dtype);
	u64 extent;
	u64 span;
	bool explicit_strides = false;
	int dim;

	if (!element_bytes || !ndim || ndim > TENSOR_NATIVE_MAX_DIMS)
		return -EINVAL;

	for (dim = 0; dim < ndim; dim++)
		explicit_strides |= stride_bytes && stride_bytes[dim];

	if (!explicit_strides)
		return tensor_native_init_contiguous(tensor, dtype, ndim, shape,
						     data_offset);

	memset(tensor, 0, sizeof(*tensor));
	tensor->magic = TENSOR_NATIVE_MAGIC;
	tensor->version = TENSOR_NATIVE_VERSION;
	tensor->ndim = ndim;
	tensor->dtype = dtype;
	tensor->data_offset = data_offset;
	extent = element_bytes;

	for (dim = 0; dim < ndim; dim++) {
		if (!shape[dim] || stride_bytes[dim] < element_bytes)
			return -EINVAL;
		if (check_mul_overflow(shape[dim] - 1, stride_bytes[dim], &span) ||
		    check_add_overflow(extent, span, &extent))
			return -EOVERFLOW;
		tensor->shape[dim] = shape[dim];
		tensor->stride_bytes[dim] = stride_bytes[dim];
	}
	tensor->data_bytes = extent;
	return 0;
}

static struct tensor_native_object *
tensor_native_object_alloc(struct tensor_native_storage *storage,
			   size_t storage_offset,
			   const struct tensor_native_hdr *layout)
{
	struct tensor_native_object *object;
	size_t prefix;

	object = kzalloc_obj(*object, GFP_KERNEL);
	if (!object)
		return ERR_PTR(-ENOMEM);

	object->storage = storage;
	object->storage_offset = storage_offset;
	object->mapping_offset = round_down(storage_offset, PAGE_SIZE);
	prefix = storage_offset - object->mapping_offset;
	object->mapping_bytes = PAGE_ALIGN(prefix + layout->data_bytes);
	if (storage_offset > storage->bytes ||
	    layout->data_bytes > storage->bytes - storage_offset ||
	    object->mapping_offset > storage->allocation_bytes ||
	    object->mapping_bytes > storage->allocation_bytes -
				    object->mapping_offset) {
		kfree(object);
		return ERR_PTR(-EINVAL);
	}

	object->tensor = *layout;
	object->tensor.data_offset = prefix;
	tensor_native_storage_get(storage);
	return object;
}

static int tensor_native_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct tensor_native_file *tensor_file = file->private_data;
	struct tensor_native_object *object = tensor_file->object;
	struct tensor_native_storage *storage = object->storage;
	unsigned long offset;
	unsigned long length = vma->vm_end - vma->vm_start;
	pgoff_t storage_pgoff;

	if (vma->vm_pgoff > ULONG_MAX >> PAGE_SHIFT)
		return -EINVAL;
	offset = vma->vm_pgoff << PAGE_SHIFT;
	if (offset > object->mapping_bytes ||
	    length > object->mapping_bytes - offset)
		return -EINVAL;

	storage_pgoff = (object->mapping_offset >> PAGE_SHIFT) + vma->vm_pgoff;
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
	if (storage->type == TENSOR_STORAGE_VMALLOC)
		return remap_vmalloc_range(vma, storage->data, storage_pgoff);
	return dma_buf_mmap(storage->dmabuf, vma, storage_pgoff);
}

static __poll_t tensor_native_poll(struct file *file, poll_table *wait)
{
	struct tensor_native_file *tensor_file = file->private_data;
	struct tensor_native_storage *storage = tensor_file->object->storage;

	poll_wait(file, &storage->waitq, wait);
	if (atomic64_read(&storage->sequence) != tensor_file->seen_sequence)
		return EPOLLIN | EPOLLRDNORM;
	return 0;
}

static long tensor_native_get_info(struct tensor_native_file *tensor_file,
				   void __user *argp)
{
	struct tensor_native_info info = {
		.tensor = tensor_file->object->tensor,
		.sequence = atomic64_read(&tensor_file->object->storage->sequence),
	};

	return copy_to_user(argp, &info, sizeof(info)) ? -EFAULT : 0;
}

static long tensor_native_ioctl_signal(struct tensor_native_file *tensor_file,
				       void __user *argp)
{
	struct tensor_native_storage *storage = tensor_file->object->storage;
	struct tensor_native_signal signal;
	u64 current_seq;
	u64 previous;

	if (copy_from_user(&signal, argp, sizeof(signal)))
		return -EFAULT;

	if (!signal.sequence) {
		signal.sequence = atomic64_inc_return(&storage->sequence);
	} else {
		current_seq = atomic64_read(&storage->sequence);
		for (;;) {
			if (signal.sequence <= current_seq)
				return -EINVAL;
			previous = atomic64_cmpxchg(&storage->sequence, current_seq,
						    signal.sequence);
			if (previous == current_seq)
				break;
			current_seq = previous;
		}
	}

	wake_up_interruptible_poll(&storage->waitq, EPOLLIN | EPOLLRDNORM);
	trace_tensor_signal(storage, signal.sequence, TENSOR_TRACE_SIGNAL_USER);
	return copy_to_user(argp, &signal, sizeof(signal)) ? -EFAULT : 0;
}

static long tensor_native_wait(struct tensor_native_file *tensor_file,
			       void __user *argp)
{
	struct tensor_native_storage *storage = tensor_file->object->storage;
	struct tensor_native_wait wait;
	u64 sequence;
	long timeout;
	long ret;

	if (copy_from_user(&wait, argp, sizeof(wait)))
		return -EFAULT;
	sequence = wait.sequence;

	if (atomic64_read(&storage->sequence) <= sequence) {
		if (!wait.timeout_ns)
			return -EAGAIN;
		if (wait.timeout_ns < 0) {
			ret = wait_event_interruptible(storage->waitq,
						       has_new_seq(storage, sequence));
			if (ret)
				return ret;
		} else {
			timeout = nsecs_to_jiffies(wait.timeout_ns);
			if (!timeout)
				timeout = 1;
			ret = wait_event_interruptible_timeout(storage->waitq,
							       has_new_seq(storage, sequence),
						       timeout);
			if (ret < 0)
				return ret;
			if (!ret)
				return -ETIMEDOUT;
		}
	}

	wait.sequence = atomic64_read(&storage->sequence);
	tensor_file->seen_sequence = wait.sequence;
	return copy_to_user(argp, &wait, sizeof(wait)) ? -EFAULT : 0;
}

static int tensor_access_dir(u32 flags, enum dma_data_direction *direction)
{
	switch (flags) {
	case TENSOR_ACCESS_READ:
		*direction = DMA_FROM_DEVICE;
		return 0;
	case TENSOR_ACCESS_WRITE:
		*direction = DMA_TO_DEVICE;
		return 0;
	case TENSOR_ACCESS_READ | TENSOR_ACCESS_WRITE:
		*direction = DMA_BIDIRECTIONAL;
		return 0;
	default:
		return -EINVAL;
	}
}

static int tensor_storage_begin_access(struct tensor_native_storage *storage,
				       enum dma_data_direction direction)
{
	bool write;
	enum dma_resv_usage usage;
	long ret;

	if (storage->type == TENSOR_STORAGE_DMABUF)
		return dma_buf_begin_cpu_access(storage->dmabuf, direction);

	write = direction != DMA_FROM_DEVICE;
	usage = dma_resv_usage_rw(write);
	ret = dma_resv_wait_timeout(&storage->resv, usage, true,
				    MAX_SCHEDULE_TIMEOUT);
	return ret < 0 ? ret : 0;
}

static int tensor_storage_end_access(struct tensor_native_storage *storage,
				     enum dma_data_direction direction)
{
	if (storage->type == TENSOR_STORAGE_DMABUF)
		return dma_buf_end_cpu_access(storage->dmabuf, direction);
	return 0;
}

static long tensor_native_begin_access(struct tensor_native_file *tensor_file,
				       void __user *argp)
{
	struct tensor_native_storage *storage = tensor_file->object->storage;
	struct tensor_native_access access;
	enum dma_data_direction direction;
	int ret;

	if (copy_from_user(&access, argp, sizeof(access)))
		return -EFAULT;
	if (access.reserved)
		return -EINVAL;
	ret = tensor_access_dir(access.flags, &direction);
	if (ret)
		return ret;

	mutex_lock(&tensor_file->access_lock);
	if (tensor_file->access_active) {
		ret = -EBUSY;
		goto unlock;
	}
	ret = tensor_storage_begin_access(storage, direction);
	if (ret)
		goto unlock;
	tensor_file->access_direction = direction;
	tensor_file->access_active = true;
unlock:
	mutex_unlock(&tensor_file->access_lock);
	return ret;
}

static long tensor_native_end_access(struct tensor_native_file *tensor_file,
				     void __user *argp)
{
	struct tensor_native_storage *storage = tensor_file->object->storage;
	struct tensor_native_access access;
	enum dma_data_direction direction;
	int ret;

	if (copy_from_user(&access, argp, sizeof(access)))
		return -EFAULT;
	if (access.reserved)
		return -EINVAL;
	ret = tensor_access_dir(access.flags, &direction);
	if (ret)
		return ret;

	mutex_lock(&tensor_file->access_lock);
	if (!tensor_file->access_active ||
	    tensor_file->access_direction != direction) {
		ret = -EINVAL;
		goto unlock;
	}
	ret = tensor_storage_end_access(storage, direction);
	if (!ret)
		tensor_file->access_active = false;
unlock:
	mutex_unlock(&tensor_file->access_lock);
	return ret;
}

static int tensor_native_prepare_fd(struct tensor_native_object *object,
				    struct file **filep);

static struct sg_table *
tensor_native_dma_map(struct dma_buf_attachment *attachment,
		      enum dma_data_direction direction)
{
	struct tensor_native_dma_export *export = attachment->dmabuf->priv;
	struct sg_table *table;
	struct page **pages;
	size_t page_count = export->bytes >> PAGE_SHIFT;
	size_t index;
	int ret;

	pages = kcalloc(page_count, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);
	for (index = 0; index < page_count; index++)
		pages[index] = vmalloc_to_page(export->storage->data +
					       export->offset + index * PAGE_SIZE);

	table = kzalloc_obj(*table, GFP_KERNEL);
	if (!table) {
		ret = -ENOMEM;
		goto free_pages;
	}
	ret = sg_alloc_table_from_pages(table, pages, page_count, 0,
					export->bytes, GFP_KERNEL);
	if (ret)
		goto free_table;
	ret = dma_map_sgtable(attachment->dev, table, direction, 0);
	if (ret)
		goto free_sg;
	kfree(pages);
	return table;

free_sg:
	sg_free_table(table);
free_table:
	kfree(table);
free_pages:
	kfree(pages);
	return ERR_PTR(ret);
}

static void tensor_native_dma_unmap(struct dma_buf_attachment *attachment,
				    struct sg_table *table,
				    enum dma_data_direction direction)
{
	dma_unmap_sgtable(attachment->dev, table, direction, 0);
	sg_free_table(table);
	kfree(table);
}

static int tensor_native_dma_mmap(struct dma_buf *dmabuf,
				  struct vm_area_struct *vma)
{
	struct tensor_native_dma_export *export = dmabuf->priv;
	unsigned long offset;
	unsigned long length = vma->vm_end - vma->vm_start;

	if (vma->vm_pgoff > ULONG_MAX >> PAGE_SHIFT)
		return -EINVAL;
	offset = vma->vm_pgoff << PAGE_SHIFT;
	if (offset > export->bytes || length > export->bytes - offset)
		return -EINVAL;
	return remap_vmalloc_range(vma, export->storage->data,
				   (export->offset >> PAGE_SHIFT) + vma->vm_pgoff);
}

static int tensor_native_dma_vmap(struct dma_buf *dmabuf,
				  struct iosys_map *map)
{
	struct tensor_native_dma_export *export = dmabuf->priv;

	iosys_map_set_vaddr(map, export->storage->data + export->offset);
	return 0;
}

static void tensor_native_dma_vunmap(struct dma_buf *dmabuf,
				     struct iosys_map *map)
{
	iosys_map_clear(map);
}

static void tensor_native_dma_release(struct dma_buf *dmabuf)
{
	struct tensor_native_dma_export *export = dmabuf->priv;

	tensor_native_storage_put(export->storage);
	kfree(export);
}

static const struct dma_buf_ops tensor_native_dma_ops = {
	.map_dma_buf = tensor_native_dma_map,
	.unmap_dma_buf = tensor_native_dma_unmap,
	.mmap = tensor_native_dma_mmap,
	.vmap = tensor_native_dma_vmap,
	.vunmap = tensor_native_dma_vunmap,
	.release = tensor_native_dma_release,
};

static long tensor_native_export_dmabuf(struct tensor_native_file *tensor_file,
					void __user *argp)
{
	struct tensor_native_object *object = tensor_file->object;
	struct tensor_native_dma_export *export;
	struct tensor_native_dma_buf request;
	DEFINE_DMA_BUF_EXPORT_INFO(info);
	struct dma_buf *dmabuf;
	int fd;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || object->storage->type != TENSOR_STORAGE_VMALLOC)
		return -EINVAL;

	export = kzalloc_obj(*export, GFP_KERNEL);
	if (!export)
		return -ENOMEM;
	export->storage = object->storage;
	export->offset = object->mapping_offset;
	export->bytes = object->mapping_bytes;
	tensor_native_storage_get(export->storage);

	info.ops = &tensor_native_dma_ops;
	info.size = export->bytes;
	info.flags = O_RDWR;
	info.resv = &object->storage->resv;
	info.priv = export;
	dmabuf = dma_buf_export(&info);
	if (IS_ERR(dmabuf)) {
		tensor_native_storage_put(export->storage);
		kfree(export);
		return PTR_ERR(dmabuf);
	}

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0) {
		dma_buf_put(dmabuf);
		return fd;
	}
	request.fd = fd;
	if (copy_to_user(argp, &request, sizeof(request))) {
		close_fd(fd);
		return -EFAULT;
	}
	return 0;
}

static long tensor_native_clone_view(struct tensor_native_file *tensor_file,
				     void __user *argp)
{
	struct tensor_native_object *parent = tensor_file->object;
	struct tensor_native_clone_view view;
	struct tensor_native_object *object;
	struct tensor_native_hdr layout;
	struct file *file;
	size_t storage_offset;
	int fd;
	int ret;

	if (copy_from_user(&view, argp, sizeof(view)))
		return -EFAULT;
	if (view.flags || view.reserved || view.reserved2 ||
	    view.offset_bytes > parent->tensor.data_bytes ||
	    view.offset_bytes % tensor_native_dtype_size(parent->tensor.dtype))
		return -EINVAL;

	ret = tensor_native_init_layout(&layout, parent->tensor.dtype, view.ndim,
					view.shape, view.stride_bytes, 0);
	if (ret)
		return ret;
	if (layout.data_bytes > parent->tensor.data_bytes - view.offset_bytes)
		return -EINVAL;
	if (check_add_overflow(parent->storage_offset, view.offset_bytes,
			       &storage_offset))
		return -EOVERFLOW;

	object = tensor_native_object_alloc(parent->storage, storage_offset, &layout);
	if (IS_ERR(object))
		return PTR_ERR(object);
	fd = tensor_native_prepare_fd(object, &file);
	if (fd < 0) {
		tensor_native_storage_put(object->storage);
		kfree(object);
		return fd;
	}
	view.fd = fd;
	view.tensor = object->tensor;
	if (copy_to_user(argp, &view, sizeof(view))) {
		put_unused_fd(fd);
		fput(file);
		return -EFAULT;
	}
	fd_install(fd, file);
	trace_tensor_object_create(object, object->storage, object->tensor.dtype,
				   object->tensor.ndim,
				   object->tensor.data_bytes,
				   TENSOR_TRACE_CREATE_VIEW);
	return 0;
}

static long tensor_native_object_ioctl(struct file *file, unsigned int cmd,
				       unsigned long arg);
static int tensor_native_object_release(struct inode *inode, struct file *file);

static const struct file_operations tensor_native_object_fops = {
	.owner = THIS_MODULE,
	.mmap = tensor_native_mmap,
	.poll = tensor_native_poll,
	.unlocked_ioctl = tensor_native_object_ioctl,
	.compat_ioctl = tensor_native_object_ioctl,
	.release = tensor_native_object_release,
	.llseek = noop_llseek,
};

struct tensor_native_handle *tensor_native_get(int fd)
{
	struct tensor_native_handle *handle;
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &tensor_native_object_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	handle = kzalloc_obj(*handle, GFP_KERNEL);
	if (!handle) {
		fput(file);
		return ERR_PTR(-ENOMEM);
	}
	handle->file = file;
	handle->object = ((struct tensor_native_file *)file->private_data)->object;
	return handle;
}
EXPORT_SYMBOL_GPL(tensor_native_get);

void tensor_native_put(struct tensor_native_handle *handle)
{
	if (!handle)
		return;
	fput(handle->file);
	kfree(handle);
}
EXPORT_SYMBOL_GPL(tensor_native_put);

int tensor_native_get_metadata(struct tensor_native_handle *handle,
			       struct tensor_native_hdr *tensor)
{
	if (!handle || !tensor)
		return -EINVAL;
	*tensor = handle->object->tensor;
	return 0;
}
EXPORT_SYMBOL_GPL(tensor_native_get_metadata);

struct tensor_native_mapping *
tensor_native_map(struct tensor_native_handle *handle, u32 access_flags)
{
	struct tensor_native_object *object;
	struct tensor_native_storage *storage;
	struct tensor_native_mapping *mapping;
	enum dma_data_direction direction;
	int ret;

	if (!handle)
		return ERR_PTR(-EINVAL);
	ret = tensor_access_dir(access_flags, &direction);
	if (ret)
		return ERR_PTR(ret);
	object = handle->object;
	storage = object->storage;
	mapping = kzalloc_obj(*mapping, GFP_KERNEL);
	if (!mapping)
		return ERR_PTR(-ENOMEM);
	ret = tensor_storage_begin_access(storage, direction);
	if (ret)
		goto free_mapping;

	mapping->file = handle->file;
	get_file(mapping->file);
	mapping->object = object;
	mapping->direction = direction;
	if (storage->type == TENSOR_STORAGE_DMABUF) {
		ret = dma_buf_vmap(storage->dmabuf, &mapping->dma_map);
		if (ret)
			goto end_access;
		mapping->dmabuf_mapped = true;
		mapping->map = mapping->dma_map;
		iosys_map_incr(&mapping->map, object->storage_offset);
	} else {
		iosys_map_set_vaddr(&mapping->map,
				    storage->data + object->storage_offset);
	}
	return mapping;

end_access:
	tensor_storage_end_access(storage, direction);
	fput(mapping->file);
free_mapping:
	kfree(mapping);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(tensor_native_map);

const struct iosys_map *
tensor_native_mapping_map(struct tensor_native_mapping *mapping)
{
	return mapping ? &mapping->map : NULL;
}
EXPORT_SYMBOL_GPL(tensor_native_mapping_map);

void tensor_native_unmap(struct tensor_native_mapping *mapping)
{
	struct tensor_native_storage *storage;

	if (!mapping)
		return;
	storage = mapping->object->storage;
	if (mapping->dmabuf_mapped)
		dma_buf_vunmap(storage->dmabuf, &mapping->dma_map);
	tensor_storage_end_access(storage, mapping->direction);
	fput(mapping->file);
	kfree(mapping);
}
EXPORT_SYMBOL_GPL(tensor_native_unmap);

u64 tensor_native_signal(struct tensor_native_handle *handle)
{
	struct tensor_native_storage *storage;
	u64 sequence;

	if (!handle)
		return 0;
	storage = handle->object->storage;
	sequence = atomic64_inc_return(&storage->sequence);
	wake_up_interruptible_poll(&storage->waitq, EPOLLIN | EPOLLRDNORM);
	trace_tensor_signal(storage, sequence, TENSOR_TRACE_SIGNAL_KERNEL);
	return sequence;
}
EXPORT_SYMBOL_GPL(tensor_native_signal);

static long tensor_native_object_ioctl(struct file *file, unsigned int cmd,
				       unsigned long arg)
{
	struct tensor_native_file *tensor_file = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case TENSOR_GET_INFO:
		return tensor_native_get_info(tensor_file, argp);
	case TENSOR_SIGNAL:
		return tensor_native_ioctl_signal(tensor_file, argp);
	case TENSOR_WAIT:
		return tensor_native_wait(tensor_file, argp);
	case TENSOR_CLONE_VIEW:
		return tensor_native_clone_view(tensor_file, argp);
	case TENSOR_EXPORT_DMABUF:
		return tensor_native_export_dmabuf(tensor_file, argp);
	case TENSOR_BEGIN_ACCESS:
		return tensor_native_begin_access(tensor_file, argp);
	case TENSOR_END_ACCESS:
		return tensor_native_end_access(tensor_file, argp);
	default:
		return -ENOTTY;
	}
}

static int tensor_native_object_release(struct inode *inode, struct file *file)
{
	struct tensor_native_file *tensor_file = file->private_data;
	struct tensor_native_object *object = tensor_file->object;
	struct tensor_native_storage *storage = object->storage;

	if (tensor_file->access_active && storage->type == TENSOR_STORAGE_DMABUF)
		dma_buf_end_cpu_access(storage->dmabuf,
				       tensor_file->access_direction);

	trace_tensor_object_release(object, storage, object->tensor.data_bytes);
	tensor_native_storage_put(storage);
	kfree(object);
	kfree(tensor_file);
	return 0;
}

static int tensor_native_prepare_fd(struct tensor_native_object *object,
				    struct file **filep)
{
	struct tensor_native_file *tensor_file;
	struct file *file;
	int fd;
	int ret;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	tensor_file = kzalloc_obj(*tensor_file, GFP_KERNEL);
	if (!tensor_file) {
		ret = -ENOMEM;
		goto put_fd;
	}
	tensor_file->object = object;
	mutex_init(&tensor_file->access_lock);
	file = anon_inode_getfile("[tensor_native]", &tensor_native_object_fops,
				  tensor_file, O_RDWR);
	if (IS_ERR(file)) {
		ret = PTR_ERR(file);
		kfree(tensor_file);
		goto put_fd;
	}
	*filep = file;
	return fd;

put_fd:
	put_unused_fd(fd);
	return ret;
}

static struct tensor_native_storage *tensor_native_vmalloc_storage(size_t bytes)
{
	struct tensor_native_account *account;
	struct tensor_native_storage *storage;
	size_t allocation_bytes = PAGE_ALIGN(bytes);

	account = tensor_native_reserve_bytes(allocation_bytes);
	if (IS_ERR(account))
		return ERR_CAST(account);
	storage = kzalloc_obj(*storage, GFP_KERNEL);
	if (!storage) {
		tensor_native_release_bytes(account, allocation_bytes);
		return ERR_PTR(-ENOMEM);
	}
	storage->data = vmalloc_user(allocation_bytes);
	if (!storage->data) {
		kfree(storage);
		tensor_native_release_bytes(account, allocation_bytes);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&storage->refs, 1);
	storage->type = TENSOR_STORAGE_VMALLOC;
	storage->bytes = bytes;
	storage->allocation_bytes = allocation_bytes;
	storage->owner_uid = current_uid();
	storage->cgroup_id = cgroup_id(account->cgroup);
	storage->account = account;
	dma_resv_init(&storage->resv);
	atomic64_set(&storage->sequence, 0);
	init_waitqueue_head(&storage->waitq);
	return storage;
}

static struct tensor_native_storage *tensor_native_dmabuf_storage(int fd)
{
	struct tensor_native_storage *storage;
	struct dma_buf *dmabuf;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);
	if (!dmabuf->size || dmabuf->size > SIZE_MAX - (PAGE_SIZE - 1)) {
		dma_buf_put(dmabuf);
		return ERR_PTR(-E2BIG);
	}
	storage = kzalloc_obj(*storage, GFP_KERNEL);
	if (!storage) {
		dma_buf_put(dmabuf);
		return ERR_PTR(-ENOMEM);
	}
	refcount_set(&storage->refs, 1);
	storage->type = TENSOR_STORAGE_DMABUF;
	storage->bytes = dmabuf->size;
	storage->allocation_bytes = PAGE_ALIGN(dmabuf->size);
	storage->owner_uid = current_uid();
	storage->cgroup_id = cgroup_id(task_dfl_cgroup(current));
	storage->dmabuf = dmabuf;
	atomic64_set(&storage->sequence, 0);
	init_waitqueue_head(&storage->waitq);
	return storage;
}

static long tensor_native_create(void __user *argp)
{
	struct tensor_native_storage *storage;
	struct tensor_native_object *object;
	struct tensor_native_create create;
	struct tensor_native_hdr layout;
	struct file *file;
	int fd;
	int ret;

	if (copy_from_user(&create, argp, sizeof(create)))
		return -EFAULT;
	if (create.flags || create.reserved)
		return -EINVAL;
	ret = tensor_native_init_layout(&layout, create.dtype, create.ndim,
					create.shape, NULL, 0);
	if (ret)
		return ret;
	if (layout.data_bytes > TENSOR_NATIVE_MAX_OBJECT_BYTES)
		return -E2BIG;
	storage = tensor_native_vmalloc_storage(layout.data_bytes);
	if (IS_ERR(storage))
		return PTR_ERR(storage);
	object = tensor_native_object_alloc(storage, 0, &layout);
	tensor_native_storage_put(storage);
	if (IS_ERR(object))
		return PTR_ERR(object);
	fd = tensor_native_prepare_fd(object, &file);
	if (fd < 0) {
		tensor_native_storage_put(object->storage);
		kfree(object);
		return fd;
	}
	create.fd = fd;
	create.tensor = object->tensor;
	if (copy_to_user(argp, &create, sizeof(create))) {
		put_unused_fd(fd);
		fput(file);
		return -EFAULT;
	}
	fd_install(fd, file);
	trace_tensor_object_create(object, object->storage, object->tensor.dtype,
				   object->tensor.ndim,
				   object->tensor.data_bytes,
				   TENSOR_TRACE_CREATE_NATIVE);
	return 0;
}

static long tensor_native_import_dmabuf(void __user *argp)
{
	struct tensor_native_import_dma_buf import;
	struct tensor_native_storage *storage;
	struct tensor_native_object *object;
	struct tensor_native_hdr layout;
	struct file *file;
	int fd;
	int ret;

	if (copy_from_user(&import, argp, sizeof(import)))
		return -EFAULT;
	if (import.flags || import.reserved || import.reserved2)
		return -EINVAL;
	storage = tensor_native_dmabuf_storage(import.dma_buf_fd);
	if (IS_ERR(storage))
		return PTR_ERR(storage);
	ret = tensor_native_init_layout(&layout, import.dtype, import.ndim,
					import.shape, import.stride_bytes, 0);
	if (ret || layout.data_bytes > TENSOR_NATIVE_MAX_OBJECT_BYTES ||
	    layout.data_bytes > storage->bytes) {
		if (!ret)
			ret = -EINVAL;
		goto put_storage;
	}
	object = tensor_native_object_alloc(storage, 0, &layout);
	if (IS_ERR(object)) {
		ret = PTR_ERR(object);
		goto put_storage;
	}
	tensor_native_storage_put(storage);
	fd = tensor_native_prepare_fd(object, &file);
	if (fd < 0) {
		tensor_native_storage_put(object->storage);
		kfree(object);
		return fd;
	}
	import.fd = fd;
	import.tensor = object->tensor;
	if (copy_to_user(argp, &import, sizeof(import))) {
		put_unused_fd(fd);
		fput(file);
		return -EFAULT;
	}
	fd_install(fd, file);
	trace_tensor_object_create(object, object->storage, object->tensor.dtype,
				   object->tensor.ndim,
				   object->tensor.data_bytes,
				   TENSOR_TRACE_CREATE_DMABUF);
	return 0;

put_storage:
	tensor_native_storage_put(storage);
	return ret;
}

static long tensor_native_control_ioctl(struct file *file, unsigned int cmd,
					unsigned long arg)
{
	switch (cmd) {
	case TENSOR_CREATE:
		return tensor_native_create((void __user *)arg);
	case TENSOR_IMPORT_DMABUF:
		return tensor_native_import_dmabuf((void __user *)arg);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations tensor_native_control_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = tensor_native_control_ioctl,
	.compat_ioctl = tensor_native_control_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice tensor_native_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "tensor_native",
	.fops = &tensor_native_control_fops,
	.mode = 0600,
};

static int tensor_native_accounting_show(struct seq_file *seq, void *unused)
{
	struct tensor_native_account *account;
	int bucket;

	seq_printf(seq, "total_bytes %ld\n",
		   atomic_long_read(&tensor_native_total_bytes));
	seq_printf(seq, "uid_limit_bytes %lu\n", tensor_native_uid_limit_bytes);
	seq_printf(seq, "cgroup_limit_bytes %lu\n",
		   tensor_native_cgroup_limit_bytes);
	seq_puts(seq, "uid cgroup_id objects bytes\n");
	mutex_lock(&tensor_native_account_lock);
	hash_for_each(tensor_native_accounts, bucket, account, node)
		seq_printf(seq, "%u %llu %llu %zu\n",
			   from_kuid_munged(current_user_ns(), account->uid),
			   cgroup_id(account->cgroup), account->objects,
			   account->bytes);
	mutex_unlock(&tensor_native_account_lock);
	return 0;
}

static int __init tensor_native_init(void)
{
	int ret;

	ret = misc_register(&tensor_native_miscdev);
	if (ret)
		return ret;
	if (!proc_create_single("tensor_native_accounting", 0444, NULL,
				tensor_native_accounting_show)) {
		misc_deregister(&tensor_native_miscdev);
		return -ENOMEM;
	}
	return 0;
}

static void __exit tensor_native_exit(void)
{
	remove_proc_entry("tensor_native_accounting", NULL);
	misc_deregister(&tensor_native_miscdev);
}

module_init(tensor_native_init);
module_exit(tensor_native_exit);

MODULE_DESCRIPTION("Kernel-managed tensor objects");
MODULE_IMPORT_NS(DMA_BUF);
MODULE_LICENSE("GPL");

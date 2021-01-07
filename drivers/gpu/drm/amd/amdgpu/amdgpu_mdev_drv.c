#include <drm/amdgpu_drm.h>
#include <drm/drm_drv.h>
#include <drm/drm_gem.h>
#include <drm/drm_vblank.h>
#include "amdgpu_drv.h"

#include <drm/drm_pciids.h>
#include <linux/console.h>
#include <linux/kfifo.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/vga_switcheroo.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_gem_vram_helper.h>
#include <drm/drm_managed.h>
#include <linux/mmu_notifier.h>

#include "amdgpu.h"
#include "amdgpu_mdev_common.h"

#define KMS_DRIVER_MAJOR	3
#define KMS_DRIVER_MINOR	40
#define KMS_DRIVER_PATCHLEVEL	0

#define IOCTL_TIMEOUT		msecs_to_jiffies(200)
struct amdgpu_mdev {
	void  *bar0_base;
	u32 bar2_size;
	u32    *mmio;
	wait_queue_head_t ioctl_wait;
	struct kfifo ioctl_reqs;
	DECLARE_HASHTABLE(offset_htable, 16);
};

struct offset_key {
	struct hlist_node hnode;
	uint32_t local_handle;
	uint32_t remote_handle;


};


struct amdgpu_mdev amdgpu_dev_mdev;

static void amdgpu_mdev_ring_doorbell(void)
{
	writew(1, amdgpu_dev_mdev.mmio);
}

static vm_fault_t amdgpu_mdev_drm_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	//struct amdgpu_mdev *mdev = vma->vm_private_data;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

	printk("mmap vm_address %lu start %lu offset %lu\n", vmf->address, vma->vm_start, page_offset);


	return VM_FAULT_SIGSEGV;
}

static const struct vm_operations_struct amdgpu_mdev_drm_vm_ops = {
	.fault = amdgpu_mdev_drm_vm_fault,
};

int amdgpu_mdev_open_kms(struct drm_device *dev, struct drm_file *file_priv)
{
	struct guest_ioctl cmd;
	int ret;

	cmd.id =  pid_nr(get_task_pid(current, PIDTYPE_PID));
	cmd.cmd = AMDGPU_GUEST_CMD_OPEN_KMS;
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	cmd.ioctl_completed = false;
	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");


	return 0;
}
//amdgpu_mmap()
static int amdgpu_mdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct drm_file *file = filp->private_data;

	printk("mmap vm_start %lu offset %lu\n", vma->vm_start, vma->vm_pgoff);
	vma->vm_ops = &amdgpu_mdev_drm_vm_ops;
	//vma->vm_private_data = mdev_state;
	return 0;
}
static const struct file_operations amdgpu_mdev_kms_fops = {
	.owner		= THIS_MODULE,
	.open		= drm_open,
	.release	= drm_release,
	.unlocked_ioctl	= drm_ioctl,
	.compat_ioctl	= drm_compat_ioctl,
	.poll		= drm_poll,
	.read		= drm_read,
	.llseek		= noop_llseek,
	.mmap		= drm_gem_mmap,
};


static void amdgpu_mdev_prepare_cmd(struct guest_ioctl *cmd, unsigned int req)
{
	cmd->cmd = req;
	cmd->ioctl_completed = false;
	cmd->id = pid_nr(get_task_pid(current, PIDTYPE_PID));

}

static int amdgpu_mdev_ctx_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	union drm_amdgpu_ctx *args = data;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_CTX);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_CTX \n");

	printk("priority %u\n", args->in.priority);
	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       args, sizeof(union drm_amdgpu_ctx));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(args, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_ctx));
	printk("id = %u\n", args->out.alloc.ctx_id);
	return 0;

}

static int amdgpu_mdev_vm_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_VM);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_VM \n");

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_vm));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_vm));
	return 0;

}

static int amdgpu_mdev_bo_list_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;
	union drm_amdgpu_bo_list *args = data;
	struct drm_amdgpu_bo_list_in *in = &args->in;
	const uint32_t info_size = sizeof(struct drm_amdgpu_bo_list_entry);
	const void __user *uptr = u64_to_user_ptr(args->in.bo_info_ptr);
	struct drm_amdgpu_bo_list_entry *info = amdgpu_dev_mdev.bar0_base
		+ sizeof(struct guest_ioctl)
		+ sizeof(union drm_amdgpu_bo_list);

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_BO_LIST);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_BO_LIST \n");

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_bo_list));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	ret = -EFAULT;
	printk("amdgpu_mdev_bo_list_ioctl trying to copy %u bo, info_size %u in_info %u\n", in->bo_number, info_size, args->in.bo_info_size);
	if (likely(info_size == args->in.bo_info_size)) {
		unsigned long bytes = in->bo_number *
			in->bo_info_size;

		if (copy_from_user(info, uptr, bytes)) {
			printk("failed to copy from user\n");
			return ret;
		}
		printk("handle %u\n", info->bo_handle);

	} else {
		unsigned long bytes = min(in->bo_info_size, info_size);
		unsigned i;

		memset(info, 0, in->bo_number * info_size);
		for (i = 0; i < in->bo_number; ++i) {
			if (copy_from_user(&info[i], uptr, bytes)) {
				printk("failed to copy from user\n");
				return ret;
			}
			printk("handle %u\n", info[i].bo_handle);
			uptr += in->bo_info_size;
		}
	}


	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_bo_list));
	printk("done AMDGPU_GUEST_CMD_IOCTL_BO_LIST handle %u\n", args->out.list_handle);
	return 0;

}

static int amdgpu_mdev_cs_parser_init(struct amdgpu_cs_parser *p, union drm_amdgpu_cs *cs)
{
	struct amdgpu_fpriv *fpriv = p->filp->driver_priv;
	struct amdgpu_vm *vm = &fpriv->vm;
	uint64_t *chunk_array_user;
	uint64_t *chunk_array;
	unsigned size, num_ibs = 0;
	uint32_t uf_offset = 0;
	int i;
	int ret;

	if (cs->in.num_chunks == 0)
		return 0;

	chunk_array = kmalloc_array(cs->in.num_chunks, sizeof(uint64_t), GFP_KERNEL);
	if (!chunk_array)
		return -ENOMEM;

	/* get chunks */
	chunk_array_user = u64_to_user_ptr(cs->in.chunks);
	if (copy_from_user(chunk_array, chunk_array_user,
			   sizeof(uint64_t)*cs->in.num_chunks)) {
		ret = -EFAULT;
		goto free_chunk;
	}

	p->nchunks = cs->in.num_chunks;
	//printk("p->nchunks %u\n", p->nchunks);
	p->chunks = kmalloc_array(p->nchunks, sizeof(struct amdgpu_cs_chunk),
			    GFP_KERNEL);
	if (!p->chunks) {
		ret = -ENOMEM;
		goto free_chunk;
	}

	for (i = 0; i < p->nchunks; i++) {
		struct drm_amdgpu_cs_chunk __user **chunk_ptr = NULL;
		struct drm_amdgpu_cs_chunk user_chunk;
		uint32_t __user *cdata;

		chunk_ptr = u64_to_user_ptr(chunk_array[i]);
		if (copy_from_user(&user_chunk, chunk_ptr,
				       sizeof(struct drm_amdgpu_cs_chunk))) {
			ret = -EFAULT;
			i--;
			goto free_partial_kdata;
		}
		p->chunks[i].chunk_id = user_chunk.chunk_id;
		p->chunks[i].length_dw = user_chunk.length_dw;

		size = p->chunks[i].length_dw;
		printk("length_dw %u\n", p->chunks[i].length_dw);
		cdata = u64_to_user_ptr(user_chunk.chunk_data);

		p->chunks[i].kdata = kvmalloc_array(size, sizeof(uint32_t), GFP_KERNEL);
		if (p->chunks[i].kdata == NULL) {
			ret = -ENOMEM;
			i--;
			goto free_partial_kdata;
		}
		size *= sizeof(uint32_t);
		if (copy_from_user(p->chunks[i].kdata, cdata, size)) {
			ret = -EFAULT;
			goto free_partial_kdata;
		}

		//printk("kdata after copy %x %d\n", p->chunks[i].kdata, i);
		switch (p->chunks[i].chunk_id) {
		case AMDGPU_CHUNK_ID_IB:
			++num_ibs;
			break;

		case AMDGPU_CHUNK_ID_FENCE:
			printk("Err amdgpu_mdev_cs_parser_init AMDGPU_CHUNK_ID_FENCE \n");
			/*
			size = sizeof(struct drm_amdgpu_cs_chunk_fence);
			if (p->chunks[i].length_dw * sizeof(uint32_t) < size) {
				ret = -EINVAL;
				goto free_partial_kdata;
			}

			ret = amdgpu_cs_user_fence_chunk(p, p->chunks[i].kdata,
							 &uf_offset);
			if (ret)
				goto free_partial_kdata;
			*/
			break;

		case AMDGPU_CHUNK_ID_BO_HANDLES:
			printk("Err amdgpu_mdev_cs_parser_init AMDGPU_CHUNK_ID_BO_HANDLES \n");
			/*
			size = sizeof(struct drm_amdgpu_bo_list_in);
			if (p->chunks[i].length_dw * sizeof(uint32_t) < size) {
				ret = -EINVAL;
				goto free_partial_kdata;
			}

			ret = amdgpu_cs_bo_handles_chunk(p, p->chunks[i].kdata);
			if (ret)
				goto free_partial_kdata;
			*/
			break;

		case AMDGPU_CHUNK_ID_DEPENDENCIES:
		case AMDGPU_CHUNK_ID_SYNCOBJ_IN:
		case AMDGPU_CHUNK_ID_SYNCOBJ_OUT:
		case AMDGPU_CHUNK_ID_SCHEDULED_DEPENDENCIES:
		case AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_WAIT:
		case AMDGPU_CHUNK_ID_SYNCOBJ_TIMELINE_SIGNAL:
			break;

		default:
			ret = -EINVAL;
			goto free_partial_kdata;
		}
	}

	kfree(chunk_array);

	return 0;

free_all_kdata:
	i = p->nchunks - 1;
free_partial_kdata:
	for (; i >= 0; i--)
		kvfree(p->chunks[i].kdata);
	kfree(p->chunks);
	p->chunks = NULL;
	p->nchunks = 0;
free_chunk:
	kfree(chunk_array);

	return ret;
}


int amdgpu_mdev_vm_cs_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0, i, size;
	struct guest_ioctl cmd;
	struct amdgpu_cs_parser *parser;
	struct drm_amdgpu_cs_chunk *chunk;
	struct drm_amdgpu_cs_chunk_ib *chunk_ib;
	void *cdata;
	u64 test_data = 0;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_CS);
	printk("calling AMDGPU_GUEST_CMD_IOCTL_CS\n");

	parser = amdgpu_dev_mdev.bar0_base
	       + sizeof(struct guest_ioctl)
	       + sizeof(union drm_amdgpu_cs);
	ret = amdgpu_mdev_cs_parser_init(parser, data);
	if (ret)
		printk("amdgpu_mdev_cs_parser_init failed %d\n", ret);
	printk("number of chunks %u ret %d %p\n", parser->nchunks, ret, parser->chunks);

	cdata = (void *)parser + sizeof(struct amdgpu_cs_parser) +
		parser->nchunks * sizeof(struct amdgpu_cs_chunk);
	chunk = (void *) parser + sizeof(struct amdgpu_cs_parser);
	memcpy(chunk, parser->chunks, parser->nchunks *  sizeof(struct amdgpu_cs_parser));
	for (i = 0; i < parser->nchunks; i++) {
		size = parser->chunks[i].length_dw;
		size *= sizeof(uint32_t);
		printk("p->chunks[%d].length_dw %u id %u\n", i, parser->chunks[i].length_dw, parser->chunks[i].chunk_id);
		memcpy(cdata, parser->chunks[i].kdata, size);
	//	printk("cdata %x %d\n", *(int *)cdata, i);
	//	printk("kdata after copy %x %d\n", parser->chunks[i].kdata, i);
	//	printk("chunk id %u %d\n", parser->chunks[i].chunk_id, i);
	//	printk("%llu %llu", (u64)amdgpu_dev_mdev.bar0_base, (u64)cdata);
		chunk_ib = parser->chunks[i].kdata;
		printk("kdata va_start %llu instance %u ring %u", chunk_ib->va_start, chunk_ib->ip_instance, chunk_ib->ring);
		chunk_ib = cdata;
		printk("cdata va_start %llu instance %u ring %u", chunk_ib->va_start, chunk_ib->ip_instance, chunk_ib->ring);
	//	printk("nirmoy cdata - cs %llu\n", cdata - (void *)parser);
	//	printk("nirmoy cdata - cs %llu\n", cdata - (void *)parser);
		cdata = cdata + size;
		printk("after cdata");

	}

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_cs));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	printk("done memcpy\n");
	amdgpu_mdev_ring_doorbell();
	printk("waiting \n");
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_cs));
	return 0;

}

static int amdgpu_mdev_gem_va_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_GEM_VA);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_GEM_VA \n");

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(struct drm_amdgpu_gem_va));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(struct drm_amdgpu_gem_va));
	printk("done AMDGPU_GUEST_CMD_IOCTL_GEM_VA \n");
	return 0;

}

static struct offset_key *get_handle_key(u32 remote_handle)
{
	struct offset_key *key = NULL;

	hash_for_each_possible(amdgpu_dev_mdev.offset_htable, key, hnode, remote_handle)
		return key;
	return key;
}


static int amdgpu_mdev_gem_mmap_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;
	struct drm_gem_object *gobj;
	struct drm_gem_vram_object *gbo;
	union drm_amdgpu_gem_mmap *args = data;

	struct offset_key *key = get_handle_key(args->in.handle);

	if (!key) {
		printk("amdgpu_mdev_gem_mmap_ioctl failed to get key\n");
		return -1;
	}

	printk("handle recv %u local %u\n", key->remote_handle, key->local_handle);
	gobj = drm_gem_object_lookup(filp, key->local_handle);
	gbo = drm_gem_vram_of_gem(gobj);
	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_GEM_MMAP);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_GEM_MMAP \n");

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_gem_mmap));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	args->out.addr_ptr = drm_vma_node_offset_addr(&gobj->vma_node);
	printk("Mapping %llu\n", args->out.addr_ptr);
	printk("done AMDGPU_GUEST_CMD_IOCTL_GEM_MMAP \n");
	//memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_gem_mmap));
	return 0;

}

static int amdgpu_mdev_wait_cs_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;
	union drm_amdgpu_wait_cs *wait = data;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_WAIT_CS);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_WAIT_CS \n");
	printk("sending ctx %u ip_type %u ins %u\n",
	       wait->in.ctx_id,
	       wait->in.ip_type,
	       wait->in.ip_instance);

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_wait_cs));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_wait_cs));
	printk("out status %d\n", wait->out.status);
	printk("done AMDGPU_GUEST_CMD_IOCTL_WAIT_CS \n");
	return 0;

}

static int amdgpu_mdev_sched_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_SCHED);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_SCHED \n");

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_gem_create));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_sched));
	return 0;

}

static int amdgpu_mdev_gem_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;
	struct drm_gem_vram_object *gbo;
	union drm_amdgpu_gem_create *args = (union drm_amdgpu_gem_create *) data;
	u32 handle;
	struct offset_key *key = kzalloc(sizeof(struct offset_key), GFP_KERNEL);

	printk("doing AMDGPU_GUEST_CMD_IOCTL_GEM_CREATE \n");
	args->in.bo_size = ALIGN(args->in.bo_size, PAGE_SIZE);
	printk("allocating %llu\n", args->in.bo_size);
	gbo = drm_gem_vram_create(dev, args->in.bo_size, 0);
	ret = drm_gem_vram_pin(gbo, DRM_GEM_VRAM_PL_FLAG_VRAM);

	if (ret) {
		printk("VRAM pinning failed\n");
		return ret;
	}
	ret = drm_gem_handle_create(filp, &gbo->bo.base, &handle);
	if (ret) {
		printk("unable to create handle\n");
		return ret;
	}
	cmd.offset = drm_gem_vram_offset(gbo);
	cmd.size = args->in.bo_size;
	cmd.handle = handle;
	printk("sending offset %lu and size %lu\n", cmd.offset, cmd.size);
	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_GEM_CREATE);
	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_gem_create));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_gem_create));
	printk("handle recv %u local %u\n", args->out.handle, handle);
	key->local_handle = handle;
	key->remote_handle = args->out.handle;
	hash_add(amdgpu_dev_mdev.offset_htable, &key->hnode, args->out.handle);
	printk("done AMDGPU_GUEST_CMD_IOCTL_GEM_CREATE \n");
	return 0;

}

static int amdgpu_mdev_info_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct drm_amdgpu_info *info = data;
	void __user *out = (void __user *)(uintptr_t)info->return_pointer;
	struct guest_ioctl cmd;

	//printk("query %d size %u\n", info->query, info->return_size);
	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_INFO);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_INFO \n");

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       info, sizeof(struct drm_amdgpu_info));
	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(struct drm_amdgpu_info) + sizeof(cmd);
	ret = copy_to_user(out, amdgpu_dev_mdev.bar0_base + ret, info->return_size);
	if (ret) {
		printk("failed to copy\n");
		return -EFAULT;
	}
	printk("done AMDGPU_GUEST_CMD_IOCTL_INFO \n");
	return 0;
}

static int amdgpu_mdev_cs_wait_fences_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	union drm_amdgpu_wait_fences *wait = data;
	struct guest_ioctl cmd;
	struct drm_amdgpu_fence *fences_user;
	uint32_t fence_count = wait->in.fence_count;


	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_WAIT_FENCES);
	printk("doing AMDGPU_GUEST_CMD_IOCTL_WAIT_FENCES \n");
	printk("waiting ofr %u fences \n", fence_count);
	fences_user = u64_to_user_ptr(wait->in.fences);

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_wait_fences));
	if (copy_from_user(amdgpu_dev_mdev.bar0_base
			   + sizeof(struct guest_ioctl)
			   + sizeof(union drm_amdgpu_wait_fences),
			   fences_user,
			   sizeof(struct drm_amdgpu_fence) * fence_count)) {
		printk("amdgpu_mdev_cs_wait_fences_ioctl faulted\n");
		return -EFAULT;
	}

	amdgpu_mdev_ring_doorbell();
	ret = wait_event_timeout(amdgpu_dev_mdev.ioctl_wait,
				 &cmd.ioctl_completed,
				 IOCTL_TIMEOUT);
	if (!ret)
		printk("timed out \n");
	ret = sizeof(cmd);
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_wait_fences ));
	printk("done AMDGPU_GUEST_CMD_IOCTL_WAIT_FENCES \n");
	return 0;
}

static int amdgpu_mdev_metadata_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	printk("amdgpu_mdev_metadata_ioctl: not implemented\n");
	return -1;

}
const struct drm_ioctl_desc amdgpu_mdev_ioctls_kms[] = {
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_CREATE, amdgpu_mdev_gem_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_MMAP, amdgpu_mdev_gem_mmap_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_CTX, amdgpu_mdev_ctx_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_BO_LIST, amdgpu_mdev_bo_list_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_CS, amdgpu_mdev_vm_cs_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_WAIT_CS, amdgpu_mdev_wait_cs_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_VM, amdgpu_mdev_vm_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_SCHED, amdgpu_mdev_sched_ioctl, DRM_MASTER),
	DRM_IOCTL_DEF_DRV(AMDGPU_INFO, amdgpu_mdev_info_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_METADATA, amdgpu_mdev_metadata_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_VA, amdgpu_mdev_gem_va_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_WAIT_FENCES, amdgpu_mdev_cs_wait_fences_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
};

static struct drm_driver mdev_kms_driver = {
	.driver_features =
	    DRIVER_GEM |
	    DRIVER_RENDER | DRIVER_SYNCOBJ,
	.open = amdgpu_mdev_open_kms,
	.fops = &amdgpu_mdev_kms_fops,
	.ioctls = amdgpu_mdev_ioctls_kms,
	.name = DRIVER_NAME,
	.desc = DRIVER_DESC,
	.date = DRIVER_DATE,
	.major = KMS_DRIVER_MAJOR,
	.minor = KMS_DRIVER_MINOR,
	.patchlevel = KMS_DRIVER_PATCHLEVEL,
	.num_ioctls = ARRAY_SIZE(amdgpu_mdev_ioctls_kms),
};

//drm_ioctl()

static irqreturn_t amdgpu_mdev_irq_thread_fn(int irq, void *devid)
{
	struct guest_ioctl cmd;
	int count;

	count = kfifo_out(&amdgpu_dev_mdev.ioctl_reqs,
			  &cmd, sizeof(struct guest_ioctl));
	if (count != sizeof(cmd)) {
		printk("Fatal kfifo_out return\n");
		return IRQ_HANDLED;
	}
	cmd.ioctl_completed = true;
	wake_up(&amdgpu_dev_mdev.ioctl_wait);
	return IRQ_HANDLED;
}
int amdgpu_mdev_pci_probe(struct pci_dev *pdev,
				 const struct pci_device_id *ent)
{
	int ret, retry = 0;
	struct drm_device *ddev;
	struct amdgpu_device *adev;
	unsigned long ioaddr, iosize;
	struct drm_vram_mm *vmm;

	adev = devm_drm_dev_alloc(&pdev->dev, &mdev_kms_driver, typeof(*adev), ddev);
	if (IS_ERR(adev))
		return PTR_ERR(adev);

	adev->dev  = &pdev->dev;
	adev->pdev = pdev;
	ddev = adev_to_drm(adev);


	drm_mode_config_init(ddev);

	ddev->driver_features &= ~DRIVER_ATOMIC;

	ret = pci_enable_device(pdev);
	if (ret)
		goto err_free;
	ret = pci_enable_msi(pdev);
	if (ret) {
		printk("failed to enable msi %d\n", ret);
		goto err_pci;
	} else {
		ret = request_threaded_irq(pdev->irq, NULL,
					   amdgpu_mdev_irq_thread_fn,
					   IRQF_ONESHOT, "amdgpu_mdev_irq",
					   pdev);
		if (ret)
			pci_disable_msi(pdev);
	}



	ioaddr = pci_resource_start(pdev, 2);
	iosize = pci_resource_len(pdev, 2);
	amdgpu_dev_mdev.bar0_base = memremap(ioaddr, iosize, MEMREMAP_WB);
	amdgpu_dev_mdev.bar2_size = iosize;
	ioaddr = pci_resource_start(pdev, 1);
	iosize = pci_resource_len(pdev, 1);
	amdgpu_dev_mdev.mmio = memremap(ioaddr, iosize, MEMREMAP_WB);
	adev->gmc.aper_base = pci_resource_start(adev->pdev, 0);
	adev->gmc.aper_size = pci_resource_len(adev->pdev, 0);
	/*
	adev->gmc.visible_vram_size = adev->gmc.aper_size;
	adev->gmc.real_vram_size = adev->gmc.aper_size;
	ret = amdgpu_ttm_init(adev);
	if (ret) {
		printk("ttm init failed %d\n", ret);
		return ret;
	}*/
	if (amdgpu_dev_mdev.bar0_base == NULL) {
		printk("ioremap bar0 failed\n");
		return -ENOMEM;
	}
	if (amdgpu_dev_mdev.mmio == NULL) {
		printk("ioremap mmio failed\n");
		return -ENOMEM;
	}

	vmm = drm_vram_helper_alloc_mm(ddev, adev->gmc.aper_base, adev->gmc.aper_size);

	if (IS_ERR(vmm)) {
		printk("drm_vram_helper_alloc_mm failed \n");
		return PTR_ERR(vmm);
	}
	init_waitqueue_head(&amdgpu_dev_mdev.ioctl_wait);
	if (kfifo_alloc(&amdgpu_dev_mdev.ioctl_reqs,
			1024 * sizeof(struct guest_ioctl), GFP_KERNEL))
		goto err_pci;
	hash_init(amdgpu_dev_mdev.offset_htable);
	pci_set_drvdata(pdev, ddev);

retry_init:
	ret = drm_dev_register(ddev, ent->driver_data);
	if (ret == -EAGAIN && ++retry <= 3) {
		DRM_INFO("retry init %d\n", retry);
		/* Don't request EX mode too frequently which is attacking */
		msleep(5000);
		goto retry_init;
	} else if (ret)
		goto err_pci;

	adev = ddev->dev_private;
	return 0;

err_pci:
	pci_disable_device(pdev);
err_free:
	drm_dev_put(ddev);
	return ret;

}


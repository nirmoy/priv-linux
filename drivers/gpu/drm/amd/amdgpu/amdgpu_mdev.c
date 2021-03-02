// SPDX-License-Identifier: GPL-2.0-only
/*
 * Mediated virtual PCI host device driver for amdgpu
 *
 * Copyright 2019 Advanced Micro Devices, Inc.
 *     Author: Nirmoy Das <nirmoy.das@amd.com>
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/uuid.h>
#include <linux/vfio.h>
#include <linux/iommu.h>
#include <linux/sysfs.h>
#include <linux/file.h>
#include <linux/mdev.h>
#include <linux/pci.h>
#include <linux/eventfd.h>
#include <linux/hashtable.h>

#include "amdgpu_mdev_common.h"
#include "amdgpu.h"
#include "amdgpu_sched.h"

#define AMDGPU_MDEV_CLASS_NAME "amdgpu"
#define AMDGPU_MDEV_NAME       "vgpu"
#define MDEV_STRING_LEN		16

/* helper macros copied from vfio-pci */
#define VFIO_PCI_OFFSET_SHIFT   40
#define VFIO_PCI_OFFSET_TO_INDEX(off)   (off >> VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_INDEX_TO_OFFSET(index) ((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_MASK    (((u64)(1) << VFIO_PCI_OFFSET_SHIFT) - 1)

#define AMDGPU_MDEV_BAR2_SIZE  2*1024*1024
#define AMDGPU_MDEV_BAR5_SIZE  512*1024
#define AMDGPU_MDEV_MMIO_SIZE  PAGE_SIZE
#define AMDGPU_MDEV_APERTURE_SIZE  128*1024*1024

#define STORE_LE16(addr, val)   (*(u16 *)addr = val)
#define STORE_LE32(addr, val)   (*(u32 *)addr = val)

static unsigned long ttm_bo_io_mem_pfn(struct ttm_buffer_object *bo,
				       unsigned long page_offset)
{
	struct ttm_device *bdev = bo->bdev;

	if (bdev->funcs->io_mem_pfn)
		return bdev->funcs->io_mem_pfn(bo, page_offset);

	return (bo->mem.bus.offset >> PAGE_SHIFT) + page_offset;
}

struct pci_bar_info {
	uint64_t start;
	uint64_t size;
	uint32_t flags;
};

struct amdgpu_vram {
	struct amdgpu_bo	*bo;
	u64			gpu_addr;
	void			*cpu_addr;
	u32			size;
};

static struct amdgpu_mdev {
	dev_t		vd_devt;
	struct class	*vd_class;
	struct cdev	vd_cdev;
	struct idr	vd_idr;
	struct device	dev;
	struct amdgpu_device *adev;
} amdgpu_mdev;

struct amdgpu_mdev_guest_process {

	struct amdgpu_fpriv guest_fpriv;
	struct drm_client_dev client;
	pid_t id;
};

struct offset_key {
	struct hlist_node hnode;
	u64 offset;
	u32 size;
	uint32_t handle;
	struct drm_file *filp;
	struct amdgpu_bo	*bo;
	struct drm_gem_object	*gobj;
	u64			gpu_addr;
	void			*cpu_addr;


};

/* State of each mdev device */
struct mdev_state {
	struct mdev_device	*mdev;
	struct mutex		ops_lock;
	struct amdgpu_device	*adev;
	struct vfio_device_info dev_info;
	struct eventfd_ctx	*msi_evtfd;
	struct eventfd_ctx	*intx_evtfd;
	struct notifier_block	group_notifier;
	struct notifier_block	iommu_notifier;
	struct idr		fpriv_handles;
	struct page		**pages;
	void			*bar2_mem;
	struct kvm		*kvm;
	struct amdgpu_vram	stolen_vram;
	int			irq_fd;
	int			id;
	int			irq_index;
	u8			*vconfig;
	pgoff_t			pagecount;
	u32			bar_mask[VFIO_PCI_NUM_REGIONS];
	DECLARE_HASHTABLE(offset_htable, 16);
};

static void amdgpu_mdev_trigger_interrupt(struct mdev_state *mdev_state)
{
	if (mdev_state->irq_index == VFIO_PCI_MSI_IRQ_INDEX)
			eventfd_signal(mdev_state->msi_evtfd, 1);
		else
			eventfd_signal(mdev_state->intx_evtfd, 1);


}

static struct page *__amdgpu_mdev_get_page(struct mdev_state *mdev_state,
				      pgoff_t pgoff)
{
	WARN_ON(!mutex_is_locked(&mdev_state->ops_lock));

	if (!mdev_state->pages[pgoff]) {
		mdev_state->pages[pgoff] =
			alloc_pages(GFP_HIGHUSER | __GFP_ZERO, 0);
		if (!mdev_state->pages[pgoff])
			return NULL;
	}

	get_page(mdev_state->pages[pgoff]);
	return mdev_state->pages[pgoff];
}

static struct page *amdgpu_mdev_get_page(struct mdev_state *mdev_state,
				    pgoff_t pgoff)
{
	struct page *page;

	if (WARN_ON(pgoff >= mdev_state->pagecount))
		return NULL;

	mutex_lock(&mdev_state->ops_lock);
	page = __amdgpu_mdev_get_page(mdev_state, pgoff);
	mutex_unlock(&mdev_state->ops_lock);

	return page;
}

static void amdgpu_put_pages(struct mdev_state *mdev_state)
{
	struct device *dev = mdev_dev(mdev_state->mdev);
	int i, count = 0;

	WARN_ON(!mutex_is_locked(&mdev_state->ops_lock));

	for (i = 0; i < mdev_state->pagecount; i++) {
		if (!mdev_state->pages[i])
			continue;
		put_page(mdev_state->pages[i]);
		mdev_state->pages[i] = NULL;
		count++;
	}
	dev_dbg(dev, "%s: %d pages released\n", __func__, count);
}

static void amdgpu_mdev_create_config_space(struct mdev_state *mdev_state)
{
	STORE_LE16((u16 *) &mdev_state->vconfig[PCI_VENDOR_ID],
		   PCI_VENDOR_ID_ATI);
	STORE_LE16((u16 *) &mdev_state->vconfig[PCI_DEVICE_ID],
		   0x1637); // copy from raven
	STORE_LE16((u16 *) &mdev_state->vconfig[PCI_SUBSYSTEM_VENDOR_ID],
		   0x407);
	STORE_LE16((u16 *) &mdev_state->vconfig[PCI_SUBSYSTEM_ID],
		   PCI_SUBDEVICE_ID_QEMU);

	STORE_LE16((u16 *) &mdev_state->vconfig[PCI_COMMAND],
		   PCI_COMMAND_IO | PCI_COMMAND_MEMORY);
	STORE_LE16((u16 *) &mdev_state->vconfig[PCI_CLASS_DEVICE],
		   PCI_CLASS_DISPLAY_VGA);
	mdev_state->vconfig[PCI_CLASS_REVISION] =  0x01;

	STORE_LE32((u32 *) &mdev_state->vconfig[PCI_BASE_ADDRESS_0],
		   PCI_BASE_ADDRESS_SPACE_MEMORY |
		   PCI_BASE_ADDRESS_MEM_TYPE_32	 |
		   PCI_BASE_ADDRESS_MEM_PREFETCH);
	mdev_state->bar_mask[0] = ~(AMDGPU_MDEV_APERTURE_SIZE) + 1;
	STORE_LE32((u32 *) &mdev_state->vconfig[PCI_BASE_ADDRESS_1],
		   PCI_BASE_ADDRESS_SPACE_MEMORY |
		   PCI_BASE_ADDRESS_MEM_TYPE_32);
	mdev_state->bar_mask[1] = ~(AMDGPU_MDEV_MMIO_SIZE) + 1;

	STORE_LE32((u32 *) &mdev_state->vconfig[PCI_BASE_ADDRESS_2],
		   PCI_BASE_ADDRESS_SPACE_MEMORY |
		   PCI_BASE_ADDRESS_MEM_TYPE_32);
	mdev_state->bar_mask[2] = ~(AMDGPU_MDEV_BAR2_SIZE) + 1;
	STORE_LE32((u32 *) &mdev_state->vconfig[PCI_BASE_ADDRESS_5],
		   PCI_BASE_ADDRESS_SPACE_MEMORY |
		   PCI_BASE_ADDRESS_MEM_TYPE_32);
	mdev_state->bar_mask[2] = ~(AMDGPU_MDEV_BAR5_SIZE) + 1;


	mdev_state->vconfig[PCI_INTERRUPT_PIN] =  0x01;   /* interrupt pin (INTA#) */
	/* enable pci capability */
	STORE_LE16((u16 *) &mdev_state->vconfig[PCI_STATUS], PCI_STATUS_CAP_LIST);
	mdev_state->vconfig[PCI_CAPABILITY_LIST]       = 0xA0;
	/* enable msi */
	mdev_state->vconfig[0xA0 + 0]       = PCI_CAP_ID_MSI;
	mdev_state->vconfig[0xA0 + 2]       = 0x84; /* TODO: why*/
}


static int amdgpu_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{

	struct mdev_state *mdev_state;
	struct amdgpu_device *adev = amdgpu_mdev.adev;
	int r;

	printk("%pS %lld aa \n", __builtin_return_address(0),
	       adev ? adev->gmc.aper_size : -1);
	mdev_state = kzalloc(sizeof(struct mdev_state), GFP_KERNEL);
	if (mdev_state == NULL)
		return -ENOMEM;

	mdev_state->vconfig = kzalloc(PCI_CFG_SPACE_EXP_SIZE, GFP_KERNEL);
	if (mdev_state->vconfig == NULL)
		return -ENOMEM;


	mdev_state->mdev = mdev;
	mdev_state->id = 1;
	mdev_state->adev = amdgpu_mdev.adev;
	mdev_state->pagecount = AMDGPU_MDEV_APERTURE_SIZE >> PAGE_SHIFT;
	mdev_state->irq_index = -1;
	mdev_state->pages = kcalloc(mdev_state->pagecount,
				    sizeof(struct page *),
				    GFP_KERNEL);
	if (!mdev_state->pages)
		return -1;
	mdev_state->bar2_mem = vmalloc_user(AMDGPU_MDEV_BAR2_SIZE);
	if (!mdev_state->bar2_mem)
		return -1;//TODO cleanup

	mdev_state->stolen_vram.bo = NULL;
	r = amdgpu_bo_create_kernel(adev, AMDGPU_MDEV_APERTURE_SIZE, PAGE_SIZE,
				    AMDGPU_GEM_DOMAIN_VRAM,
				    &mdev_state->stolen_vram.bo,
				    &mdev_state->stolen_vram.gpu_addr,
				    &mdev_state->stolen_vram.cpu_addr);
	if (r)
		printk("failed to reserve VRAM\n");
	else {
		printk("allocated bo %p, cpu %p, gpu %llu\n",
		       mdev_state->stolen_vram.bo,
		       mdev_state->stolen_vram.cpu_addr,
		       mdev_state->stolen_vram.gpu_addr);
	}
	mdev_state->stolen_vram.size = AMDGPU_MDEV_APERTURE_SIZE;

	mutex_init(&mdev_state->ops_lock);
	hash_init(mdev_state->offset_htable);
	mdev_set_drvdata(mdev, mdev_state);
	idr_init(&mdev_state->fpriv_handles);

	amdgpu_mdev_create_config_space(mdev_state);
	return 0;
}

static int amdgpu_remove(struct mdev_device *mdev)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);

	printk("%pS\n", __builtin_return_address(0));
	kfree(mdev_state->pages);
	kfree(mdev_state->vconfig);
	amdgpu_bo_free_kernel(&mdev_state->stolen_vram.bo,
			      &mdev_state->stolen_vram.gpu_addr,
			      &mdev_state->stolen_vram.cpu_addr);
	return 0;
}

static void handle_pci_cfg_write(struct mdev_state *mdev_state, u16 offset,
				 char *buf, u32 count)
{
	struct device *dev = mdev_dev(mdev_state->mdev);
	u32 cfg_addr;

	//printk("config write %u count %u, offset %u offset align %d\n", buf, count, offset, IS_ALIGNED(offset, 8));
	switch (rounddown(offset, 4)) {
	case PCI_BASE_ADDRESS_0:
		cfg_addr = *(u32 *)buf;

		if (cfg_addr == 0xffffffff) {
			cfg_addr = (cfg_addr & mdev_state->bar_mask[0]);
		} else {
			cfg_addr &= PCI_BASE_ADDRESS_MEM_MASK;
			if (cfg_addr)
				dev_info(dev, "BAR #%d @ 0x%x\n",
					 0, cfg_addr);
		}

		cfg_addr |= (mdev_state->vconfig[offset] &
			     ~PCI_BASE_ADDRESS_MEM_MASK);
		STORE_LE32(&mdev_state->vconfig[offset], cfg_addr);
		break;
	}
}

int handle_guest_cmd(struct mdev_state *mdev_state)
{
	return 0;
}

static void handle_mmio_access(struct mdev_state *mdev_state, u16 offset,
			       char *buf, u32 count, bool is_write)
{
	struct device *dev = mdev_dev(mdev_state->mdev);

	//printk("%s\n", "handle_mmio_access");
	if (!is_write)
		return;

	switch (offset) {
	case 0x00:
		handle_guest_cmd(mdev_state);
		break;
	default:
		dev_dbg(dev, "%s: @0x%03x, count %d (unhandled)\n",
			__func__, offset, count);
		break;
	}
}

ssize_t amdgpu_mdev_access(struct mdev_device *mdev, char *buf, size_t count,
			   loff_t pos, bool is_write)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(pos);
	struct page *pg;
	char *map;
	loff_t poff;
	int ret = 0;

	pos = pos & VFIO_PCI_OFFSET_MASK;

	switch(index) {
	case VFIO_PCI_CONFIG_REGION_INDEX: {
		printk("Reading/Writting config space\n");
		if (is_write)
			handle_pci_cfg_write(mdev_state, pos, buf, count);
		else
			memcpy(buf, (mdev_state->vconfig + pos), count);
		break;
	}
	case VFIO_PCI_BAR2_REGION_INDEX: {
		printk("accessing bar2\n");
		/*
		if (is_write)
			memcpy(map + poff, buf, count);
		else
			memcpy(buf, map + poff, count);
		*/
		break;
	}
	case VFIO_PCI_BAR1_REGION_INDEX: {
		handle_mmio_access(mdev_state, pos, buf, count, is_write);
		break;


	}
	case VFIO_PCI_BAR0_REGION_INDEX:
	case VFIO_PCI_BAR3_REGION_INDEX:
	case VFIO_PCI_BAR4_REGION_INDEX:
	case VFIO_PCI_BAR5_REGION_INDEX:
	case VFIO_PCI_VGA_REGION_INDEX:
	case VFIO_PCI_ROM_REGION_INDEX:
		break;
	default:
		printk("Error %s: %s @0x%llx (unhandled)\n",
			__func__, is_write ? "WR" : "RD", pos);
		ret = -1;
		goto accessfailed;
	}

	ret = count;


accessfailed:

	return ret;
}


static ssize_t amdgpu_read(struct mdev_device *mdev, char __user *buf,
			 size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int ret;

	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			ret =  amdgpu_mdev_access(mdev, (char *)&val, sizeof(val),
					   *ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			ret = amdgpu_mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 2;
		} else {
			u8 val;

			ret = amdgpu_mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, false);
			if (ret <= 0)
				goto read_err;

			if (copy_to_user(buf, &val, sizeof(val)))
				goto read_err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;

read_err:
	return -EFAULT;

	return 0;
}

static ssize_t amdgpu_write(struct mdev_device *mdev, const char __user *buf,
		   size_t count, loff_t *ppos)
{
	unsigned int done = 0;
	int ret;

	while (count) {
		size_t filled;

		if (count >= 4 && !(*ppos % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = amdgpu_mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 4;
		} else if (count >= 2 && !(*ppos % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = amdgpu_mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, sizeof(val)))
				goto write_err;

			ret = amdgpu_mdev_access(mdev, (char *)&val, sizeof(val),
					  *ppos, true);
			if (ret <= 0)
				goto write_err;

			filled = 1;
		}
		count -= filled;
		done += filled;
		*ppos += filled;
		buf += filled;
	}

	return done;
write_err:
	return -EFAULT;
	return 0;
}

static int amdgpu_mdev_get_region_info(struct mdev_device *mdev,
				       struct vfio_region_info *info)
{
	if (info->index >= VFIO_PCI_NUM_REGIONS + 1)
		return -EINVAL;

	printk("amdgpu_mdev_get_region_info %d\n", info->index);
	switch (info->index) {
	case VFIO_PCI_CONFIG_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = PCI_CFG_SPACE_EXP_SIZE;
		info->flags  = (VFIO_REGION_INFO_FLAG_READ |
				VFIO_REGION_INFO_FLAG_WRITE);
		break;
	case VFIO_PCI_BAR0_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = AMDGPU_MDEV_APERTURE_SIZE;
		info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				VFIO_REGION_INFO_FLAG_WRITE |
				VFIO_REGION_INFO_FLAG_MMAP);
		break;
	case VFIO_PCI_BAR1_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = AMDGPU_MDEV_MMIO_SIZE;
		info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				VFIO_REGION_INFO_FLAG_WRITE);
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = AMDGPU_MDEV_BAR2_SIZE;
		info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				VFIO_REGION_INFO_FLAG_WRITE |
				VFIO_REGION_INFO_FLAG_MMAP);
	case VFIO_PCI_BAR5_REGION_INDEX:
		info->offset = VFIO_PCI_INDEX_TO_OFFSET(info->index);
		info->size   = AMDGPU_MDEV_BAR5_SIZE;
		info->flags  = (VFIO_REGION_INFO_FLAG_READ  |
				VFIO_REGION_INFO_FLAG_WRITE |
				VFIO_REGION_INFO_FLAG_MMAP);

		break;

	default:
		info->size   = 0;
		info->offset = 0;
		info->flags  = 0;
	}

	return 0;
}

static int amdgpu_mdev_set_irqs(struct mdev_device *mdev, uint32_t flags,
			 unsigned int index, unsigned int start,
			 unsigned int count, void *data)
{
	int ret = 0;
	struct mdev_state *mdev_state;

	if (!mdev)
		return -EINVAL;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -EINVAL;

	mutex_lock(&mdev_state->ops_lock);
	switch (index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
		{
			if (flags & VFIO_IRQ_SET_DATA_NONE) {
				pr_info("%s: disable INTx\n", __func__);
				if (mdev_state->intx_evtfd)
					eventfd_ctx_put(mdev_state->intx_evtfd);
				break;
			}

			if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
				int fd = *(int *)data;

				if (fd > 0) {
					struct eventfd_ctx *evt;

					evt = eventfd_ctx_fdget(fd);
					if (IS_ERR(evt)) {
						ret = PTR_ERR(evt);
						break;
					}
					mdev_state->intx_evtfd = evt;
					pr_info("setting intx_evtfd\n");
					mdev_state->irq_fd = fd;
					mdev_state->irq_index = index;
					break;
				}
			}
			break;
		}
		}
		break;
	case VFIO_PCI_MSI_IRQ_INDEX:
		pr_info("%s: MSI_IRQ\n", __func__);
		switch (flags & VFIO_IRQ_SET_ACTION_TYPE_MASK) {
		case VFIO_IRQ_SET_ACTION_MASK:
		case VFIO_IRQ_SET_ACTION_UNMASK:
			break;
		case VFIO_IRQ_SET_ACTION_TRIGGER:
			if (flags & VFIO_IRQ_SET_DATA_NONE) {
				if (mdev_state->msi_evtfd)
					eventfd_ctx_put(mdev_state->msi_evtfd);
				pr_info("%s: disable MSI\n", __func__);
				mdev_state->irq_index = VFIO_PCI_INTX_IRQ_INDEX;
				break;
			}
			if (flags & VFIO_IRQ_SET_DATA_EVENTFD) {
				int fd = *(int *)data;
				struct eventfd_ctx *evt;

				if (fd <= 0)
					break;

				if (mdev_state->msi_evtfd)
					break;

				evt = eventfd_ctx_fdget(fd);
				if (IS_ERR(evt)) {
					ret = PTR_ERR(evt);
					break;
				}
				mdev_state->msi_evtfd = evt;
				mdev_state->irq_fd = fd;
				mdev_state->irq_index = index;
			}
			break;
	}
	break;
	case VFIO_PCI_MSIX_IRQ_INDEX:
		pr_info("%s: MSIX_IRQ\n", __func__);
		break;
	case VFIO_PCI_ERR_IRQ_INDEX:
		pr_info("%s: ERR_IRQ\n", __func__);
		break;
	case VFIO_PCI_REQ_IRQ_INDEX:
		pr_info("%s: REQ_IRQ\n", __func__);
		break;
	}

	mutex_unlock(&mdev_state->ops_lock);
	return ret;
}

static int amdgpu_mdev_get_irq_info(struct mdev_device *mdev,
			     struct vfio_irq_info *irq_info)
{
	pr_info("amdgpu_mdev_get_irq_info %d\n", irq_info->index);
	switch (irq_info->index) {
	case VFIO_PCI_INTX_IRQ_INDEX:
	case VFIO_PCI_MSI_IRQ_INDEX:
	case VFIO_PCI_REQ_IRQ_INDEX:
		break;

	default:
		return -EINVAL;
	}

	irq_info->flags = VFIO_IRQ_INFO_EVENTFD;
	irq_info->count = 1;

	pr_info("amdgpu_mdev_get_irq_info 2nd part\n");
	if (irq_info->index == VFIO_PCI_INTX_IRQ_INDEX)
		irq_info->flags |= (VFIO_IRQ_INFO_MASKABLE |
				VFIO_IRQ_INFO_AUTOMASKED);
	else
		irq_info->flags |= VFIO_IRQ_INFO_NORESIZE;

	return 0;
}

static void amdgpu_mdev_get_device_info(struct mdev_device *mdev,
			 struct vfio_device_info *dev_info)
{
	dev_info->flags = VFIO_DEVICE_FLAGS_PCI;
	dev_info->num_regions = VFIO_PCI_NUM_REGIONS;
	dev_info->num_irqs = VFIO_PCI_NUM_IRQS;
}

static long amdgpu_ioctl(struct mdev_device *mdev, unsigned int cmd,
			 unsigned long arg)
{
	unsigned long minsz, outsz;
	struct mdev_state *mdev_state;
	int ret;

	mdev_state = mdev_get_drvdata(mdev);
	if (!mdev_state)
		return -ENODEV;


	printk("amdgpu_ioctl case %d\n", cmd);
	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
	{
		struct vfio_device_info info;
		printk("amdgpu_ioctl case VFIO_DEVICE_GET_INFO\n");

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		amdgpu_mdev_get_device_info(mdev, &info);
		memcpy(&mdev_state->dev_info, &info, sizeof(info));

		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;
		return 0;
	}
	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info;
		printk("amdgpu_ioctl case VFIO_DEVICE_GET_REGION_INFO\n");
		minsz = offsetofend(typeof(info), offset);
		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;
		outsz = info.argsz;
		if (outsz < minsz)
			return -EINVAL;
		if (outsz > sizeof(info))
			return -EINVAL;

		ret = amdgpu_mdev_get_region_info(mdev, &info);
		if (ret)
			return ret;

		if (copy_to_user((void __user *)arg, &info, outsz))
			return -EFAULT;
		return 0;
	}
	case VFIO_DEVICE_GET_IRQ_INFO:
	{
		struct vfio_irq_info info;
		printk("amdgpu_ioctl case VFIO_DEVICE_GET_IRQ_INFO\n");

		minsz = offsetofend(struct vfio_irq_info, count);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if ((info.argsz < minsz) ||
		    (info.index >= mdev_state->dev_info.num_irqs))
			return -EINVAL;

		ret = amdgpu_mdev_get_irq_info(mdev, &info);
		if (ret)
			return ret;



		if (copy_to_user((void __user *)arg, &info, minsz))
			return -EFAULT;

		return 0;
	}
	case VFIO_DEVICE_SET_IRQS:
	{
		struct vfio_irq_set hdr;
		u8 *data = NULL, *ptr = NULL;
		size_t data_size = 0;
		printk("VFIO_DEVICE_SET_IRQS 1\n");
		minsz = offsetofend(struct vfio_irq_set, count);

		if (copy_from_user(&hdr, (void __user *)arg, minsz))
			return -EFAULT;

		ret = vfio_set_irqs_validate_and_prepare(&hdr,
						mdev_state->dev_info.num_irqs,
						VFIO_PCI_NUM_IRQS,
						&data_size);
		if (ret)
			return ret;

		if (data_size) {
			ptr = data = memdup_user((void __user *)(arg + minsz),
						 data_size);
			if (IS_ERR(data))
				return PTR_ERR(data);
		}

		ret = amdgpu_mdev_set_irqs(mdev, hdr.flags, hdr.index, hdr.start,
				    hdr.count, data);

		kfree(ptr);
		return ret;

	}

	}
	return -ENOTTY;
}

static struct offset_key *get_offset_key(struct mdev_state *mdev_state, u64 offset)
{
	struct offset_key *key = NULL;

	hash_for_each_possible(mdev_state->offset_htable, key, hnode, offset)
		return key;
	return key;
}


static vm_fault_t amdgpu_mdev_bar0_vm_fault(struct vm_fault *vmf)
{
	struct page *page;
	unsigned long pfn;
	struct vm_area_struct *vma = vmf->vma;
	struct mdev_state *mdev_state = vma->vm_private_data;
	struct ttm_buffer_object *bo = &mdev_state->stolen_vram.bo->tbo;
	struct ttm_tt *ttm = bo->ttm;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;
	//unsigned long vm_pgoff = vma->vm_pgoff &
	//	((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);
	struct offset_key *key = get_offset_key(mdev_state, page_offset);

	if (key) {
		bo = &key->bo->tbo;
		ttm = bo->ttm;

		printk("got ttm tbo %p %p\n", ttm, bo);
		printk("found offset_key %lu\n", page_offset);
	}

	printk("amdgpu_mdev_bar0_vm_fault %lu %lu %p\n", page_offset, vmf->address, ttm);
	if (bo->mem.bus.is_iomem) {
		printk("before getting pfn %p\n", bo);
		pfn = ttm_bo_io_mem_pfn(bo, page_offset);
	}
	else
		pfn = page_to_pfn(ttm->pages[page_offset]);

	printk("amdgpu_mdev_bar0_vm_fault pfn %lu \n", pfn);
	/*
	pfn =  ((unsigned long)__pa(mdev_state->stolen_vram.cpu_addr) >> PAGE_SHIFT) +
		vm_pgoff + page_offset;
	printk("amdgpu_mdev_bar0_vm_fault pfn %lu \n", pfn);*/
	return vmf_insert_pfn(vma, vmf->address, pfn);
	/*
	page = amdgpu_mdev_get_page(mdev_state, page_offset);
	if (!page) {
		printk("amdgpu_mdev_bar0_vm_fault failed\n");
		return VM_FAULT_SIGBUS;
	}

	return vmf_insert_page(vma, vmf->address, page);
	*/
}

static const struct vm_operations_struct amdgpu_mdev_bar0_vm_ops = {
	.fault = amdgpu_mdev_bar0_vm_fault,
};
/*
static vm_fault_t amdgpu_mdev_bar2_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mdev_state *mdev_state = vma->vm_private_data;
	pgoff_t page_offset = (vmf->address - vma->vm_start) >> PAGE_SHIFT;

	if (page_offset >= mdev_state->pagecount)
		return VM_FAULT_SIGBUS;
	//return ttm_bo_vm_reserve(&mdev_state->stolen_vram.bo->tbo, vmf);
	printk("amdgpu_mdev_bar2_vm_fault page offset%lu\n", page_offset);
	vmf->page =  mdev_state->bar2_page;
	//vmf->page =  vmalloc_to_page(&mdev_state->stolen_vram.cpu_addr);
	if (!vmf->page) {
		printk("failed to get page of the virtual address\b");
		return VM_FAULT_SIGBUS;
	}

	return 0;
}

static const struct vm_operations_struct amdgpu_mdev_bar2_vm_ops = {
	.fault = amdgpu_mdev_bar2_vm_fault,
};
*/
static int amdgpu_mdev_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	unsigned int index;
	unsigned long pfn;
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if ((vma->vm_flags & VM_SHARED) == 0)
		return -EINVAL;
	switch (index) {
	case VFIO_PCI_BAR0_REGION_INDEX:
		printk("mmap VFIO_PCI_BAR0_REGION_INDEX\n");
		vma->vm_ops = &amdgpu_mdev_bar0_vm_ops;
		vma->vm_flags |= VM_PFNMAP | VM_IO | VM_DONTEXPAND | VM_DONTDUMP;
		break;
/*
		printk("before shift %lu size %u pgoff %lu\n",
		       mdev_state->stolen_vram.cpu_addr,
		       mdev_state->stolen_vram.size,
		       vma->vm_pgoff);
		pfn =  ((unsigned long)__pa(mdev_state->stolen_vram.cpu_addr) >> PAGE_SHIFT);
		printk("after shift %lu size %u\n", pfn);
		return remap_pfn_range(vma, vma->vm_start,
				       pfn,
				       AMDGPU_MDEV_APERTURE_SIZE,
				       vma->vm_page_prot);
		printk("mmap VFIO_PCI_BAR0_REGION_INDEX");
		if (vma->vm_end - vma->vm_start > AMDGPU_MDEV_APERTURE_SIZE)
			return -EINVAL;
*/
		break;
	case VFIO_PCI_BAR2_REGION_INDEX:
		printk("mma0 VFIO_PCI_BAR2_REGION_INDEX\n");
		vma->vm_private_data = mdev_state;
		//vma->vm_ops = &amdgpu_mdev_bar2_vm_ops;
		return remap_vmalloc_range_partial(vma, vma->vm_start,
					   mdev_state->bar2_mem, 0,
					   vma->vm_end - vma->vm_start);

		break;
	default:
		return -EINVAL;
	}
	vma->vm_private_data = mdev_state;

	return 0;

}

static int amdgpu_mdev_iommu_notifier(struct notifier_block *nb,
				       unsigned long action, void *data)
{
	printk("%s\n", __func__);
	dump_stack();
	return NOTIFY_DONE;
}

static int amdgpu_mdev_group_notifier(struct notifier_block *nb,
				       unsigned long action, void *data)
{
	struct mdev_state *mdev_state;

	printk("%s %lu %p\n", __func__, action, data);
	dump_stack();
	if (action != VFIO_GROUP_NOTIFY_SET_KVM)
		return NOTIFY_OK;

	mdev_state = container_of(nb, struct mdev_state, group_notifier);

	if (data) {
		printk("setting kvm %p\n", data);
		mdev_state->kvm = (struct kvm*)data;
		return NOTIFY_OK;
	}

	return NOTIFY_OK;
}

static int amdgpu_open(struct mdev_device *mdev)
{
	struct mdev_state *mdev_state = mdev_get_drvdata(mdev);
	unsigned long events;
	int ret;


	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	mdev_state->group_notifier.notifier_call = amdgpu_mdev_group_notifier;
	events = VFIO_GROUP_NOTIFY_SET_KVM;

	ret = vfio_register_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY,
				     &events, &mdev_state->group_notifier);
	if (ret) {
		module_put(THIS_MODULE);
		return ret;
	}

	mdev_state->iommu_notifier.notifier_call = amdgpu_mdev_iommu_notifier;
	events = VFIO_IOMMU_NOTIFY_DMA_UNMAP;
	ret = vfio_register_notifier(mdev_dev(mdev), VFIO_IOMMU_NOTIFY,
				     &events, &mdev_state->iommu_notifier);
	if (!ret)
		return ret;

	vfio_unregister_notifier(mdev_dev(mdev), VFIO_GROUP_NOTIFY,
				 &mdev_state->group_notifier);
	module_put(THIS_MODULE);
	printk("%s\n", "amdgpu_open");
	return 0;
}

static void amdgpu_close(struct mdev_device *mdev)
{
	printk("%s\n", "amdgpu_close");
}

static ssize_t
sample_amdgpu_dev_show(struct device *dev, struct device_attribute *attr,
		     char *buf)
{
	return sprintf(buf, "This is phy device\n");
}

static DEVICE_ATTR_RO(sample_amdgpu_dev);

static struct attribute *amdgpu_dev_attrs[] = {
	&dev_attr_sample_amdgpu_dev.attr,
	NULL,
};

static const struct attribute_group amdgpu_dev_group = {
	.name  = "amdgpu_dev",
	.attrs = amdgpu_dev_attrs,
};

static const struct attribute_group *amdgpu_dev_groups[] = {
	&amdgpu_dev_group,
	NULL,
};

static struct attribute *mdev_dev_attrs[] = {
	NULL,
};

static const struct attribute_group mdev_dev_group = {
	.name  = "vendor",
	.attrs = mdev_dev_attrs,
};

static const struct attribute_group *mdev_dev_groups[] = {
	&mdev_dev_group,
	NULL,
};

static ssize_t name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "%s\n", "amdgpu_vgpu_128mb");

}

static MDEV_TYPE_ATTR_RO(name);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{

	return sprintf(buf, "%d\n", 1);
}

static MDEV_TYPE_ATTR_RO(available_instances);


static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}

static MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};


static struct attribute_group mdev_type_group1 = {
	.name  = "128MB",
	.attrs = mdev_types_attrs,
};

static struct attribute_group *mdev_type_groups[] = {
	&mdev_type_group1,
	NULL,
};

static const struct mdev_parent_ops mdev_fops = {
	.owner                  = THIS_MODULE,
	.mdev_attr_groups       = mdev_dev_groups,
	.supported_type_groups  = mdev_type_groups,
	.create                 = amdgpu_mdev_create,
	.remove			= amdgpu_remove,
	.open                   = amdgpu_open,
	.release                = amdgpu_close,
	.read                   = amdgpu_read,
	.write                  = amdgpu_write,
	.ioctl		        = amdgpu_ioctl,
	.mmap			= amdgpu_mdev_mmap,
};

static void amdgpu_device_release(struct device *dev)
{
	dev_dbg(dev, "amdgpu: released\n");
}

int amdgpu_mdev_init(struct amdgpu_device *adev)
{
	int ret = 0;

	pr_info("amdgpu_dev: %s\n", __func__);

	memset(&amdgpu_mdev, 0, sizeof(amdgpu_mdev));

	idr_init(&amdgpu_mdev.vd_idr);

	amdgpu_mdev.vd_class = class_create(THIS_MODULE, AMDGPU_MDEV_CLASS_NAME);

	if (IS_ERR(amdgpu_mdev.vd_class)) {
		pr_err("Error: failed to register amdgpu_mdev class\n");
		ret = PTR_ERR(amdgpu_mdev.vd_class);
		goto failed1;
	}

	amdgpu_mdev.dev.class = amdgpu_mdev.vd_class;
	amdgpu_mdev.dev.release = amdgpu_device_release;
	dev_set_name(&amdgpu_mdev.dev, "%s", AMDGPU_MDEV_NAME);
	amdgpu_mdev.adev = adev;
	ret = device_register(&amdgpu_mdev.dev);
	if (ret)
		goto failed2;

	ret = mdev_register_device(&amdgpu_mdev.dev, &mdev_fops);
	if (ret)
		goto failed3;

	goto all_done;

failed3:

	device_unregister(&amdgpu_mdev.dev);
failed2:
	class_destroy(amdgpu_mdev.vd_class);
failed1:
	idr_destroy(&amdgpu_mdev.vd_idr);
all_done:
	return ret;
}

void  amdgpu_mdev_exit(void)
{
	amdgpu_mdev.dev.bus = NULL;
	mdev_unregister_device(&amdgpu_mdev.dev);

	device_unregister(&amdgpu_mdev.dev);
	idr_destroy(&amdgpu_mdev.vd_idr);
	class_destroy(amdgpu_mdev.vd_class);
	amdgpu_mdev.vd_class = NULL;
	pr_info("amdgpu_mdev: Unloaded!\n");
}


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

#define IOCTL_TIMEOUT		msecs_to_jiffies(2000)
struct amdgpu_mdev {
	void  *bar0_base;
	u32    *mmio;
	wait_queue_head_t ioctl_wait;
	struct kfifo ioctl_reqs;
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

	printk("mmap vm_address %llu start %llu offset %llu\n", vmf->address, vma->vm_start, page_offset);


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

	printk("mmap vm_start %llu offset %llu\n", vma->vm_start, vma->vm_pgoff);
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

	//printk("priority %u\n", args->in.priority);
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
	//printk("id = %u\n", args->out.alloc.ctx_id);
	return 0;

}

static int amdgpu_mdev_vm_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_VM);

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

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_BO_LIST);

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_bo_list));
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

static int amdgpu_mdev_cs_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_CS);

	kfifo_in(&amdgpu_dev_mdev.ioctl_reqs, &cmd, sizeof(struct guest_ioctl));
	memcpy(amdgpu_dev_mdev.bar0_base + sizeof(struct guest_ioctl),
	       data, sizeof(union drm_amdgpu_cs));
	memcpy(amdgpu_dev_mdev.bar0_base, &cmd, sizeof(struct guest_ioctl));
	amdgpu_mdev_ring_doorbell();
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
	return 0;

}

static int amdgpu_mdev_gem_mmap_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_GEM_MMAP);

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
	memcpy(data, amdgpu_dev_mdev.bar0_base + ret, sizeof(union drm_amdgpu_gem_mmap));
	return 0;

}

static int amdgpu_mdev_sched_ioctl(struct drm_device *dev, void *data, struct drm_file *filp)
{
	int ret = 0;
	struct guest_ioctl cmd;

	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_SCHED);

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

	args->in.bo_size = ALIGN(args->in.bo_size, PAGE_SIZE);
	printk("allocating %lu\n", args->in.bo_size);
	gbo = drm_gem_vram_create(dev, args->in.bo_size, 0);
	ret = drm_gem_vram_pin(gbo, DRM_GEM_VRAM_PL_FLAG_VRAM);
	if (ret)
		return ret;
	amdgpu_mdev_prepare_cmd(&cmd, AMDGPU_GUEST_CMD_IOCTL_GEM_CREATE);
	cmd.bo_offset = drm_gem_vram_offset(gbo);

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
	ret = drm_gem_handle_create(filp, &gbo->bo.base, &args->out.handle);
	if (ret)
		printk("failed to create handle");
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
	return 0;
}
const struct drm_ioctl_desc amdgpu_mdev_ioctls_kms[] = {
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_CREATE, amdgpu_mdev_gem_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_MMAP, amdgpu_mdev_gem_mmap_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_CTX, amdgpu_mdev_ctx_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_BO_LIST, amdgpu_mdev_bo_list_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_CS, amdgpu_mdev_cs_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_VM, amdgpu_mdev_vm_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_SCHED, amdgpu_mdev_sched_ioctl, DRM_MASTER),
	DRM_IOCTL_DEF_DRV(AMDGPU_INFO, amdgpu_mdev_info_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_METADATA, NULL, DRM_AUTH|DRM_RENDER_ALLOW),
	DRM_IOCTL_DEF_DRV(AMDGPU_GEM_VA, amdgpu_mdev_gem_va_ioctl, DRM_AUTH|DRM_RENDER_ALLOW),
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


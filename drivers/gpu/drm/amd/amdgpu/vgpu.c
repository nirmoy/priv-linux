#include "amdgpu.h"


static const struct amd_ip_funcs vgpu_common_ip_funcs = {
	.name = "vgpu_common",
};

static const struct amdgpu_ip_block_version vgpu_common_ip_block =
{
	.type = AMD_IP_BLOCK_TYPE_COMMON,
	.major = 1,
	.minor = 0,
	.rev = 0,
	.funcs = &vgpu_common_ip_funcs,
};

const struct amd_ip_funcs vgpu_gmc_ip_funcs = {
	.name = "gmc_v10_0",
};

const struct amdgpu_ip_block_version vgpu_gmc_ip_block =
{
	.type = AMD_IP_BLOCK_TYPE_GMC,
	.major = 10,
	.minor = 0,
	.rev = 0,
	.funcs = &vgpu_gmc_ip_funcs,
};
const struct amdgpu_nbio_funcs nbio_vgpu_funcs = {};

int vgpu_set_ip_blocks(struct amdgpu_device *adev)
{
	printk("vgpu_set_ip_blocks\n");
	adev->nbio.funcs = &nbio_vgpu_funcs;
	amdgpu_device_ip_block_add(adev, &vgpu_common_ip_block);
	amdgpu_device_ip_block_add(adev, &vgpu_gmc_ip_block);
	return 0;
}


  #ifndef __AMDGPU_MDEV_H__
  #define __AMDGPU_MDEV_H__

void  amdgpu_mdev_exit(void);
int amdgpu_mdev_init(struct amdgpu_device *adev);
int amdgpu_mdev_pci_probe(struct pci_dev *, const struct pci_device_id *);

#endif

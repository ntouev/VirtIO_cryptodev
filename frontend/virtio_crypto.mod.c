#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0xd1b09e08, "module_layout" },
	{ 0x9ee9d2da, "cdev_del" },
	{ 0xe1ea0878, "kmalloc_caches" },
	{ 0xd2b09ce5, "__kmalloc" },
	{ 0xd3725fc4, "cdev_init" },
	{ 0xdaf485b9, "pv_lock_ops" },
	{ 0x3fd78f3b, "register_chrdev_region" },
	{ 0xad27f361, "__warn_printk" },
	{ 0xf5a7a58b, "virtqueue_kick" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x6f26a72a, "nonseekable_open" },
	{ 0x96f093b0, "virtqueue_get_buf" },
	{ 0xb44ad4b3, "_copy_to_user" },
	{ 0xb45439df, "virtqueue_add_sgs" },
	{ 0x3812050a, "_raw_spin_unlock_irqrestore" },
	{ 0x7c32d0f0, "printk" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0x9c1cb9ae, "cdev_add" },
	{ 0x8ff4079b, "pv_irq_ops" },
	{ 0x9770584b, "unregister_virtio_driver" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0x47941711, "_raw_spin_lock_irq" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0xc3c01ffa, "kmem_cache_alloc_trace" },
	{ 0x51760917, "_raw_spin_lock_irqsave" },
	{ 0xb320cc0e, "sg_init_one" },
	{ 0x37a0cba, "kfree" },
	{ 0x362ef408, "_copy_from_user" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0xfccbd1c3, "register_virtio_driver" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=virtio_ring,virtio";

MODULE_ALIAS("virtio:d0000001Ev*");

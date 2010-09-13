#ifndef MODULE
#define MODULE
#endif
#include <linux/module.h>

#include "filter_module.c"

static int __init exp_init(void) {
	printk(KERN_INFO "load experiment\n");
	process_filter();
    return 0;
}

static void __exit exp_exit(void) {
	printk(KERN_INFO "unload experiment\n");
}

module_init(exp_init);
module_exit(exp_exit);
MODULE_DESCRIPTION("example probe");
MODULE_LICENSE("GPL");


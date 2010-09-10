#define MODULE
#include <linux/module.h>

static int __init exp_init(void) {
        printk(KERN_INFO "load experiment\n");
        return 0;
}

static void __exit exp_exit(void) {
        printk(KERN_INFO "unload experiment\n");
}

module_init(exp_init);
module_exit(exp_exit);
MODULE_DESCRIPTION("example probe");
MODULE_LICENSE("GPL");


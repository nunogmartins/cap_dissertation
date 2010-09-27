#ifndef MODULE
#define MODULE
#endif
#include <linux/module.h>

extern int experiment(void);

static int __init other_init(void){

printk(KERN_INFO "load other experiment\n");

	experiment();

return 0;

}


static void __exit other_exit(void) {
	printk(KERN_INFO "unload other experiment\n");
}


module_init(other_init);
module_exit(other_exit);
MODULE_DESCRIPTION("example probe");
MODULE_LICENSE("GPL");


#ifndef MODULE
#define MODULE
#endif
#include <linux/module.h>
#include <linux/moduleparam.h>

static int my_pid;
module_param(my_pid, int , 0);

extern int experiment(int pid);

static int __init other_init(void){

printk(KERN_INFO "load other experiment\n");

	experiment(my_pid);

return 0;

}


static void __exit other_exit(void) {
	printk(KERN_INFO "unload other experiment\n");
}


module_init(other_init);
module_exit(other_exit);
MODULE_DESCRIPTION("example probe");
MODULE_LICENSE("GPL");


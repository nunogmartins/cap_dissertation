#ifndef MODULE
#define MODULE
#endif
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>

//#include "filter_module.c"
struct inode *d_inode = NULL;
unsigned long howMany = 0L;
struct file **fd_array;
struct fdtable *fdt;
struct file **fd;

EXPORT_SYMBOL(fd_array);

static int __init exp_init(void){

d_inode = NULL;
printk(KERN_INFO "load experiment\n");
return 0;

}

int experiment(int pid) {
	struct task_struct *p;
	struct files_struct *files;
//	struct fdtable *fdt;
//	struct file **fd;
	
	for_each_process(p){
		if(p->pid == pid || pid == -1){
			printk(KERN_INFO "pid %d and name %s \n",p->pid, p->comm);
			files = p->files;
			fdt = files->fdt;
			fd_array = files->fd_array;
			fd = fdt->fd;
			
		}
		if(p->pid == pid)
			break;
	}

    return 0;
}

EXPORT_SYMBOL(experiment);

static void __exit exp_exit(void) {
	printk(KERN_INFO "unload experiment\n");
}


module_init(exp_init);
module_exit(exp_exit);
MODULE_DESCRIPTION("example probe");
MODULE_LICENSE("GPL");


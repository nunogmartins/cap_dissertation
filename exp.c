#ifndef MODULE
#define MODULE
#endif
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include "filter_module.c"

/*static int count_open_files(struct fdtable *fdt)
{
	int size = fdt->max_fds;
	int i;
	// Find the last open fd 
	for (i = size/(8*sizeof(long)); i > 0; ) {
		if (fdt->open_fds->fds_bits[--i])
			break;
	}
	i = (i+1) * 8 * sizeof(long);
	return i;
}
*/


static int __init exp_init(void) {
	struct task_struct *p;
	struct files_struct *files;
	unsigned long i;
	int j,k;
	//struct fd_set *fds;
	struct fdtable *fdt;

	for_each_process(p){
		if(p->pid == 1674){
			printk(KERN_INFO "pid %d and name %s \n",p->pid, p->comm);
			files = p->files;
			fdt = files->fdt;
			//fds = fdt->open_fds;
			i = find_last_bit(fdt->open_fds->fds_bits,64);
			for(j=0,k=0;j < (int)i;j++)
			{
				if(fdt->open_fds->fds_bits[j])
					k++;
			}
			printk(KERN_INFO "has %d files openned\n",k);
		}
	}


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


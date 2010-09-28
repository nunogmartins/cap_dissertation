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
#include <linux/socket.h>

//#include "filter_module.c"
struct inode *d_inode = NULL;
unsigned long howMany = 0L;
struct file **fd_array;
struct fdtable *fdt;
struct file **fd;
struct socket *s_other;
struct path f_path;

EXPORT_SYMBOL(fd_array);

static int __init exp_init(void){

d_inode = NULL;
printk(KERN_INFO "load experiment\n");
return 0;

}

int experiment(int pid) {
	struct task_struct *p = NULL;
	struct files_struct *files = NULL;
//	struct fdtable *fdt;
//	struct file **fd;
	int i = 0;
	fd_array = NULL;
	fdt = NULL;
	fd = NULL;
	s_other = NULL;

	for_each_process(p){
		if(p->pid == pid || pid == -1){
			printk(KERN_INFO "pid %d and name %s \n",p->pid, p->comm);
			files = p->files;
			fdt = files->fdt;
			fd_array = files->fd_array;
			fd = fdt->fd;
			for(i=0; i < 32 ; i++)
			{
				struct file *fi = NULL;
				struct dentry *dentry = NULL;
				struct inode *d_inode = NULL;

				fi = *(fd+i);
				if(fi == NULL)
					continue;
				
				f_path = fi->f_path;
				dentry = fi->f_dentry;
				if(dentry == NULL)
					continue;
				d_inode = dentry->d_inode;
				if(d_inode->i_mode == 49663)
				{
					struct socket *s = NULL;
					printk(KERN_INFO "id %d and is a socket\n",i);
					s = (struct socket *)fi->private_data;
					s_other = s;
				
				}else 
					printk(KERN_INFO "id %d and is not a socket\n",i);
			

			}// end of for i
			
		}
		if(p->pid == pid)
			break;
	} //end of for_each_process

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


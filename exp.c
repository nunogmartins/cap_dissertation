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
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/kprobes.h> // -- it's time to get kprobes into the experiment ... 

//#include "filter_module.c"
struct inode *d_inode = NULL;
unsigned long howMany = 0L;
struct file **fd_array;
struct fdtable *fdt;
struct file **fd;
struct socket *s_other;
struct path f_path;

static char func_name[NAME_MAX] = "do_fork";
module_param_string(func, func_name, NAME_MAX, S_IRUGO);
MODULE_PARM_DESC(func, "Function to kretprobe; this module will report the"
			" function's execution time");
extern void process_filter(void);

/* per-instance private data */
struct my_data {
	ktime_t entry_stamp;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_data *data;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct my_data *)ri->data;
	data->entry_stamp = ktime_get();
	return 0;
}

/*
 * Return-probe handler: Log the return value and duration. Duration may turn
 * out to be zero consistently, depending upon the granularity of time
 * accounting on the platform.
 */
static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct my_data *data = (struct my_data *)ri->data;
	s64 delta;
	ktime_t now;
	struct task_struct *task;

	
	task = (struct task_struct *)ri->task;
	printk(KERN_INFO "the application is %s with pid %d.\n",task->comm,task->pid);
	now = ktime_get();
	delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	printk(KERN_INFO "%s returned %d and took %lld ns to execute\n",
			func_name, retval, (long long)delta);

	return 0;
}


EXPORT_SYMBOL(fd_array);

static struct kretprobe my_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.data_size		= sizeof(struct my_data),
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
};


static int __init exp_init(void){

	int ret;
	d_inode = NULL;
	printk(KERN_INFO "load experiment\n");
	
	my_kretprobe.kp.symbol_name = func_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n",
			my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);

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
					struct sock *sk;
					struct sk_buff *skb;
					struct tcp_hdr *tcph;
					struct inet_sock *i_sock;

					printk(KERN_INFO "id %d and is a socket\n",i);
					s = (struct socket *)fi->private_data;
					s_other = s;
					sk = s->sk;
					i_sock = inet_sk(sk);
					printk(KERN_INFO "port = %u \n", i_sock->num);
					
				
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
	unregister_kretprobe(&my_kretprobe);
	printk(KERN_INFO "unload experiment\n");
}


module_init(exp_init);
module_exit(exp_exit);
MODULE_DESCRIPTION("example probe");
MODULE_LICENSE("GPL");


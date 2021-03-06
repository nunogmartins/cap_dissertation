#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/byteorder/generic.h>
#include <asm/uaccess.h>
#include <linux/filter.h>
#include <linux/fdtable.h>

#include "table_port.h"

static long jattach_filter(struct sock_fprog *fprog, struct sock *sk)
{
	int i = 0;
	struct sock_filter *sf = fprog->filter;
	printk(KERN_INFO "inside of the probe");
	
	/*if(fprog->len == 1)
	{
		sf->k = 100;
	}
	else {
		f->code = 6;
	}
	*/

	for(i = 0; i < fprog->len ; i++)
	{
		printk(KERN_INFO "line %03d code is %d jt %d jf %d k %d", i, sf->code, sf->jt, sf->jf, sf->k);
		sf++;
	}	
	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

/* per-instance private data */
struct my_data {
	ktime_t entry_stamp;
};

/* Here we use the entry_hanlder to timestamp function entry */
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct my_data *data;
	struct task_struct *task;
	struct files_struct *files;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	/*task = (struct task_struct *)ri->task;
	if(task != NULL){
		int nextfd = -1;
		files = task->files;
		nextfd = files->next_fd;
		printk(KERN_INFO "on entry handler next fd = %d",nextfd);
	}
*/
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
	struct files_struct *files;	
	struct kretprobe *rp = NULL;
	struct kprobe kp;
	const char *name = NULL;

	if (!current->mm)
		return 1;	/* Skip kernel threads */
	task = (struct task_struct *)ri->task;
	/*if(task != NULL){
		int nextfd = -1;
		files = task->files;
		nextfd = files->next_fd;
		printk(KERN_INFO "on ret handler nextfd = %d",nextfd);
		
	}*/
	//printk(KERN_INFO "the application is %s with pid %d.\n",task->comm,task->pid);
	now = ktime_get();
	rp = ri->rp;
	kp = rp->kp;
name = kp.symbol_name;
	
	delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	printk(KERN_INFO "%s returned %d application %s\n",
	name, retval, task->comm);

	return 0;
}

static struct kretprobe my_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.data_size		= sizeof(struct my_data),
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
};

static struct kretprobe my_socket_kretprobe = {
	.handler		= ret_handler,
	.entry_handler		= entry_handler,
	.data_size		= sizeof(struct my_data),
	/* Probe up to 20 instances concurrently. */
	.maxactive		= 20,
};

static struct jprobe my_jprobe = {
	.entry			= jattach_filter,
	.kp = {
		.symbol_name	= "sk_attach_filter",
	},
};

static int instantiationKRETProbe(struct kretprobe kret,
								const char *function_name,
								kretprobe_handler_t handler,
								kretprobe_handler_t entry_handler)
{
	int ret = -1;
	kret.kp.symbol_name = function_name;
	kret.handler = handler;
	kret.entry_handler = entry_handler;
	ret = register_kretprobe(&kret);
	return ret;
	
}


static int __init jprobe_init(void)
{
	int ret;

	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
	       my_jprobe.kp.addr, my_jprobe.entry);
	

	my_kretprobe.kp.symbol_name = "sys_accept4";
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n",
			my_kretprobe.kp.symbol_name, my_kretprobe.kp.addr);

	my_socket_kretprobe.kp.symbol_name = "sys_socket";

	ret = register_kretprobe(&my_socket_kretprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n",
				ret);
		return -1;
	}
	printk(KERN_INFO "Planted return probe at %s: %p\n",
			my_socket_kretprobe.kp.symbol_name, my_socket_kretprobe.kp.addr);

	return 0;
}

static void __exit jprobe_exit(void)
{
	
	unregister_jprobe(&my_jprobe);
	printk(KERN_INFO "jprobe at %p unregistered\n", my_jprobe.kp.addr);
	
	unregister_kretprobe(&my_kretprobe);
	printk(KERN_INFO "kretprobe at %p unregistered\n", my_kretprobe.kp.addr);
	
	unregister_kretprobe(&my_socket_kretprobe);
	printk(KERN_INFO "kretprobe at %p unregistered\n", my_socket_kretprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");

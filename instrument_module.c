#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/byteorder/generic.h>
#include <asm/uaccess.h>
#include <linux/filter.h>
#include <linux/fdtable.h>

#include "table_port.h"

struct kretprobe *kretprobes = NULL;
struct jprobe *jprobes = NULL;

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task;
	struct files_struct *files;

	if (!current->mm)
		return 1;	/* Skip kernel threads */

	data = (struct my_data *)ri->data;
	data->entry_stamp = ktime_get();
	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct task_struct *task;
	struct files_struct *files;
	struct kretprobe *rp = NULL;
	struct kprobe kp;
	const char *name = NULL;

	if (!current->mm)
		return 1;	/* Skip kernel threads */
	task = (struct task_struct *)ri->task;

	rp = ri->rp;
	kp = rp->kp;
    name = kp.symbol_name;

	printk(KERN_INFO "%s returned %d application %s\n",
	name, retval, task->comm);

	return 0;
}



static int instantiationKRETProbe(struct kretprobe *kret,
								const char *function_name,
								kretprobe_handler_t handler,
								kretprobe_handler_t entry_handler)
{
	int ret = -1;
	kret->kp.symbol_name = function_name;
	kret->handler = handler;
	kret->entry_handler = entry_handler;
	kret->data_size		= 0;
	kret->maxactive		= 20;

	ret = register_kretprobe(kret);
	return ret;

}


static int __init instrument_init(void)
{
    int ret = -1;
    kretprobes = kmalloc(sizeof(*kretprobes)*2,GFP_KERNEL);
    ret = instantiationKRETProbe(kretprobes,"sys_socket",ret_handler,ret_handler);

    if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	printk(KERN_INFO "Planted kretprobe at %p, handler addr %p\n",
	       kretprobes->kp.addr, kretprobes->entry);


    //register all probes
	return 0;
}

static void __exit instrument_exit(void)
{
    //unregister all probes ...
    unregister_kretprobe(kretprobes);
	printk(KERN_INFO "kretprobe at %p unregistered\n", kretprobes->kp.addr);

    if(kretprobes)
        kfree(kretprobes);
    if(jprobes)
        kfree(jprobes);
}

module_init(instrument_init)
module_exit(instrument_exit)
MODULE_LICENSE("GPL");


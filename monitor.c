/*
 * monitor.c
 *
 *  Created on: Nov 8, 2010
 *      Author: nuno
 */

#include <linux/module.h>
#include <linux/kprobes.h>

struct kretprobe *kretprobes = NULL;
struct jprobe *jprobes = NULL;
char *application_name = "server";

extern int init_debug(void);
extern void destroy_debug(void);

extern int init_kretprobes_common(int *initial);
extern int init_kretprobes_tcp(int *initial);
extern int init_kretprobes_udp(int *initial);

#define NR_PROBES 6

void print_regs(const char *function, struct pt_regs *regs)
{
	printk(KERN_INFO "%s ax=%p bx=%p cx=%p dx=%p bp=%p sp=%p",
			function, (void *)regs->ax,(void *)regs->bx,(void *)regs->cx,
			(void *)regs->dx,(void*)regs->bp,(void *) regs->sp);
}

int instantiationKRETProbe(struct kretprobe *kret,
								const char *function_name,
								kretprobe_handler_t func_handler,
								kretprobe_handler_t func_entry_handler)
{
	int ret = -1;

	struct kprobe kp = {
	.symbol_name = function_name,
	};

	kret->kp = kp;
	kret->handler = func_handler;
	kret->entry_handler = func_entry_handler;
	kret->data_size		= 0;
	kret->maxactive		= 20;

	ret = register_kretprobe(kret);
    if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	printk(KERN_INFO "Planted kretprobe at %p, handler addr %p\n",
	       kret->kp.symbol_name, kret->kp.addr);

	return ret;
}

static int __init monitor_init(void)
{
	int index = 0;
	int ret = -1;
	kretprobes = kmalloc(sizeof(*kretprobes)*NR_PROBES,GFP_KERNEL);
	if(!lsm){
		printk(KERN_INFO "problem allocating memory");
		return -1;
	}

	ret = init_kretprobes_common(&index);
	if(ret < 0)
	{
		printk(KERN_INFO "problem in common");
		goto problem;
	}

	ret = init_kretprobes_tcp(&index);
	if(ret < 0)
	{
		printk(KERN_INFO "problem in tcp");
		goto problem;
	}

	ret = init_kretprobes_udp(&index);
	if(ret < 0)
	{
		printk(KERN_INFO "problem in udp");
		goto problem;
	}

	return 0;

problem:
	kfree(kretprobes);
	return 0;
}

static void removeKprobe(int index)
{
	printk(KERN_INFO "missed %d probes" , (kretprobes)->nmissed);
	unregister_kretprobe((kretprobes+index));
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+index)->kp.addr);
}

static void __exit monitor_exit(void)
{
	int i=0;
	destroy_debug();
	//unregister all probes ...
	for(i=0; i < NR_PROBES ; i++)
	{
		removeKprobe(i);
	}

	if(kretprobes)
		kfree(kretprobes);
}
module_init(monitor_init)
module_exit(monitor_exit)
MODULE_LICENSE("GPL");

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



static int __init monitor_init(void)
{
	int index = 0;
	int ret = -1;
	kretprobes = kmalloc(sizeof(*kretprobes)*NR_PROBES,GFP_KERNEL);
	if(!kretprobes){
		printk(KERN_INFO "problem allocating memory");
		return -1;
	}

	ret = init_kretprobes_common(&index);
	if(!ret)
	{
		//problem ...
	}

	ret = init_kretprobes_tcp(&index);
	if(!ret)
	{
		//problem ...
	}

	ret = init_kretprobes_udp(&index);
	if(!ret)
	{
		//problem ...
	}

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

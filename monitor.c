/*
 * monitor.c
 *
 *  Created on: Nov 8, 2010
 *      Author: nuno
 */

#include "config.h"

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/skbuff.h>
#include <linux/list.h>

#include "pcap_monitoring.h"
#include "table_port.h"
#include "portsDB.h"

struct kretprobe *kretprobes = NULL;
struct jprobe *jprobes = NULL;
char *application_name = "server";
struct local_addresses_list *local_list = NULL;


pid_t monitor_pid;

/*
* extern from linux kernel
* net/core/filter.c
*/

/*struct packetInfo {
	u8 proto;
	u16 srcPort, dstPort;
	u32 srcAddr, dstAddr;
};
*/

extern unsigned int (*portExists)(struct packetInfo *src_pi,struct packetInfo *dst_pi);
unsigned int (*Backup_portExists)(struct packetInfo *pi,struct packetInfo *dst_pi);

extern struct rb_root db;

extern int init_debug(void);
extern void destroy_debug(void);

extern int init_kretprobes_syscalls(int *index);
extern int populate(void);
extern int depopulate(void);
/*extern int init_kretprobes_common(int *initial);
extern int init_kretprobes_tcp(int *initial);
extern int init_kretprobes_udp(int *initial);
*/

#define NR_PROBES 7

void print_regs(const char *function, struct pt_regs *regs)
{
	printk(KERN_INFO "%s ax=%p bx=%p cx=%p dx=%p bp=%p sp=%p",
			function, (void *)regs->ax,(void *)regs->bx,(void *)regs->cx,
			(void *)regs->dx,(void*)regs->bp,(void *) regs->sp);
}

int instantiationKRETProbe(struct kretprobe *kret,
								const char *function_name,
								kretprobe_handler_t func_handler,
								kretprobe_handler_t func_entry_handler,
								ssize_t data_size)
{
	int ret = -1;

	struct kprobe kp = {
	.symbol_name = function_name,
	};

	kret->kp = kp;
	kret->handler = func_handler;
	kret->entry_handler = func_entry_handler;
	kret->data_size		= data_size;
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

unsigned int my_portExists(struct packetInfo *src_pi,struct packetInfo *dst_pi)
{
	struct portInfo *sentinel_src = NULL;
	struct portInfo *sentinel_dst = NULL;

	if(src_pi!=NULL && dst_pi!=NULL)
	{
		if(src_pi->protocol == 0x11 || src_pi->protocol == 0x06){

			printk(KERN_INFO "proto 0x%x srcadd 0x%x dstaddr 0x%x srcP %hu dstP %hu", src_pi->protocol,src_pi->address, dst_pi->address,src_pi->port, dst_pi->port );

			sentinel_src = my_search(&db,src_pi);
			printAll(&db);

			if(sentinel_src != NULL)
			{
				printk(KERN_INFO "found src port %hu",src_pi->port);
#ifdef OLD_PHASE

				if(/*sentinel_src->address == pi->srcAddr && */sentinel_src->protocol == src_pi->protocol)
				{
					return 1;
				}
#endif
				return 1;
			}

			sentinel_dst = my_search(&db,dst_pi);

			if(sentinel_dst != NULL)
			{
				printk(KERN_INFO "found dst port %hu",dst_pi->port);

#ifdef OLD_PHASE
				if(/*sentinel_dst->address == pi->dstAddr && */ sentinel_dst->protocol == dst_pi->protocol)
				{
					return 1;
				}
				else
					return 0;
#endif
				return 1;
			}

		}
	}

	return 0;
}

static int __init monitor_init(void)
{

	int index = 0;
	int ret = -1;

	monitor_pid = -1;

	kretprobes = kmalloc(sizeof(*kretprobes)*NR_PROBES,GFP_KERNEL);
	if(!kretprobes){
		printk(KERN_INFO "problem allocating memory");
		return -1;
	}
/*
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
*/
#ifdef MY_KPROBES
	ret = init_kretprobes_syscalls(&index);
	if(ret < 0)
	{
		printk(KERN_INFO "problem in syscalls");
		goto problem;
	}
#endif

	init_debug();
	
	Backup_portExists = portExists;
	local_list = listAllDevicesAddress();

#ifdef UNIT_TESTING
	populate();
#endif
	return 0;
#ifdef MY_KPROBES
problem:
	/* ToDo:todos os probes que ja foram registados têm de ser desregistados
	 */
	kfree(kretprobes);
	return 0;
#endif
}

static void removeKprobe(int index)
{
	if((kretprobes+index)!=NULL){
		printk(KERN_INFO "in index %d missed %d probes" , index,(kretprobes+index)->nmissed);
		unregister_kretprobe((kretprobes+index));
		printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+index)->kp.addr);
	}
}

static void __exit monitor_exit(void)
{
	int i=0;
	int ret = -1;

	destroy_debug();
	//unregister all probes ...
#ifdef MY_KPROBES
	for(i=0; i < NR_PROBES ; i++)
	{
		removeKprobe(i);
	}
#endif
	if(kretprobes)
		kfree(kretprobes);

	portExists = Backup_portExists;
#ifdef UNIT_TESTING
	depopulate();
#endif

	ret = remove_local_addresses_list(local_list);
	if(ret == 0)
		kfree(local_list);

}

void initializeTreeWithTaskInfo(pid_t new_pid)
{
	struct task_struct *t;
	monitor_pid = new_pid;

	portExists = my_portExists;

	for_each_process(t)
	{
		if (t->pid == monitor_pid || t->real_parent->pid == monitor_pid)
		{
			//ToDo: change all structures according to pid
			//ToDo: get all ports from the task that has new_pid

			struct files_struct *files;
			struct file **fd;
			struct fdtable *fdt;

			files = t->files;
			fdt = files->fdt;
#ifdef MY_DEBUG	
			printk(KERN_INFO "application %s with pid %lu", t->comm,(unsigned long)t->pid);
#endif
			while(fdt!=NULL)
			{
				unsigned long file_descriptor = 0;
				struct file *file;

				fd = fdt->fd;
				for(file_descriptor=0; file_descriptor < fdt->max_fds; file_descriptor++)
				{
					if((file=fd[file_descriptor]) != NULL){
						struct localPacketInfo *p = getLocalPacketInfoFromFile(file);
						if(p!=NULL)
						{
#ifdef MY_DEBUG
							printk(KERN_INFO "iteration %lu is socket",file_descriptor);
#endif
							insertPort(p);
							kfree(p); //it was allocated in localPacketInfo
						}
					}
				}
				//end of for or while more internal ...
				fdt = fdt->next; //verifica se existem mais fdtable
			}  //end of while / no more fdtables in files_struct

		}
	}
}

module_init(monitor_init)
module_exit(monitor_exit)
MODULE_LICENSE("GPL");

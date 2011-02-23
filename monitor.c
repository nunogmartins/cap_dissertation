/*
 * monitor.c
 *
 *  Created on: Nov 8, 2010
 *      Author: nuno
 */
#ifndef MODULE
#define MODULE
#endif

#include "config.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/sched.h>
#include "pcap_monitoring.h"
#include "table_port.h"
#include "portsDB.h"

struct kretprobe *kretprobes = NULL;
struct jprobe *jprobes = NULL;
char *application_name = "server";
struct local_addresses_list *local_list = NULL;



static void monitor_exit(void);
static int  monitor_init(void);

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");



pid_t monitor_pid;
int kprobes_index;

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

#ifdef MY_KPROBES
extern int init_kretprobes_syscalls(int *index);
#endif

#ifdef UNIT_TESTING
extern int populate(void);
extern int depopulate(void);
#endif
/*extern int init_kretprobes_common(int *initial);
extern int init_kretprobes_tcp(int *initial);
extern int init_kretprobes_udp(int *initial);
*/

#define NR_PROBES 7

void print_regs(const char *function, struct pt_regs *regs)
{
#ifdef CONFIG_X86_64
	pr_emerg( "%s ax=%p bx=%p cx=%p dx=%p di=%p si=%p r8=%p r9=%p",function, (void *)regs->ax,(void *)regs->bx,(void *)regs->cx,(void *)regs->dx,(void*)regs->di,(void *) regs->si,(void *)regs->r8,(void *)regs->r9);
#endif
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
		pr_info( "register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	pr_info( "Planted kretprobe at %p, handler addr %p\n",
	       kret->kp.symbol_name, kret->kp.addr);

	return ret;
}

unsigned int my_portExists(struct packetInfo *src_pi,struct packetInfo *dst_pi)
{

	struct portInfo *sentinel_src = NULL;
	struct portInfo *sentinel_dst = NULL;

	if(src_pi!=NULL && dst_pi!=NULL)
	{

		if((src_pi->protocol == 0x11 || src_pi->protocol == 0x06)){

			sentinel_src = my_search(&db,src_pi);

			if(sentinel_src != NULL)
			{
#ifdef MY_DEBUG
				pr_emerg( "found src port %hu",src_pi->port);
#endif
				return 1;
			}

			sentinel_dst = my_search(&db,dst_pi);

			if(sentinel_dst != NULL)
			{
#ifdef MY_DEBUG
				pr_emerg( "found dst port %hu",dst_pi->port);
#endif
				return 1;
			}

		}
	}

	return 0;
}

static int monitor_init(void)
{
#ifdef MY_KPROBES
	int ret = -1;
	kprobes_index = 0;
	monitor_pid = -1;

	kretprobes = kmalloc(sizeof(*kretprobes)*NR_PROBES,GFP_KERNEL);
	if(!kretprobes){
		pr_info( "problem allocating memory");
		return -1;
	}

	ret = init_kretprobes_syscalls(&kprobes_index);
	if(ret < 0)
	{
		pr_info( "problem in syscalls");
		goto problem;
	}
#endif

	init_debug();
	
	Backup_portExists = portExists;
	portExists = my_portExists;
	local_list = listAllDevicesAddress();

#ifdef UNIT_TESTING
	populate();
#endif



#ifdef MY_KPROBES
problem:
	/* ToDo:todos os probes que ja foram registados têm de ser desregistados
	 */
	kfree(kretprobes);
#endif

	return 0;
}

#ifdef MY_KPROBES
static void removeKprobe(int index)
{
	if((kretprobes+index)!=NULL){
		pr_info( "in index %d missed %d probes" , index,(kretprobes+index)->nmissed);
		unregister_kretprobe((kretprobes+index));
		pr_info( "kretprobe at %p named %s unregistered\n", (kretprobes+index)->kp.addr, (kretprobes+index)->kp.symbol_name);
	}
}
#endif

static void monitor_exit(void)
{
#ifdef MY_KPROBES
	int i=0;
	int ret = -1;
#endif

	destroy_debug();
	//unregister all probes ...
#ifdef MY_KPROBES
	for(i=0; i < kprobes_index ; i++)
	{
		removeKprobe(i);
	}

	if(kretprobes)
		kfree(kretprobes);
#endif


#ifdef UNIT_TESTING
	depopulate();
#endif

	portExists = Backup_portExists;
	ret = remove_local_addresses_list(local_list);
	if(ret == 0)
		kfree(local_list);
	//ToDo: need to destroy the portTree ....
	//ToDo: clear the memory leak ...

}

void initializeTreeWithTaskInfo(pid_t new_pid)
{
	struct task_struct *t;
	monitor_pid = new_pid;

	for_each_process(t){
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
			pr_info( "application %s with pid %lu", t->comm,(unsigned long)t->pid);
#endif
			while(fdt!=NULL)
			{
				unsigned long file_descriptor = 0;
				struct file *file;

				fd = fdt->fd;
				for(file_descriptor=0; file_descriptor < fdt->max_fds; file_descriptor++)
				{
					if((file=fd[file_descriptor]) != NULL){
						struct packetInfo p;
						int err;
						getLocalPacketInfoFromFile(file,&p,&err);
						if(err == 0)
						{
#ifdef MY_DEBUG
							pr_info( "iteration %lu is socket",file_descriptor);
#endif
							if(insertPort(&p) > 0){
#ifdef MY_DEBUG
								pr_info("insertion was ok");
#endif
							}

							else{
#ifdef MY_DEBUG
								pr_info("something was wrong with the insertion");
#endif
							}

						}
					}
				}
				//end of for or while more internal ...
				fdt = fdt->next; //verifica se existem mais fdtable
			}  //end of while / no more fdtables in files_struct

		}
	}
}




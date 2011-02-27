/*
 * monitor.c
 *
 *  Created on: Nov 8, 2010
 *      Author: nuno
 */
#include "config.h"

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/sched.h>

#include "pcap_monitoring.h"
#include "table_port.h"
#include "filter.h"
#include "debugfs_support.h"

#ifdef MY_KPROBES
#include "syscalls_monitor.h"
#endif

char *application_name = "server";
struct local_addresses_list *local_list = NULL;


static void monitor_exit(void);
static int  monitor_init(void);

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");

pid_t monitor_pid;

#ifdef UNIT_TESTING
extern int populate(void);
extern int depopulate(void);
#endif

static int monitor_init(void)
{

#ifdef MY_KPROBES
	int kretprobes_number = init_kretprobes_syscalls();
	pr_info("Loaded %d probes", kretprobes_number);
	if(kretprobes_number < 0)
		goto problem;
#endif

	monitor_pid = -1;

	init_debug();
	
	backupFilter();

	local_list = listAllDevicesAddress();

#ifdef UNIT_TESTING
	populate();
#endif

	return 0;

#ifdef MY_KPROBES
problem:
	destroy_kretprobes_syscalls();
	return -1;
#endif
}

static void monitor_exit(void)
{
#ifdef MY_KPROBES
	int ret = -1;
#endif

	destroy_debug();
	//unregister all probes ...
#ifdef MY_KPROBES
	destroy_kretprobes_syscalls();
#endif

#ifdef UNIT_TESTING
	depopulate();
#endif

	restoreFilter();
	clearInfo();
	ret = remove_local_addresses_list(local_list);
	if(ret == 0)
		kfree(local_list);
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

			pr_info( "application %s with pid %lu", t->comm,(unsigned long)t->pid);

			while(fdt != NULL)
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
							if(insertPort(&p) > 0){
								pr_info("insertion was ok");
							}
							else{
								pr_info("something was wrong with the insertion");

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

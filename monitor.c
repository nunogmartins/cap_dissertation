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

static int loadSubSystems(void)
{

#ifdef DEBUGFS_SUPPORT
	init_debug();
#endif

#ifdef FILTER_SUPPORT
	init_Filter();
#endif

#ifdef DB_SUPPORT
	init_DB();
#endif

#ifdef SYSCALLS_SUPPORT
#ifdef MY_KPROBES
	pr_info("Loaded %d probes", init_kretprobes_syscalls());
#endif
#endif
	return 0;
}

static int unloadSubSystems(void)
{
#ifdef DEBUGFS_SUPPORT
	destroy_debug();
#endif

#ifdef FILTER_SUPPORT
	exit_Filter();
#endif

#ifdef DB_SUPPORT
	exit_DB();
#endif

#ifdef SYSCALLS_SUPPORT
#ifdef MY_KPROBES
	destroy_kretprobes_syscalls();
#endif
#endif

	return 0;
}

static int monitor_init(void)
{
	monitor_pid = -1;

	loadSubSystems();

	local_list = listAllDevicesAddress();

#ifdef UNIT_TESTING
	populate();
#endif

	return 0;
}

static void monitor_exit(void)
{
	int ret = -1;

	unloadSubSystems();

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

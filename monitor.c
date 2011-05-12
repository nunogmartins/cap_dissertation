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
#include "pcap_monitoring.h"
#include "table_port.h"
#include "filter.h"
#include "debugfs_support.h"

#ifdef MY_KPROBES
#include "syscalls_monitor.h"
#endif

char *application_name = "server";
struct local_addresses_list *local_list = NULL;

//#ifdef UNIT_TESTING
extern int populate(void);
extern int depopulate(void);
//#endif

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

//    populate();

#ifdef SYSCALLS_SUPPORT
#ifdef MY_KPROBES
	my_print_debug("Loaded %d probes", init_kretprobes_syscalls());
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

//    depopulate();

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

static int __init monitor_init(void)
{
	loadSubSystems();

	local_list = listAllDevicesAddress();

#ifdef UNIT_TESTING
	populate();
#endif

	return 0;
}

static void __exit monitor_exit(void)
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

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");

/*
 * filter.c
 *
 *  Created on: Feb 27, 2011
 *      Author: nuno
 */


#include "config.h"
#include "pcap_monitoring.h"
#include "table_port.h"
#include "debugfs_support.h"

#ifdef MY_DEBUG
#include "info_acquire.h"

struct filter_info_acquire filter_info = {
		.entry = 0,
		.src = 0, 
		.dst = 0 };

#endif

extern unsigned int (*portExists)(struct packetInfo *src_pi,struct packetInfo *dst_pi);
unsigned int (*Backup_portExists)(struct packetInfo *pi,struct packetInfo *dst_pi);

u64 how_many_times;
u64 search_on_src;
u64 found_on_src;
u64 search_on_dst;
u64 found_on_dst;

unsigned int my_portExists(struct packetInfo *src_pi,struct packetInfo *dst_pi)
{

	int sentinel_src = -1;
	int  sentinel_dst = -1;
	how_many_times++;
#ifdef MY_DEBUG
	filter_info.entry++;
#endif
	/* pr_info("src addr %d.%d.%d.%d port %d dst addr %d.%d.%d.%d port %d and protocol %d\n",
		NIPQUAD(src_pi->address),src_pi->port,NIPQUAD(dst_pi->address),dst_pi->port,src_pi->protocol); */
	
	if(src_pi!=NULL && dst_pi!=NULL)
	{

		if((src_pi->protocol == UDP || src_pi->protocol == TCP)){

			sentinel_src = searchPort(src_pi);

			if(sentinel_src)
			{
#ifdef MY_DEBUG
				filter_info.src++;
#endif
				return 1;
			}

			sentinel_dst = searchPort(dst_pi);

			if(sentinel_dst)
			{
#ifdef MY_DEBUG
				filter_info.dst++;
#endif
				return 1;
			}

		}
	}

	return 0;
}

static void backupFilter(void)
{
	Backup_portExists = portExists;
	portExists = my_portExists;
}

static void restoreFilter(void){
	portExists = Backup_portExists;
}

static const struct file_operations filter_stats_fops = {
		.owner = THIS_MODULE,
		//.write = pid_write,
		//.read =
};

int init_Filter(void)
{
	backupFilter();
	how_many_times = 0;
	register_filter_calls(&how_many_times);
	register_debugfs_file("filter_stats",&filter_stats_fops);
	return 0;
}
void exit_Filter(void)
{
	restoreFilter();
}

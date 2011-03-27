/*
 * filter.c
 *
 *  Created on: Feb 27, 2011
 *      Author: nuno
 */

#include <linux/debugfs.h>

#include "config.h"
#include "pcap_monitoring.h"
#include "table_port.h"
#include "debugfs_support.h"

#ifdef MY_DEBUG
#include "info_acquire.h"

struct filter_info_acquire filter_info = {
		.entry = 0,
		.src = 0, 
		.dst = 0,
		.rejected = 0
};


static void *filter_seq_start(struct seq_file *p, loff_t *pos)
{
	if(*pos > 0)
		return NULL;
	else
		return &filter_info;
}

static void *filter_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	return NULL;
}

static void filter_seq_stop(struct seq_file *p, void *v)
{

}

static int filter_seq_show(struct seq_file *m, void *v)
{
	struct filter_info_acquire *info = NULL;
	if(v != NULL)
	{
		info = v;
		seq_printf(m,"how many entries %ld it has src %ld searches and dst "
				"searches %ld and %ld rejected\n",info->entry, info->src,
				info->dst,info->rejected);
	}else
	{
		seq_printf(m,"V is null\n");
	}
	return 0;

}

static const struct seq_operations filter_seq_ops = {
        .start  = filter_seq_start,
        .next   = filter_seq_next,
        .stop   = filter_seq_stop,
        .show   = filter_seq_show,
};

static int filter_open(struct inode *inode, struct file *file)
{
	return seq_open(file,&filter_seq_ops);
}

static int filter_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations filter_fops = {
        .open           = filter_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        //.release        = filter_release,
        .release = seq_release,
        .owner          = THIS_MODULE,
 };

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
	/* my_print_debug("src addr %d.%d.%d.%d port %d dst addr %d.%d.%d.%d port %d and protocol %d\n",
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
	filter_info.rejected++;
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
	struct dentry *parent;
	backupFilter();

	parent = createFilterStatDir();
	debugfs_create_file("stats",S_IRUSR,parent,NULL,&filter_fops);
	how_many_times = 0;
	register_filter_calls(&how_many_times);
	register_debugfs_file("filter_stats",&filter_stats_fops);
	return 0;
}
void exit_Filter(void)
{
	restoreFilter();
}

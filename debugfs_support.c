#include "config.h"

#include <linux/types.h>
#include <linux/debugfs.h>


#include "table_port.h"

struct dentry *my_debug_dir = NULL;
#ifdef MY_DEBUG
#include "info_acquire.h"
struct info_acquire d_info;
#endif

int init_debug(void)
{
	my_debug_dir = debugfs_create_dir("pcap_debug",NULL);
	if(!my_debug_dir)
	{
		pr_info("impossible to create pcap_debug directory");
		return -1;
	}	
	pr_info( "debug activated");
	return 0;
}

void destroy_debug(void)
{
	debugfs_remove_recursive(my_debug_dir);
	pr_info( "debug deactivated");
}

int register_debugfs_file(const char *name, const struct file_operations *fops)
{
	struct dentry *dentry;
	dentry = debugfs_create_file(name,S_IRUGO,my_debug_dir,NULL,fops);

	return 0;
}

void register_filter_calls(u64 *data)
{
	debugfs_create_u64("filter_calls",S_IRUSR,my_debug_dir,data);
}

void register_monitor_id(const char *name, u64 *data)
{
	debugfs_create_u64(name,S_IWUSR|S_IRUGO,my_debug_dir,data);
}

struct dentry *createMonitorStatDir(void)
{
	return debugfs_create_dir("monitor",my_debug_dir);
}

struct dentry *createFilterStatDir(void)
{
	return debugfs_create_dir("filter",my_debug_dir);
}

struct dentry *createDBStatDir(void)
{
	return debugfs_create_dir("db",my_debug_dir);
}

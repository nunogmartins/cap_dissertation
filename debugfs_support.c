#include <linux/debugfs.h>

static struct dentry *my_debug_dir = NULL;

int init_debug(void)
{
	my_debug_dir = debugfs_create_dir("pcap_debug",NULL);
	if(!my_debug_dir)
	{
		printk(KERN_INFO "impossible to create pcap_debug directory");
		return -1;
	}

	
	printk(KERN_INFO "debug activated");
	return 0;
}

void destroy_debug(void)
{
	debugfs_remove_recursive(my_debug_dir);
	printk(KERN_INFO "debug deactivated");
}


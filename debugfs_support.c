#include <linux/module.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/types.h>

static struct dentry *my_debug_dir = NULL;
extern pid_t monitor_pid;



static ssize_t pid_write(struct file *file, const char __user *user_buf,size_t size, loff_t *ppos)
{
	printk(KERN_INFO "heypidddddddddddddd");
	return 0;
}


static const struct file_operations pid_fops = {
		.owner = THIS_MODULE,
		.write = pid_write,
};

int init_debug(void)
{
	struct dentry *dentry;

	my_debug_dir = debugfs_create_dir("pcap_debug",NULL);
	if(!my_debug_dir)
	{
		printk(KERN_INFO "impossible to create pcap_debug directory");
		return -1;
	}

	dentry = debugfs_create_file("pid_monitor",S_IRUGO,my_debug_dir,NULL,&pid_fops);
	
	printk(KERN_INFO "debug activated");
	return 0;
}

void destroy_debug(void)
{
	debugfs_remove_recursive(my_debug_dir);
	printk(KERN_INFO "debug deactivated");
}


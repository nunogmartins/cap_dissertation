#include <linux/module.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/types.h>
#include <asm/uaccess.h>

static struct dentry *my_debug_dir = NULL;

extern pid_t monitor_pid;
extern void initializeTreeWithTaskInfo(pid_t pid);

static ssize_t pid_write(struct file *file, const char __user *user_buf,size_t size, loff_t *ppos)
{
	unsigned long pid;
	char *buf;
	char *endp;

	printk(KERN_INFO "pid_write function called");
	buf = kmalloc(size,GFP_KERNEL);

	copy_from_user(buf,user_buf,size);	
	/*
	 * ToDo: actualizar todas as estruturas necessárias ao funcionamento da monitorização inclusivé
	 * o pid
	 * Esta função irá fazer o parsing do pid
	 * Se for -1 irá limpar todas as estruturas, se for diferente de -1 reinicia o processo de
	 * monitorização
	 *
	 */
	pid = simple_strtoul(buf,&endp,10);
	if(endp == buf)
	{
		printk(KERN_INFO "could not convert value into long");
		return size;
	}
	kfree(buf);
	printk(KERN_INFO "pid = %lu",pid);
	
	initializeTreeWithTaskInfo((size_t) pid);

	return size;
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


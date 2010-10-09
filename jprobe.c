#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/byteorder/generic.h>
#include <asm/uaccess.h>

static long jdo_bind(int a, struct sockaddr __user * b, int c)
{
	struct sockaddr *saddr = NULL;
	struct sockaddr_in *saddrin = NULL;
	int port = -1;

	printk(KERN_INFO "size of sddar %d bytes",sizeof(*b));
	saddr=(struct sockaddr *)kmalloc(sizeof(*b),GFP_KERNEL);
	copy_from_user(saddr,b,sizeof(*b));
	saddrin = (struct sockaddr_in *)saddr;
	port = ntohs(saddrin->sin_port);
	printk(KERN_INFO "jprobe: hit and port %d ", port );
	kfree(saddr);
	/* Always end with a call to jprobe_return(). */
	jprobe_return();
	return 0;
}

static struct jprobe my_jprobe = {
	.entry			= jdo_bind,
	.kp = {
		.symbol_name	= "sys_bind",
	},
};

static int __init jprobe_init(void)
{
	int ret;

	ret = register_jprobe(&my_jprobe);
	if (ret < 0) {
		printk(KERN_INFO "register_jprobe failed, returned %d\n", ret);
		return -1;
	}
	printk(KERN_INFO "Planted jprobe at %p, handler addr %p\n",
	       my_jprobe.kp.addr, my_jprobe.entry);
	return 0;
}

static void __exit jprobe_exit(void)
{
	unregister_jprobe(&my_jprobe);
	printk(KERN_INFO "jprobe at %p unregistered\n", my_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");

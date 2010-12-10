#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "table_port.h"
#include "portsDB.h"
/*
* need to create a list with all ports in use
*/

extern struct rb_root db;

int insertPort(u16 port)
{
	int ret;
	struct portInfo *p = NULL;
	printk(KERN_INFO "inserting port %hu", port);

	p = kmalloc(sizeof(*p),GFP_KERNEL);
	p->port = port;

	ret = my_insert(&db,p);
	printAll(&db);
	return -ENOTIMPLEMENTED;
}

int deletePort(u16 port)
{
	printk(KERN_INFO "deleting port %hu",port);
	my_erase(&db,port);
	return 0;
}


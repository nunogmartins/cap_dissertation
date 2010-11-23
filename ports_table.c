#include <linux/kernel.h>
#include <linux/rbtree.h>
#include "table_port.h"
#include "portsDB.h"
/*
* need to create a list with all ports in use
*/

extern struct rb_root db;

int insertPort(int port)
{
	printk(KERN_INFO "inserting port %d", port);
	my_insert(&db,port);
	return -ENOTIMPLEMENTED;
}

int deletePort(int port)
{
	printk(KERN_INFO "deleting port %d",port);
	my_erase(&db,port);
	return 0;
}


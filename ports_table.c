#include <linux/list.h>
#include "table_port.h"
/*
* need to create a list with all ports in use
*/
int insertPort(int port)
{
	printk(KERN_INFO "inserting port %d", port);
	return -ENOTIMPLEMENTED;
}

int deletePort(int port)
{
	printk(KERN_INFO "deleting port %d",port);
	return 0;
}

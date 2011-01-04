#include "config.h"

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "table_port.h"
#include "portsDB.h"
#include "pcap_monitoring.h"

/*
* need to create a list with all ports in use
*/

extern struct rb_root db;

int insertPort(struct localPacketInfo *lpi)
{
	int ret;
	struct portInfo *p = NULL;

	if(lpi == NULL){
#ifdef MY_DEBUG
	printk(KERN_INFO "in insert lpi is null");
#endif
		return 	-1;
	}
	printk(KERN_INFO "inserting port %hu with address 0x%x being %hu", lpi->port, lpi->address, lpi->proto);
	
	if(lpi->port == 0 || lpi->address == 0 || lpi->proto == 0)
		return -1;

	printk(KERN_INFO "are not zero ...");
	p = kmalloc(sizeof(*p),GFP_KERNEL);
	p->port = lpi->port;

	p->protocol = lpi->proto;

	if(lpi->address == 0)
	{
		//ToDo: point the global addresses to this value in p structure
	}else
	{
		//ToDo: add to a list of addresses
				p->address = lpi->address;
	}

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


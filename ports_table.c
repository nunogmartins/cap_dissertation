#include "config.h"

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "table_port.h"
#include "portsDB.h"
#include "pcap_monitoring.h"

/*
* need to create a list with all ports in use
*/

extern struct rb_root db;
extern struct local_addresses_list *local_list;

static int addAddress(struct localPacketInfo *lpi, struct portInfo *port_info)
{

	struct local_addresses_list *tmp = NULL;

	switch(lpi->proto){

	case 0x06:
		if(lpi->address == 0)
			port_info->tcp = local_list;
		else
		{
			//ToDo: add to a list of addresses
			//p->address = lpi->address;
			//ToDo: function to add address to portInfo
		}
		break;
	case 0x11:
		if(lpi->address == 0)
			port_info->udp = local_list;
		else
		{
			//ToDo: add to a list of addresses
			//p->address = lpi->address;
			//ToDo: function to add address to portInfo
		}
		break;

	default:
		break;
	}
	return 1;
}

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

#ifdef MY_DEBUG
	printk(KERN_INFO "inserting port %hu with address 0x%x being %hu", lpi->port, lpi->address, lpi->proto);
#endif

	if(lpi->port == 0 || lpi->address == 0 || lpi->proto == 0)
		return -1;

	p = kmalloc(sizeof(*p),GFP_KERNEL);
	p->port = lpi->port;

	if(addAddress(lpi,p))
		ret = my_insert(&db,p);

#ifdef MY_DEBUG
	printAll(&db);
#endif
	return -ENOTIMPLEMENTED;
}

int deletePort(u16 port)
{
	printk(KERN_INFO "deleting port %hu",port);
	my_erase(&db,port);
	return 0;
}


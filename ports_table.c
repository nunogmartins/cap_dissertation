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



int insertPort(struct localPacketInfo *lpi)
{
	int ret;

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

	ret = my_insert(&db,lpi);

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


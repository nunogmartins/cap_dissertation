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

void debugFunc(struct packetInfo *lpi)
{
	pr_emerg("insert port");
	pr_emerg("port %hu",lpi->port);
	pr_emerg("protocol %hu",lpi->protocol);	
	pr_emerg("address %d.%d.%d.%d",NIPQUAD(lpi->address));
}


int insertPort(struct packetInfo *lpi)
{
	int ret=1;

	if(lpi == NULL){
		return 	-1;
	}
#ifdef MY_DEBUG
	debugFunc(lpi);
#endif

	if(lpi->port == 0 || lpi->protocol == 0)
	{
#ifdef MY_DEBUG
		pr_emerg("some info is zero port %d address 0x%x and protocol %hu",lpi->port,lpi->address, lpi->protocol);
#endif
		return -1;
	}


	ret = my_insert(&db,lpi);

	return ret;
}

int deletePort(struct packetInfo *pi)
{
#ifdef MY_DEBUG
	pr_emerg( "deleting port %hu",pi->port);
#endif
	my_erase(&db,pi);
	return 0;
}

void printTree(void){
	printAll(&db);
}

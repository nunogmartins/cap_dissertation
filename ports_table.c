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
	pr_emerg("port %hu",lpi->port);
	pr_emerg("protocol %hu",lpi->protocol);
	pr_emerg("address 0x%x",lpi->address);
}


int insertPort(struct packetInfo *lpi)
{
	int ret=1;

	if(lpi == NULL){

#ifdef MY_DEBUG
		pr_info( "in insert lpi is null");
#endif
		return 	-1;
	}

	debugFunc(lpi);

#ifdef NOT

#ifdef MY_DEBUG
	pr_info( "inserting port %hu with address 0x%x being %hu", lpi->port, lpi->address, lpi->protocol);
#endif

	if(lpi->port == 0 || lpi->protocol == 0)
	{
#ifdef MY_DEBUG
		pr_info("some info is zero port %d address 0x%x and protocol %hu",lpi->port,lpi->address, lpi->protocol);
#endif
		return -1;
	}


	ret = my_insert(&db,lpi);

#ifdef MY_DEBUG
	if(ret > 0){
		pr_info("adicionado");
		//printAll(&db);
	}else
		pr_info("nada alterado");
#endif

#endif //NOT
	return ret;
}

int deletePort(struct packetInfo *pi)
{
	pr_info( "deleting port %hu",pi->port);
	my_erase(&db,pi);
	return 0;
}


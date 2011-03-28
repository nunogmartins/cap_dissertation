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

struct rb_root db;
extern struct local_addresses_list *local_list;

int insertPort(struct packetInfo *lpi)
{
	int ret=1;

#ifdef MY_DEBUG
	if(lpi == NULL){
		return 	-1;
	}

	//debugFunc(lpi);
#endif

	if(lpi->port == 0 || lpi->protocol == 0)
	{
#ifdef MY_DEBUG_INFO
		//my_print_debug("some info is zero port %d address %d.%d.%d.%d and protocol %hu",lpi->port,NIPQUAD(lpi->address), lpi->protocol);
#endif
		return -1;
	}

	ret = my_insert(&db,lpi);

	return ret;
}

int deletePort(struct packetInfo *pi)
{
#ifdef MY_DEBUG_INFO
	//my_print_debug( "deleting port %hu",pi->port);
#endif
	my_erase(&db,pi);
	return 0;
}

int searchPort(struct packetInfo *pi){
	if( my_search(&db,pi) != NULL)
		return 1;
	else
		return 0;
}

void clearInfo(void){
	clearAllInfo(&db);
}

void printTree(void){
	printAll(&db);
}

int init_DB(void)
{
	return 0;
}
void exit_DB(void)
{
	clearInfo();
}

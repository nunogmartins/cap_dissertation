/*
 * tcp_hashtable.c
 *
 *  Created on: Nov 13, 2010
 *      Author: nuno
 */

#include <linux/list.h>

#include "pcap_monitoring.h"

#define MAX_ELEMS 2048

struct my_list {
	struct list_head list;

};

struct tcp_hashtable {
	struct list_head table[MAX_ELEMS];
	int MAX_ELEM;
	int (*hashFunction)(int port);
};


int init_hashtable(struct tcp_hashtable **h)
{

	return 0;
}


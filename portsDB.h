/*
 * portsDB.h
 *
 *  Created on: Nov 23, 2010
 *      Author: nuno
 */

#ifndef PORTSDB_H_
#define PORTSDB_H_

#include "config.h"

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>

#include "pcap_monitoring.h"

typedef struct portInfo{
	struct rb_node node;
	u16 port;
	struct local_addresses_list *udp;
	struct local_addresses_list *tcp;
	int tcp_list_counter;
	int udp_list_counter;
}portInfo;

struct portInfo *my_search(struct rb_root *root,struct packetInfo *pi);
int my_insert(struct rb_root *root, struct packetInfo *lpi);
void my_erase(struct rb_root *root, struct packetInfo *pi);
void printAll(struct rb_root *root);
void clearAllInfo(struct rb_root *root);
#ifdef MY_DEBUG
struct db_info_acquire;
struct db_info_acquire * dbInfoPointer(void);
#endif

#endif /* PORTSDB_H_ */

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

struct portInfo{
	struct rb_node node;
	u16 port;
#ifdef OLD_PHASE
	u32 address;
	u8 protocol;
#endif
#ifdef NEXT_PHASE
	struct local_addresses_list *udp;
	struct local_addresses_list *tcp;
#endif
};

struct portInfo *my_search(struct rb_root *root,struct packetInfo *pi);
int my_insert(struct rb_root *root, struct localPacketInfo *lpi);
void my_erase(struct rb_root *root, struct packetInfo *pi);
void printAll(struct rb_root *tree);
#endif /* PORTSDB_H_ */

/*
 * pcap_monitoring.h
 *
 *  Created on: Nov 10, 2010
 *      Author: nuno
 */
#include "config.h"


#ifndef PCAP_MONITORING_H_
#define PCAP_MONITORING_H_

#include <linux/types.h>
#include <linux/fs.h>
#include <net/net_namespace.h>
#include <linux/list.h>

#define TCP 0x06
#define UDP 0x11

struct packetInfo {
	u8 protocol;
	u16 port;
	u32 address;
};

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[3], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[0]

typedef struct local_addresses_list {
	struct list_head list;
	u32 address;
	int counter;
}local_addresses_list;

extern struct socket *sockfd_lookup(int fd, int *err);
void getLocalPacketInfoFromFd(unsigned int fd,struct packetInfo *,int *err);
void getLocalPacketInfoFromFile(struct file *f,struct packetInfo *,int *err);
struct local_addresses_list* listAllDevicesAddress(void);
int remove_local_addresses_list(struct local_addresses_list *list);

extern struct net inet;

#endif /* PCAP_MONITORING_H_ */

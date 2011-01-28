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

#define CHECK_MONITOR_PID	\
	if(!current->mm)	\
		return 1;	\
	if(monitor_pid == -1) 	\
		return 1;	\
	if(task->pid != monitor_pid) \
		if(task->real_parent->pid != monitor_pid) \
		return 1;
//ToDo: isto esta mal feito o ||

struct cell{
	int fd;
	int type;
	int port;
	int status;
	int direction;
};

struct packetInfo {
	u8 protocol;
	u16 port;
	u32 address;
};

typedef struct local_addresses_list {
	struct list_head list;
	u32 address;
	int counter;
}local_addresses_list;

extern struct socket *sockfd_lookup(int fd, int *err);
unsigned short getPort(unsigned int fd,int direction);
void getLocalPacketInfoFromFd(unsigned int fd,struct packetInfo *,int *err);
void getLocalPacketInfoFromFile(struct file *f,struct packetInfo *,int *err);
struct local_addresses_list* listAllDevicesAddress(void);
int remove_local_addresses_list(struct local_addresses_list *list);

extern struct net inet;

#endif /* PCAP_MONITORING_H_ */

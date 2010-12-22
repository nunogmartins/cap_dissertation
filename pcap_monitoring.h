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

#define CHECK_MONITOR_PID	\
	if(!current->mm)	\
		return 1;	\
	if(monitor_pid == -1) 	\
		return 1;	\
	if(task->pid != monitor_pid || task->real_parent->pid == monitor_pid) \
		return 1;

struct cell{
	int fd;
	int type;
	int port;
	int status;
	int direction;
};

struct localPacketInfo{
	u8 proto;
	u16 port;
	u32 address;
};

struct packetInfo {
	u8 proto;
	u16 srcPort, dstPort;
	u32 srcAddr, dstAddr;
};

struct lista_enderecos {

};

extern struct socket *sockfd_lookup(int fd, int *err);
unsigned short getPort(unsigned int fd,int direction);
struct localPacketInfo * getLocalPacketInfoFromFd(unsigned int fd);
struct localPacketInfo * getLocalPacketInfoFromFile(struct file *f);
struct lista_enderecos* listAllDevicesAddress(void);

extern struct net inet;

#endif /* PCAP_MONITORING_H_ */

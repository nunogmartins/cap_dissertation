/*
 * pcap_monitoring.h
 *
 *  Created on: Nov 10, 2010
 *      Author: nuno
 */

#ifndef PCAP_MONITORING_H_
#define PCAP_MONITORING_H_

#define CHECK_MONITOR_PID \
	if(monitor_pid == -1) \
		return 1;	\
	if(task->pid != monitor_pid) \
		return 1;

struct cell{
	int fd;
	int type;
	int port;
	int status;
	int direction;
};

extern struct socket *sockfd_lookup(int fd, int *err);
unsigned short getPort(unsigned int fd,int direction);

#endif /* PCAP_MONITORING_H_ */

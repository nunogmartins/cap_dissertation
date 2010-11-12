/*
 * pcap_monitoring.h
 *
 *  Created on: Nov 10, 2010
 *      Author: nuno
 */

#ifndef PCAP_MONITORING_H_
#define PCAP_MONITORING_H_

struct cell{
	int fd;
	int type;
	int port;
	int status;
};
struct task_struct;

extern struct socket *sockfd_lookup(int fd, int *err);
extern unsigned short getPort(unsigned int fd, struct task_struct *ts);

#endif /* PCAP_MONITORING_H_ */

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
	int direction;
};

extern struct socket *sockfd_lookup(int fd, int *err);
unsigned short getPort(unsigned int fd,int direction);

#endif /* PCAP_MONITORING_H_ */

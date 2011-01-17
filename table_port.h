#ifndef TABLE_PORT_H
#define TABLE_PORT_H

#include "config.h"

#include "pcap_monitoring.h"

#define ENOTIMPLEMENTED 255 
/*struct entry {
	unsigned short proto;
	unsigned short port;
	unsigned int fd;
};
*/
int insertPort(struct packetInfo *lpi);
int deletePort(struct packetInfo *pi);
void printTree(void);

#endif

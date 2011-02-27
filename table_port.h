#ifndef TABLE_PORT_H
#define TABLE_PORT_H

#include "config.h"

#include "pcap_monitoring.h"

int insertPort(struct packetInfo *lpi);
int deletePort(struct packetInfo *pi);
int searchPort(struct packetInfo *pi);
void clearInfo(void);
void printTree(void);

#endif

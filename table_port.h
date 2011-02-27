#ifndef TABLE_PORT_H
#define TABLE_PORT_H

#include "config.h"

#include "pcap_monitoring.h"

int insertPort(struct packetInfo *lpi);
int deletePort(struct packetInfo *pi);
int searchPort(struct packetInfo *pi);
void clearInfo(void);
void printTree(void);

int init_DB(void);
void exit_DB(void);

#endif

/*
 * colector.h
 *
 *  Created on: Feb 25, 2011
 *      Author: nuno
 */

#ifndef COLECTOR_H_
#define COLECTOR_H_


struct filter_info_acquire {
	long entry;
	long src;
	long dst;
};

#define MAX_SYSCALLS 7

struct syscall_info_acquire {

};

struct db_info_acquire {
	int how_many_ports;
	long how_many_inserts;
	long how_many_removes;
};

struct info_acquire {
	struct filter_info_acquire *filter;
	struct syscall_info_acquire *syscalls[MAX_SYSCALLS];
	struct db_info_acquire *db;
};



int acquireInfo(struct info_acquire *info);

#endif /* COLECTOR_H_ */
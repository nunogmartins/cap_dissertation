/*
 * syscalls_monitor.h
 *
 *  Created on: Feb 27, 2011
 *      Author: nuno
 */

#ifndef SYSCALLS_MONITOR_H_
#define SYSCALLS_MONITOR_H_

int init_kretprobes_syscalls(void);
void destroy_kretprobes_syscalls(void);

#endif /* SYSCALLS_MONITOR_H_ */

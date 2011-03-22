/*
 * debugfs_support.h
 *
 *  Created on: Feb 27, 2011
 *      Author: nuno
 */

#ifndef DEBUGFS_SUPPORT_H_
#define DEBUGFS_SUPPORT_H_

int init_debug(void);
void destroy_debug(void);

int register_debugfs_file(const char *name, const struct file_operations *fops);
void register_filter_calls(u64 *data);
void register_monitor_id(const char *name, u64 *data);

#endif /* DEBUGFS_SUPPORT_H_ */

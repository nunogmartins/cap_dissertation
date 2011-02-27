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

int register_debugfs_file(void);

#endif /* DEBUGFS_SUPPORT_H_ */

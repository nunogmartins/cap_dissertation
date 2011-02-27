/*
 * filter.h
 *
 *  Created on: Feb 27, 2011
 *      Author: nuno
 */

#ifndef FILTER_H_
#define FILTER_H_

unsigned int my_portExists(struct packetInfo *src_pi,struct packetInfo *dst_pi);
void backupFilter(void);
void restoreFilter(void);
#endif /* FILTER_H_ */

/*
 * portsDB.h
 *
 *  Created on: Nov 23, 2010
 *      Author: nuno
 */

#ifndef PORTSDB_H_
#define PORTSDB_H_

struct portInfo *my_search(struct rb_root *root,int port);
int my_insert(struct rb_root *root, struct portInfo *port);
void my_erase(struct rb_root *root, int port);

#endif /* PORTSDB_H_ */

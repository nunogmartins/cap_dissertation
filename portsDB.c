/*
 * portsDB.c
 *
 *  Created on: Nov 22, 2010
 *      Author: nuno
 */

#include "config.h"

#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "pcap_monitoring.h"
#include "portsDB.h"

struct rb_root db = RB_ROOT;
extern struct local_addresses_list *local_list;

/*
 * returns NULL if there isn't that port int the tree
 */
struct portInfo *my_search(struct rb_root *root,struct packetInfo *pi)
{
	struct rb_node *node = root->rb_node;
	struct portInfo *data = NULL;


	while(node)
	{
		data = container_of(node,struct portInfo,node);

		if(pi->port < data->port)
			node = node->rb_left;
		else
			if(pi->port > data->port)
				node = node->rb_right;
			else
				if(pi->port == data->port){
					//ToDo: have to search for address on procotol
					return data; //its my port ...
				}

				else
					return NULL;
	}

	return NULL;
}

int my_insert(struct rb_root *root, struct portInfo *port)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;

#ifdef MY_DEBUG
			printk(KERN_INFO "port = %hu", port->port);
#endif

	while(*new)
	{
		struct portInfo *this = container_of(*new,struct portInfo, node);

		parent = *new;
		if(port->port < this->port){
			new = &((*new)->rb_left);
		}
		else
			if(port->port > this->port){
				new = &((*new)->rb_right);
			}
			else
			{
				//ToDo: verify what this has and what port has to update this variables
				//ToDo: kfree(port) because it was allocated a portInfo and now it is not used anywhere
				return 0;
			}
	}

	rb_link_node(&port->node,parent,new);
	rb_insert_color(&port->node,root);

	return 1;
}
/*
 * ToDo: implementation for updating the tree
 */
int my_update(struct rb_root *root, struct portInfo *port)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	while(*new)
	{
		struct portInfo *this = container_of(*new,struct portInfo, node);

		parent = *new;
		if(port->port < this->port){
			new = &((*new)->rb_left);
		}
		else
			if(port->port > this->port){
				new = &((*new)->rb_right);
			}
			else
			{
				//ToDo: verify what this has and what port has to update this variables
				//ToDo: kfree(port) because it was allocated a portInfo and now it is not used anywhere
				return 0;
			}
	}

	rb_link_node(&port->node,parent,new);
	rb_insert_color(&port->node,root);
	return 1;

}

void my_erase(struct rb_root *root, u16 port)
{
	struct portInfo *data = my_search(root,port);

	if(data)
	{
		rb_erase(&data->node,root);
	}

	//ToDo: possibly here to kfree data memory ...
	//@here ... allocated in ports_table::insertPort ...
}

void printAll(struct rb_root *tree)
{
	struct rb_node *node;
	for(node = rb_first(tree); node ; node = rb_next(node))
	{

		printk(KERN_INFO "port = %hu ", rb_entry(node,struct portInfo, node)->port);
		//ToDo: iterate over tcp and udp lists
	}
}

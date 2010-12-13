/*
 * portsDB.c
 *
 *  Created on: Nov 22, 2010
 *      Author: nuno
 */
#include <linux/kernel.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "portsDB.h"

struct rb_root db = RB_ROOT;

/*
 * returns NULL if there isn't that port int the tree
 */
struct portInfo *my_search(struct rb_root *root,u16 port)
{
	struct rb_node *node = root->rb_node;
	struct portInfo *data = NULL;


	while(node)
	{
		data = container_of(node,struct portInfo,node);

		if(port < data->port)
			node = node->rb_left;
		else
			if(port > data->port)
				node = node->rb_right;
			else
				if(port == data->port)
					return data; //its my port ...
				else
					return NULL;
	}

	return NULL;
}

int my_insert(struct rb_root *root, struct portInfo *port)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	while(*new)
	{
		struct portInfo *this = container_of(*new,struct portInfo, node);

		parent = *new;
		if(port->port < this->port)
			new = &((*new)->rb_left);
		else
			if(port->port > this->port)
				new = &((*new)->rb_right);
			else
				return 0;
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
}

void printAll(struct rb_root *tree)
{
	struct rb_node *node;
	for(node = rb_first(tree); node ; node = rb_next(node))
	{
		printk(KERN_INFO "port = %hu", rb_entry(node,struct portInfo, node)->port);
	}
}

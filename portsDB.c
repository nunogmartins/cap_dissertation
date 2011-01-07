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

static int addAddress(struct localPacketInfo *lpi, struct portInfo *port_info)
{
	struct local_addresses_list *tmp = NULL;

	struct local_addresses_list *node = NULL;

	switch(lpi->proto){
	case 0x06:
		if(lpi->address == 0){
			port_info->tcp = local_list;
			return 1;
		}
		else
			tmp = port_info->tcp;
		break;

	case 0x11:
		if(lpi->address == 0){
			port_info->tcp = local_list;
			return 1;
		}
		else
			tmp = port_info->udp;
		break;

	default:
		break;
	}

	if(!tmp){
		tmp = kmalloc(sizeof(*tmp),GFP_KERNEL);

		if(!tmp)
			return -1;

		INIT_LIST_HEAD(&(tmp->list));
	}

	node = kmalloc(sizeof(*node),GPF_KERNEL);

	if(!node)
		return -1;

	node->address = lpi->address;
	list_add(&(tmp->list),&(node->list));

	return 1;
}

struct portInfo * createPacketInfo(struct localPacketInfo *lpi)
{
	struct portInfo *pi = NULL;
	pi = kmalloc(sizeof(struct portInfo),GFP_KERNEL);

	if(!pi)
		return NULL;

	pi->port = lpi->port;

	pi->tcp = NULL;
	pi->udp = NULL;

	addAddress(lpi,pi);

	return pi;
}

int my_insert(struct rb_root *root, struct localPacketInfo *lpi)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct portInfo *port = NULL;

#ifdef MY_DEBUG
			printk(KERN_INFO "port = %hu", lpi->port);
#endif

	while(*new)
	{
		struct portInfo *this = container_of(*new,struct portInfo, node);

		parent = *new;
		if(lpi->port < this->port){
			new = &((*new)->rb_left);
		}
		else
			if(lpi->port > this->port){
				new = &((*new)->rb_right);
			}
			else
			{
				//ToDo: verify what this has and what port has to update this variables
				//ToDo: need to verify that address is not already on the list ..
				addAddress(lpi,this);
				return 0;
			}
	}

	port = createPacketInfo(lpi);
	if(!port)
		return -1;

	rb_link_node(&port->node,parent,new);
	rb_insert_color(&port->node,root);

	return 1;
}

void my_erase(struct rb_root *root, u16 port)
{
	//ToDo: completly ...

	/*struct portInfo *data = my_search(root,port);

	if(data)
	{
		rb_erase(&data->node,root);
	}
	*/

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

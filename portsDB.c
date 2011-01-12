/*
 * portsDB.c
 *
 *  Created on: Nov 22, 2010
 *      Author: nuno
 */

#include "config.h"

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/types.h>

#include "pcap_monitoring.h"
#include "portsDB.h"

struct rb_root db = RB_ROOT;
extern struct local_addresses_list *local_list;

/*
 * returns NULL if there isn't that port int the tree
 */
static inline int isEqualPacketInfo(struct packetInfo *pi, struct portInfo *info)
{

	struct local_addresses_list *tmp = NULL;
	local_addresses_list *address = NULL;
	struct list_head *pos = NULL;

#ifdef MY_DEBUG
	if(!info)
	{
		pr_warning("my info is null");
		BUG();
	}

	if(!pi){
			pr_warning("pi is null");
			BUG();
	}
#endif

	switch(pi->protocol){

	case 0x06:
#ifdef MY_DEBUG
		pr_info("is equal to tcp");
#endif
		if(info->tcp){
			tmp = info->tcp;
#ifdef MY_DEBUG
			pr_info("tcp is different from null");
#endif
		}
		break;

	case 0x11:
		if(info->udp)
			tmp = info->udp;
		break;

	default:
		return 0;
	}

	if(!tmp)
		return 0;

	pr_emerg("going to iterate on equalPacketInfo");

	list_for_each(pos,&(tmp->list))
	{
		address = list_entry(pos,local_addresses_list,list);
		if(!address)
			BUG();

#ifdef MY_DEBUG
		pr_emerg("iteration address 0x%x",address->address);
#endif
		if(pi->address == address->address){
#ifdef MY_DEBUG
			pr_emerg("found equal 0x%x",address->address);
#endif
			return 1;
		}
	}

	return 0;
}

struct portInfo *my_search(struct rb_root *root,struct packetInfo *pi)
{
	struct rb_node *node = root->rb_node;
	struct portInfo *data = NULL;

	pr_info("in search");

	while(node)
	{
		data = container_of(node,portInfo,node);

		if(pi->port < data->port)
			node = node->rb_left;
		else
			if(pi->port > data->port)
				node = node->rb_right;
			else
				if(pi->port == data->port){
					//ToDo: have to search for address on procotol
					if(isEqualPacketInfo(pi,data)!=0)
						return data; //its my port ...
					else
						return NULL;
				}

				else
					return NULL;
	}

	return NULL;
}

static int addAddress(struct packetInfo *lpi, struct portInfo *port_info)
{
	struct local_addresses_list *tmp = NULL;

	struct local_addresses_list *node = NULL;

	switch(lpi->protocol){
	case 0x06:
		if(lpi->address == 0){
			port_info->tcp = local_list;
			return 1;
		}
		else{
			if(!port_info->tcp)
			{
				port_info->tcp = kmalloc(sizeof(*tmp),GFP_KERNEL);

				if(!port_info->tcp)
					return -1;

				INIT_LIST_HEAD(&((port_info->tcp)->list));
			}
			tmp = port_info->tcp;
#ifdef MY_DEBUG
			pr_info("is tcp and tmp is now ... %p",tmp);
#endif
		}
		break;

	case 0x11:
		if(lpi->address == 0){
			port_info->tcp = local_list;
			return 1;
		}
		else{
			if(!port_info->udp)
			{
				
				port_info->udp = kmalloc(sizeof(*tmp),GFP_KERNEL);
			
				if(!port_info->udp)
					return -1;

				INIT_LIST_HEAD(&((port_info->udp)->list));
			}
			tmp = port_info->udp;
		}
		break;

	default:
		return -1;
	}

	if(tmp)
		pr_warning("tmp is not null");
	else{
		pr_warning("tmp is null ...");
		BUG();
	}

	node = kmalloc(sizeof(*node),GFP_KERNEL);

	if(!node)
		return -1;

	node->address = lpi->address;
#ifdef MY_DEBUG
	pr_warning("going to list add");
#endif

	list_add(&(tmp->list),&(node->list));
#ifdef MY_DEBUG
	pr_warning("node added to the list");
#endif

	return 1;
}

struct portInfo * createPacketInfo(struct packetInfo *lpi)
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

int my_insert(struct rb_root *root, struct packetInfo *lpi)
{
	struct rb_node **new = &(root->rb_node), *parent = NULL;
	struct portInfo *port = NULL;

#ifdef MY_DEBUG
			pr_info( "in insert for port = %hu", lpi->port);
#endif

	while(*new)
	{
		struct portInfo *this = container_of(*new,portInfo, node);

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
				if(!isEqualPacketInfo(lpi,this))
					addAddress(lpi,this);
				else
					return 0;

				return 1;
			}
	}
	
	pr_info("vou criar um novo");
	port = createPacketInfo(lpi);
	if(!port)
		return -1;

	rb_link_node(&port->node,parent,new);
	rb_insert_color(&port->node,root);

	return 1;
}

void my_erase(struct rb_root *root, struct packetInfo *pi)
{
	short int toRemove = 0;

	//ToDo: completly ...

	struct portInfo *data = my_search(root,pi);


	if(toRemove)
		if(data)
		{
			if((!data->tcp) && !(data->udp)){
				rb_erase(&data->node,root);
			/*
			 * ToDo: taking care of the information of the node
			 */
				kfree(data);
			}else{
				//ToDo: remove only the address it needs to remove ...
			}
			//ToDo: possibly here to kfree data memory ...
			//@here ... allocated in ports_table::insertPort ...

		}


}

static void iterateList(struct local_addresses_list *tmp)
{
	struct list_head *pos = NULL;
	struct local_addresses_list *address = NULL;

	list_for_each(pos,&(tmp->list))
	{
		address = list_entry(pos,local_addresses_list,list);
		pr_info("address 0x%x",address->address);
	}
}

void printAll(struct rb_root *tree)
{
	struct rb_node *node;
	struct portInfo *p = NULL;

	for(node = rb_first(tree); node ; node = rb_next(node))
	{
		p = rb_entry(node,portInfo, node);
		pr_info( "port = %hu ", p->port);

#ifdef NOT
		if(p->tcp){
			pr_info( "tcp addresses");
			iterateList(p->tcp);
		}

		if(p->udp){
			pr_info( "udp addresses");
			iterateList(p->udp);
		}
#endif
	}
}

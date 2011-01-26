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
	int i=0;

	switch(pi->protocol){

	case 0x06:
		if(info->tcp)
			tmp = info->tcp;
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

	list_for_each(pos,&(tmp->list))
	{
		address = list_entry(pos,local_addresses_list,list);
		if(pi->address == address->address){
			return 1;
		}
	}

	return 0;
}

struct portInfo *my_search(struct rb_root *root,struct packetInfo *pi)
{
	struct rb_node *node = root->rb_node;
	struct portInfo *data = NULL;

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
					if(isEqualPacketInfo(pi,data)!=0)
						return data;
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

	node = kmalloc(sizeof(*node),GFP_KERNEL);

	if(!node)
		return -1;

	node->address = lpi->address;

	list_add(&(node->list),&(tmp->list));

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
	
	port = createPacketInfo(lpi);
	if(!port)
		return -1;

	rb_link_node(&port->node,parent,new);
	rb_insert_color(&port->node,root);

	return 1;
}

static void removeAddressFromNode(struct portInfo *pi,struct packetInfo *lpi)
{
	struct local_addresses_list *list = NULL, *tmp = NULL;
	struct list_head *q = NULL, *pos = NULL;

	switch(lpi->protocol)
	{
	case 0x6:
		tmp = pi->tcp;
		break;
	case 0x11:
		tmp = pi->udp;
		break;
	default:
		return;
	}

	if(lpi->address == 0)
	{
		return;
	}

	if(!tmp)
		return;

	/*
	 * ToDo: verify if tmp is not local_addresses
	 */

	list_for_each_safe(pos,q,&(tmp->list))
	{
		list = list_entry(pos,local_addresses_list,list);
		if(lpi->address == list->address){
			list_del(pos);
			kfree(list);
			return;
		}
	}
}

void my_erase(struct rb_root *root, struct packetInfo *pi)
{
	//ToDo: completly ...

	struct portInfo *data = my_search(root,pi);

		if(data)
		{
			if((!data->tcp) && !(data->udp)){
				/* rb_erase(&data->node,root);
					kfree(data); */
			/*
			 * ToDo: taking care of the information of the node
			 */
#ifdef MY_DEBUG
				pr_emerg("removing the node");
#endif
			}else{
				//ToDo: remove only the address it needs to remove ...
#ifdef MY_DEBUG
				pr_emerg("removing only the address");
#endif
				removeAddressFromNode(data,pi);
				if((!data->tcp) && (!data->udp))
				{
#ifdef MY_DEBUG
					pr_emerg("needing to remove the node");
#endif
				}
			}
			//ToDo: possibly here to kfree data memory ...
			//@here ... allocated in createPacketInfo

		}


}

#ifdef DEBUG_INFO

static void iterateList(struct local_addresses_list *tmp)
{
	struct list_head *pos = NULL;
	struct local_addresses_list *address = NULL;

	list_for_each(pos,&(tmp->list))
	{
		address = list_entry(pos,local_addresses_list,list);
#ifdef MY_DEBUG
		pr_emerg("address 0x%x",address->address);
#endif
	}
}

void printAll(struct rb_root *tree)
{
	struct rb_node *node;
	struct portInfo *p = NULL;

	for(node = rb_first(tree); node ; node = rb_next(node))
	{
		p = rb_entry(node,portInfo, node);
		pr_emerg( "port = %hu ", p->port);

		if(p->tcp){
#ifdef MY_DEBUG
			pr_emerg( "tcp addresses");
#endif
			iterateList(p->tcp);
		}

		if(p->udp){
#ifdef MY_DEBUG
			pr_emerg( "udp addresses");
#endif
			iterateList(p->udp);
		}
	}
}

#endif

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

#ifdef MY_DEBUG
#include "info_acquire.h"
#endif

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

static int addAddress(struct packetInfo *lpi, struct local_addresses_list *tmp, int *list_counter)
{
	local_addresses_list *address = NULL;
	struct list_head *pos = NULL;
	struct local_addresses_list *node = NULL;

	list_for_each(pos,&(tmp->list))
	{
		address = list_entry(pos,local_addresses_list,list);
		if(lpi->address == address->address){
			address->counter++;
			return 1;
		}
	}

	node = kmalloc(sizeof(*node),GFP_KERNEL);

	if(!node)
		return -1;

	node->address = lpi->address;
	node->counter = 1;

	list_add(&(node->list),&(tmp->list));
	(*list_counter)++;

	return 1;
}

static int insertAddress(struct packetInfo *lpi, struct portInfo *port_info)
{

	switch(lpi->protocol)
	{
	case TCP:
		if(!(port_info->tcp))
		{
			port_info->tcp = kmalloc(sizeof(struct local_addresses_list ),GFP_KERNEL);

			if(!port_info->tcp)
				return -1;

			INIT_LIST_HEAD(&((port_info->tcp)->list));
			port_info->tcp->counter = 0;
		}

		if(lpi->address == 0)
		{
			local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos,&(local_list->list))
			{
				struct packetInfo pi;

				address = list_entry(pos,local_addresses_list,list);

				pi.address = address->address;

				addAddress(&pi,port_info->tcp,&(port_info->tcp_list_counter));
			}

		}
		else{

			addAddress(lpi,port_info->tcp,&(port_info->tcp_list_counter));
		}

		break;

	case UDP:
		if(!(port_info->udp))
		{
			port_info->udp = kmalloc(sizeof(struct local_addresses_list),GFP_KERNEL);

			if(!port_info->udp)
				return -1;

			INIT_LIST_HEAD(&((port_info->udp)->list));
			port_info->udp->counter = 0;
		}

		if(lpi->address == 0)
		{
			local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos,&(local_list->list))
			{
				struct packetInfo pi;

				address = list_entry(pos,local_addresses_list,list);

				pi.address = address->address;

				addAddress(&pi,port_info->udp,&(port_info->udp_list_counter));
			}


		}
		else{
			addAddress(lpi,port_info->udp,&(port_info->udp_list_counter));
		}

		break;

	default:
		return -1;
	}

	return 0;
}

static struct portInfo * createPacketInfo(struct packetInfo *lpi)
{
	struct portInfo *pi = NULL;
	pi = kmalloc(sizeof(struct portInfo),GFP_KERNEL);

	if(!pi)
		return NULL;

	pi->port = lpi->port;

	pi->tcp = NULL;
	pi->tcp_list_counter = 0;
	pi->udp = NULL;
	pi->udp_list_counter = 0;

	insertAddress(lpi,pi);

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
				insertAddress(lpi,this);
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

int decrementAddress(struct packetInfo *lpi,struct local_addresses_list *protocol, int *list_counter)
{
	local_addresses_list *address = NULL;
	struct list_head *pos = NULL, *q =NULL;

	list_for_each_safe(pos,q,&(protocol->list))
	{
		address = list_entry(pos,local_addresses_list,list);
		if(lpi->address == address->address){
			(address->counter)--;
			if(address->counter <= 0){
				list_del(pos);
				kfree(address);
				(*(list_counter))--;
			}
			return 1;
		}
	}

	return 0;
}

static void removeAddressFromNode(struct portInfo *pi,struct packetInfo *lpi)
{

	switch(lpi->protocol)
	{
	case TCP:
		if(lpi->address){
			decrementAddress(lpi,pi->tcp,&(pi->tcp_list_counter));
		}else
		{
			local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos,&(local_list->list))
			{
				struct packetInfo aux;

				address = list_entry(pos,local_addresses_list,list);

				aux.address = address->address;

				decrementAddress(&aux,pi->tcp,&(pi->tcp_list_counter));
			}
		}
		if(pi->tcp_list_counter == 0)
		{
			kfree(pi->tcp);
			pi->tcp = NULL;
		}
		break;

	case UDP:
		if(lpi->address){
			decrementAddress(lpi,pi->udp,&(pi->udp_list_counter));
		}else
		{
			local_addresses_list *address = NULL;
			struct list_head *pos = NULL;

			list_for_each(pos,&(local_list->list))
			{
				struct packetInfo aux;

				address = list_entry(pos,local_addresses_list,list);

				aux.address = address->address;

				decrementAddress(&aux,pi->udp,&(pi->udp_list_counter));
			}

		}
		if(pi->udp_list_counter == 0)
		{
			kfree(pi->udp);
			pi->udp = NULL;
		}
		break;
	default:
		return;
	}
}

void my_erase(struct rb_root *root, struct packetInfo *pi)
{
	struct portInfo *data = my_search(root,pi);

	if(data)
	{
		removeAddressFromNode(data,pi);

		if((!data->tcp) && !(data->udp)){
			rb_erase(&data->node,root);
			kfree(data);
#ifdef MY_DEBUG
			pr_emerg("removing the node");
#endif
		}
	}
}

static void iterateList(struct local_addresses_list *tmp)
{
	struct list_head *pos = NULL;
	struct local_addresses_list *address = NULL;

	list_for_each(pos,&(tmp->list))
	{
		address = list_entry(pos,local_addresses_list,list);
		pr_emerg("address %d.%d.%d.%d and counter %d",NIPQUAD(address->address), address->counter);
	}
}

void printAll(struct rb_root *tree)
{
	struct rb_node *node;
	struct portInfo *p = NULL;
	int i = 0;


	for(node = rb_first(tree); node ; node = rb_next(node))
	{
		p = rb_entry(node,portInfo, node);
		pr_emerg( "port = %hu ", p->port);

		if(p->tcp){
			pr_emerg( "tcp addresses 0x%p and counter %d",p->tcp,p->tcp_list_counter);
			iterateList(p->tcp);
		}

		if(p->udp){
			pr_emerg( "udp addresses 0x%p and counter %d",p->udp,p->udp_list_counter);
			iterateList(p->udp);
		}
		i++;
	}

	if(i == 0)
	{
		pr_emerg("Arvore vazia");
	}
}

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
struct db_info_acquire db_info;




#endif

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

#ifdef MY_DEBUG
	db_info.how_many_inserts++;
	db_info.how_many_ports++;
#endif

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
			db_info.how_many_removes++;
			db_info.how_many_ports--;
#endif
		}
	}
}
/*
static void iterateList(struct local_addresses_list *tmp)
{
	struct list_head *pos = NULL;
	struct local_addresses_list *address = NULL;

	list_for_each(pos,&(tmp->list))
	{
		address = list_entry(pos,local_addresses_list,list);
		my_print_debug("address %d.%d.%d.%d and counter %d",NIPQUAD(address->address), address->counter);
	}
}
*/
void printAll(struct rb_root *root)
{
	struct rb_node *node;
	//struct portInfo *p = NULL;
	unsigned long i = 0;


	for(node = rb_first(root); node ; node = rb_next(node))
	{
		/*
		p = rb_entry(node,portInfo, node);
		my_print_debug( "port = %hu ", p->port);

		if(p->tcp){
			my_print_debug( "tcp addresses 0x%p and counter %d",p->tcp,p->tcp_list_counter);
			iterateList(p->tcp);
		}

		if(p->udp){
			my_print_debug( "udp addresses 0x%p and counter %d",p->udp,p->udp_list_counter);
			iterateList(p->udp);
		}
		*/
		i++;
	}

	if(i == 0)
	{
		my_print_debug("Empty Tree");
	}else
	{
		my_print_debug("The tree has %lu elements",i);
	}
}

static void clearNodeInfo(struct portInfo *pi)
{
	struct local_addresses_list *tmp = NULL;
	struct list_head *pos = NULL, *q = NULL;


	if(pi->tcp_list_counter > 0 && pi->tcp != NULL){
		struct local_addresses_list *aux = pi->tcp;
		list_for_each_safe(pos,q,&(aux->list))
		{
			tmp = list_entry(pos,local_addresses_list, list);
			list_del(pos);
			kfree(tmp);
		}
		pi->tcp_list_counter = 0;
		kfree(pi->tcp);
	}

	if(pi->udp_list_counter > 0 && pi->udp != NULL){
		struct local_addresses_list *aux = pi->udp;
		list_for_each_safe(pos,q,&(aux->list))
		{
			tmp = list_entry(pos,local_addresses_list, list);
			list_del(pos);
			kfree(tmp);
		}
		pi->udp_list_counter = 0;
		kfree(pi->udp);
	}
}

void clearAllInfo(struct rb_root *root)
{
	struct rb_node *node = NULL, *next_node = NULL;
	struct portInfo *p = NULL;

	node = rb_first(root);
	while(node)
	{
		next_node = rb_next(node);
		p = rb_entry(node,portInfo, node);
		clearNodeInfo(p);

		rb_erase(node,root);
		kfree(p);
		p = NULL;
		node = next_node;
	}
}

#ifdef MY_DEBUG
struct db_info_acquire * dbInfoPointer(void)
{
	return &db_info;
}
#endif

#ifdef MY_DEBUG

static void *db_seq_start(struct seq_file *p, loff_t *pos)
{
	if(*pos > 0)
		return NULL;
	else
		return &db_info;
}

static void *db_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	return NULL;
}

static void db_seq_stop(struct seq_file *p, void *v)
{

}

static int db_seq_show(struct seq_file *m, void *v)
{
	struct db_info_acquire *info = NULL;
	if(v != NULL)
	{
		info = v;
		seq_printf(m,"how many ports %ld inserts %ld removes %ld\n",
				info->how_many_ports, info->how_many_inserts,info->how_many_removes);
	}

	return 0;

}

static const struct seq_operations db_seq_ops = {
        .start  = db_seq_start,
        .next   = db_seq_next,
        .stop   = db_seq_stop,
        .show   = db_seq_show,
};

static int db_open(struct inode *inode, struct file *file)
{
	return seq_open(file,&db_seq_ops);
}

static const struct file_operations db_fops = {
        .open           = db_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release 		= seq_release,
        .owner          = THIS_MODULE,
 };

#include <linux/debugfs.h>
#include "debugfs_support.h"
int init_db_debug(void)
{
	struct dentry *parent = NULL;
	parent = createDBStatDir();
	debugfs_create_file("stats",S_IRUSR,parent,NULL,&db_fops);
	return 0;
}

#endif

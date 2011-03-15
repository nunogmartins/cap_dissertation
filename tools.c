/*
 * tools.c
 *
 *  Created on: Nov 12, 2010
 *      Author: nuno
 */
#include "config.h"

#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <net/net_namespace.h>
#include <linux/inetdevice.h>


#include "pcap_monitoring.h"

void getInetSockParameters(struct inet_sock *inetsock,struct packetInfo *ret)
{
	ret->port = inetsock->inet_num;
	ret->protocol = ((struct sock *)inetsock)->sk_protocol;

#ifdef MY_DEBUG_INFO
	if(ret->protocol!=0){
		int src_addr = ntohl(inetsock->inet_saddr);
		int dst_addr = ntohl(inetsock->inet_daddr);
		int rcv = ntohl(inetsock->inet_rcv_saddr);
	pr_emerg( "rcv is %d.%d.%d.%d",NIPQUAD(rcv));
	pr_emerg( "sport %hu dport %hu daddr %d.%d.%d.%d laddr %d.%d.%d.%d",
			ntohs(inetsock->inet_sport),ntohs(inetsock->inet_dport), NIPQUAD(dst_addr),NIPQUAD(src_addr));
	}
#endif

	if(ret->port == ntohs(inetsock->inet_sport))
	{
		if(!inetsock->inet_rcv_saddr){
			ret->address = inetsock->inet_saddr;
		}
		else
			ret->address = inetsock->inet_rcv_saddr;

	}else
	{
		ret->address = inetsock->inet_daddr;
	}
	ret->address = ntohl(ret->address);
	//ret->protocol = ((struct sock *)inetsock)->sk_protocol;

}


void getLocalPacketInfoFromFd(unsigned int fd, struct packetInfo *ret, int *err)
{
	struct file *f = NULL;
	*err = 0;
	f = fget(fd);


	if(f!=NULL)
	{
		fput(f);
		getLocalPacketInfoFromFile(f,ret,err);
	}else{
		*err = -3;
	}
}

void getLocalPacketInfoFromFile(struct file *f, struct packetInfo *ret, int *err)
{
	struct socket *socket = NULL;
	short type;
	unsigned short family;
	*err = 0;

	if(f!=NULL)
	{
		struct dentry *dentry;
		struct inode *d_inode;
		dentry = f->f_dentry;
		if(dentry !=NULL)
		{
			d_inode = dentry->d_inode;
			if(S_ISSOCK(d_inode->i_mode))
			{
				socket = f->private_data;
				type = socket->type;
				family = socket->sk->__sk_common.skc_family;
				if(family != AF_INET)
				{
					*err = -4;
					return; 
				}
				getInetSockParameters((struct inet_sock *)(socket->sk),ret);

#ifdef MY_DEBUG_INFO
				pr_info( "family %hu type %hu lport %hu addr %d.%d.%d.%d proto %hu",family,type,ret->port, NIPQUAD(ret->address), ret->protocol);
#endif
			}else
			{
				*err = -1;
			}
		}else
		{
			*err = -2;
		}
	}else
	{
		*err = -3;
	}

}

struct local_addresses_list* listAllDevicesAddress(void)
{
	struct net_device *dev;
	struct net *net = &init_net;
	struct local_addresses_list *list = NULL;
	struct local_addresses_list *tmp = NULL;

	list = kmalloc(sizeof(*list),GFP_KERNEL);
	INIT_LIST_HEAD(&(list->list));

	for_each_netdev(net,dev){
#ifdef MY_DEBUG_INFO
		pr_info( "device %s",dev->name);
#endif
		if(dev->ip_ptr)
		{
			struct in_device *in4 = dev->ip_ptr;
			struct in_ifaddr *addr;
			for(addr = in4->ifa_list ; addr; addr = addr->ifa_next)
			{
#ifdef MY_DEBUG_INFO
				int aux_addr = ntohl(addr->ifa_address);
				pr_info( "ip address %d.%d.%d.%d", NIPQUAD(aux_addr));
#endif
				tmp = kmalloc(sizeof(*tmp),GFP_KERNEL);
				tmp->address = ntohl(addr->ifa_address);
				list_add(&(tmp->list),&(list->list));
			}
		}
	}

	return list;
}

int remove_local_addresses_list(struct local_addresses_list *list)
{
	struct local_addresses_list *tmp;
	struct list_head *pos = NULL, *q = NULL;
	list_for_each_safe(pos,q,&(list->list))
	{
		tmp = list_entry(pos,local_addresses_list, list);//(pos,struct local_addresses_list,list);
#ifdef MY_DEBUG_INFO
		pr_info( "removing address %d.%d.%d.%d",NIPQUAD(tmp->address));
#endif
		list_del(pos);
		kfree(tmp);
	}

	return 0;
}


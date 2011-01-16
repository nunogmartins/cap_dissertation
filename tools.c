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

struct inode *getInodeFromFd(unsigned int fd)
{
	struct inode *d_inode = NULL;
	struct file *f = NULL;

	f = fget(fd);

	if(f!=NULL)
	{
		struct dentry *dentry = NULL;

		fput(f);
		dentry = f->f_dentry;
		if(dentry!=NULL)
		{
			d_inode = dentry->d_inode;
		}
	}

	return d_inode;
}


u16 getPortFromInode(struct file *f,struct inode *inode)
{
	struct socket *socket = NULL;
	if(inode)
	{
		if(S_ISSOCK(inode->i_mode))
		{
			socket = f->private_data;
			return ntohs(inet_sk(socket->sk)->inet_num) ;
		}
	}
	else
		return 0;

	return 0;
}

/*
 * unsigned int fd
 * int direction
 */

u16 getPort(unsigned int fd,int direction)
{
	struct file *f = NULL;
	//int fput_needed;
	struct socket *socket = NULL;
	/*struct sock *sock = NULL;
struct inet_sock *i_sock = NULL;
	 */
	f = fget(fd);

	if(f!=NULL)
	{
		struct dentry *dentry;
		struct inode *d_inode;
		fput(f);
		dentry = f->f_dentry;
		if(dentry !=NULL)
		{
			d_inode = dentry->d_inode;
			if(S_ISSOCK(d_inode->i_mode))
			{
				socket = f->private_data;
			}
		}
	}

	if(socket == NULL)
		return 0;

	return inet_sk(socket->sk)->inet_num;
	//return direction == 0 ? ntohs(inet_sk(socket->sk)->sport) : ntohs(inet_sk(socket->sk)->dport);
}

void getInetSockParameters(struct inet_sock *inetsock,struct packetInfo *ret)
{
	ret->port = inetsock->inet_num;
#ifdef MY_DEBUG
	pr_emerg( "rcv is 0x%x",ntohl(inetsock->inet_rcv_saddr));
	pr_emerg( "sport %hu dport %hu daddr 0x%x laddr 0x%x",ntohs(inetsock->inet_sport),ntohs(inetsock->inet_dport), ntohl(inetsock->inet_daddr),ntohl(inetsock->inet_saddr));
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
	ret->protocol = ((struct sock *)inetsock)->sk_protocol;

}


void getLocalPacketInfoFromFd(unsigned int fd, struct packetInfo *ret, int *err)
{
	struct file *f = NULL;
	struct socket *socket = NULL;

	*err = 0;
	f = fget(fd);

#ifdef MY_DEBUG	
	pr_info( "fd is %d f is null ? %s ", fd ,f == NULL ? "yes": "no");
#endif
	if(f!=NULL)
	{
		struct dentry *dentry;
		struct inode *d_inode;
		fput(f);
		dentry = f->f_dentry;
		if(dentry !=NULL)
		{
			d_inode = dentry->d_inode;
			if(S_ISSOCK(d_inode->i_mode))
			{
				socket = f->private_data;
				getInetSockParameters((struct inet_sock *)(socket->sk),ret);
#ifdef MY_DEBUG
				pr_emerg("local port %hu addr 0x%x proto %hu",ret->port, ret->address, ret->protocol);
#endif
			}else
			{
				*err = -1;
			}
		}else
		{
			*err = -2;
		}
	}
#ifdef MY_DEBUG
	else
	{
		pr_info( "f is null");
		*err = -3;
	}
#endif

}

void getLocalPacketInfoFromFile(struct file *f, struct packetInfo *ret, int *err)
{
	struct socket *socket = NULL;

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
				getInetSockParameters((struct inet_sock *)(socket->sk),ret);

#ifdef MY_DEBUG
				pr_info( "lport %hu addr 0x%x proto %hu",ret->port, ret->address, ret->protocol);
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

	for_each_netdev(net,dev)
	{
		pr_info( "device %s",dev->name);

		if(dev->ip_ptr)
		{
			struct in_device *in4 = dev->ip_ptr;
			struct in_ifaddr *addr;
			for(addr = in4->ifa_list ; addr; addr = addr->ifa_next)
			{
				pr_info( "ip address 0x%x", ntohl(addr->ifa_address));
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
		pr_info( "removing address 0x%x",tmp->address);
		list_del(pos);
		kfree(tmp);
	}

	return 0;
}


/*
 * tools.c
 *
 *  Created on: Nov 12, 2010
 *      Author: nuno
 */

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


struct localPacketInfo * getLocalPacketInfoFromFd(unsigned int fd)
{
	struct file *f = NULL;
	struct socket *socket = NULL;
	struct localPacketInfo *ret = NULL;

	f = fget(fd);

#ifdef MY_DEBUG	
	printk(KERN_INFO "f is null ? %s ", f == NULL ? "yes": "no");
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
				ret = kmalloc(sizeof(struct localPacketInfo),GFP_KERNEL);
				ret->port = inet_sk(socket->sk)->inet_num;
				if(ret->port == inet_sk(socket->sk)->inet_sport)
				{
				ret->address = inet_sk(socket->sk)->inet_saddr;
				ret->proto = inet_sk(socket->sk)->tos;
				}else
				{
				ret->address = inet_sk(socket->sk)->inet_daddr;
				ret->proto = inet_sk(socket->sk)->tos;
				}
#ifdef MY_DEBUG
				printk(KERN_INFO "local port %hu addr 0x%x proto %hu",ret->port, ret->address, ret->proto);
#endif
			}
		}
	}

	return ret;
}

struct localPacketInfo * getLocalPacketInfoFromFile(struct file *f)
{
	struct socket *socket = NULL;
	struct localPacketInfo *ret = NULL;


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
				ret = kmalloc(sizeof(struct localPacketInfo),GFP_KERNEL);
				ret->port = inet_sk(socket->sk)->inet_num;
#ifdef MY_DEBUG
				printk(KERN_INFO "rcv is ox%x",ntohl(inet_sk(socket->sk)->inet_rcv_saddr));
				printk(KERN_INFO "sport %hu dport %hu daddr 0x%x laddr 0x%x",ntohs(inet_sk(socket->sk)->inet_sport),ntohs(inet_sk(socket->sk)->inet_dport), ntohl(inet_sk(socket->sk)->inet_daddr),ntohl(inet_sk(socket->sk)->inet_saddr));
#endif
				if(ret->port == ntohs(inet_sk(socket->sk)->inet_sport))
				{
					if(!inet_sk(socket->sk)->inet_rcv_saddr){
						ret->address = inet_sk(socket->sk)->inet_saddr;
					}
					else
						ret->address = inet_sk(socket->sk)->inet_rcv_saddr;

				}else
				{
					ret->address = inet_sk(socket->sk)->inet_daddr;
				}
				ret->proto = socket->sk->sk_protocol;
#ifdef MY_DEBUG
				printk(KERN_INFO "lport %hu addr 0x%x proto %hu protocol %hu ",ret->port, ret->address, ret->proto, (socket->sk)->sk_protocol);
#endif
			}
		}
	}

	return ret;
}

void listAllDevicesAddress(void)
{
	struct net_device *dev;
	struct net *net = &init_net;

	for_each_netdev(net,dev)
	{
		unsigned char *mac = dev->dev_addr;
		int i=0;

		printk(KERN_INFO "device %s ipaddress %du",dev->name, 0);

		for (i = 0; i < 6; i++)
			printk(KERN_INFO "%02X%c", mac[i], (i<5)?':':' ' );

	}

}

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

	printk(KERN_INFO "f is null ? %s ", f == NULL ? "yes": "no");
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
				printk(KERN_INFO "is a socket");
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
				printk(KERN_INFO "local port %hu addr 0x%x proto %hu",ret->port, ret->address, ret->proto);
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
			printk(KERN_INFO "dentry <> null");
			if(S_ISSOCK(d_inode->i_mode))
			{
				printk(KERN_INFO "is a socket");
				socket = f->private_data;
				ret = kmalloc(sizeof(struct localPacketInfo),GFP_KERNEL);
				ret->port = inet_sk(socket->sk)->inet_num;
				if(ret->port == inet_sk(socket->sk)->inet_sport)
				{
					printk(KERN_INFO "rcv is ox%x",inet_sk(socket->sk)->inet_rcv_saddr);
					if(!inet_sk(socket>sk)->inet_rcv_saddr){
						ret->address = inet_sk(socket->sk)->inet_saddr;

					}
					else
						ret->address = inet_sk(socket->sk)->inet_rcv_saddr;
					ret->address = inet_sk(socket->sk)->inet_rcv_saddr;

				}else
				{
					ret->address = inet_sk(socket->sk)->inet_daddr;
				}
				ret->proto = inet_sk(socket->sk)->tos;
				printk(KERN_INFO "lport %hu addr 0x%x proto %hu",ret->port, ret->address, ret->proto);
			}
		}
	}

	return ret;
}

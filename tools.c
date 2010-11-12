/*
 * tools.c
 *
 *  Created on: Nov 12, 2010
 *      Author: nuno
 */

#include <linux/stat.h>
#include <linux/file.h>
#include <linux/path.h>
#include <linux/dcache.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/inet_sock.h>

#include "pcap_monitoring.h"

unsigned short getPort(unsigned int fd, struct task_struct *ts){
	struct file *f = NULL;
	int fput_needed;
	struct socket *socket = NULL;
	/*struct sock *sock = NULL;
	struct inet_sock *i_sock = NULL;
*/
	f = fget_light(fd,&fput_needed);
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
			}
		}
	}

	if(socket == NULL)
		return 0;

	return ntohs(inet_sk(socket->sk)->dport);
}

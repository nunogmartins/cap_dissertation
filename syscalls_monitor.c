/*
 * syscalls_monitor.c
 *
 *  Created on: Nov 9, 2010
 *      Author: nuno
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/byteorder/generic.h>
#include <asm/uaccess.h>
#include <linux/filter.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/string.h>
#include <net/inet_sock.h>

#include "table_port.h"
#include "pcap_monitoring.h"

extern struct kretprobe *kretprobes;
extern int instantiationKRETProbe(struct kretprobe *kret,
		const char *function_name,
		kretprobe_handler_t func_handler,
		kretprobe_handler_t func_entry_handler,
		ssize_t data_size);

extern char *application_name;
extern void print_regs(const char *function, struct pt_regs *regs);

static int sendto_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;

	if(application_name == NULL)
		return 1;

	if(strcmp(task->comm,application_name)!=0)
		return 1;

	return 0;
}
static int sendto_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	if(retval > 0)
	{

	}
	return 0;
}

static int recvfrom_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;

	if(application_name == NULL)
		return 1;

	if(!current->mm)
		return 1;

	if(strcmp(task->comm,application_name)!=0)
		return 1;

return 0;
}
static int recvfrom_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	if(retval > 0)
	{

	}
	return 0;
}


static int close_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct cell *my_data = (struct cell *)ri->data;
	struct socket *socket = NULL;
	int err = -1;

	if(!current->mm)
		return 1;

	printk(KERN_INFO "application %s",task->comm);
	print_regs("close",regs);

	if(application_name == NULL)
		return 1;

	if(strcmp(task->comm,application_name)!=0)
		return 1;

	socket = sockfd_lookup(regs->ax,&err);
	if(err !=-ENOTSOCK && socket != NULL)
	{
		struct sock *sk = socket->sk;
		struct inet_sock *i_sock = inet_sk(sk);

		my_data->port = i_sock->num;

	}
	my_data->fd = regs->ax;
	return 0;
}

static int close_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;

	print_regs("close_ret",regs);

	if(retval == 0)
		deletePort(my_data->port);

	return 0;
}


static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	int fd = regs->ax;
	struct sockaddr_in in;
	struct cell *my_data = (struct cell *)ri->data;

	if(!current->mm)
		return 1;

	if(application_name == NULL)
		return 1;

	if(strcmp(task->comm,application_name)!=0)
		return 1;

	memcpy(&in,(void *)regs->dx,regs->cx);

	my_data->fd = fd;
	my_data->port = ntohs(in.sin_port);

#ifdef DEBUG_D
	printk(KERN_INFO "bind to port %d and fd %d",ntohs(in.sin_port),fd);
#endif

	return 0;
}

static int bind_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	if(retval > 0)
	{
	//TODO: get the port from the data and insert
		insertPort(my_data->port);
	}
	return 0;
}


static int connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;

	if(!current->mm)
		return 1;

	if(application_name == NULL)
		return 1;


	if(strcmp(task->comm,application_name)!=0)
		return 1;
#ifdef DEBUG_D
	print_regs("connect", regs);
#endif
	return 0;
}

static int connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	if(retval > 0)
	{
		//TODO: get the data and insert it into the list
	}
	return 0;
}

static int accept_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	int server_fd = regs->ax;
	void * sockaddr_addr = (void *)regs->dx;
	struct sockaddr addr;
	void * clilen_addr = (void *)regs->cx;
	size_t clilen = 0;

	struct cell *my_data = (struct cell *)ri->data;

	if(!current->mm)
		return 1;

	if(application_name == NULL)
		return 1;

	if(strcmp(task->comm,application_name)!=0)
		return 1;

	memcpy(&clilen,clilen_addr,(size_t)4);
	memcpy(&addr,sockaddr_addr,(size_t)clilen);
#ifdef DEBUG_D
	printk(KERN_INFO "server fd %d and clilen %d ",server_fd,clilen);
#endif


	return 0;
}
static int accept_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
//	int i=-1;
	void *stack = (void *)regs->di;
	int server_fd = -1;
	struct sockaddr_in addr;
	long pointer = -1;
	struct socket *socket = NULL;
	int err;

	/*for(i=0;i <= 64 ; i+=4)
	{
		int value = -1;
		memcpy(&value,stack-i,4);
		printk(KERN_INFO "i=%d stack value =%p ", i,value);
	}
*/
	memcpy(&server_fd,(void *)(stack-24),4);
	memcpy(&pointer,(void*)(stack-20),4);
	memcpy(&addr,(void*)(pointer),16);

	if(retval > 0)
	{
		socket = sockfd_lookup(retval,&err);
		if(err !=-ENOTSOCK && socket != NULL)
		{
			struct sock *sk = socket->sk;
			struct inet_sock *i_sock = inet_sk(sk);
			insertPort(i_sock->num);

		}
		insertPort(htons(addr.sin_port));

	}
#ifdef DEBUG_D
	printk(KERN_INFO "to port %d ",htons(addr.sin_port));
	printk(KERN_INFO "accept returned file descriptor %d",retval);
	print_regs("accept",regs);
#endif


	return 0;
}

static int socket_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	int family = regs->cx;
	int type = regs->dx;
	int domain = regs->ax;

	if(!current->mm)
		return 1;

	if(application_name == NULL)
		return 1;

	if(domain==AF_INET || domain==AF_INET6){
		if(type==SOCK_STREAM || type==SOCK_DGRAM)
		{
			if(strcmp(task->comm,application_name)!=0)
				return 1;
		}else
			return 1;
	}
	else
		return 1;

#ifdef DEBUG_D
	printk(KERN_INFO "entry domain %d type %d family %d",domain,type, family);
#endif
	return 0;


}

static int socket_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	int family = -1;
	int type = -1;
	int domain = -1;
	void *stack = (void *)regs->bp;
	//int i = -1;
	memcpy(&domain,stack-36,4);
	memcpy(&type,stack-32,4);
	memcpy(&family,stack-28,4);

	/*for(i=0;i <= 36 ; i+=4)
	{
		int value = -1;
		memcpy(&value,stack-i,4);
		printk(KERN_INFO "i=%d stack value =%d ", i,value);
	}
*/
	if(retval > 0)
	{
		//TODO: add this file descriptor to the system
	}
#ifdef DEBUG_D
	printk(KERN_INFO "domain %d type %d family %d",domain,type, family);
	printk(KERN_INFO "the file descriptor is %d", retval);
#endif

	return 0;
}
/*
 * function called on module init to initialize kretprobes common to tcp and udp
 */

int init_kretprobes_syscalls(int *initial)
{
	int ret = -1;
	int index = *initial;



	    ret = instantiationKRETProbe((kretprobes+index),"sys_socket",socket_ret_handler,socket_entry_handler,0);
	    index +=1;
		if(ret < 0)
			return -1;

	    ret = instantiationKRETProbe((kretprobes+index),"sys_bind",bind_ret_handler,bind_entry_handler,0);
	    index +=1;
		if(ret < 0)
			return -1;

	    ret = instantiationKRETProbe((kretprobes+index),"sys_connect",connect_ret_handler,connect_entry_handler,0);
	    index +=1;
		if(ret < 0)
			return -1;

	    ret = instantiationKRETProbe((kretprobes+index),"sys_accept4",accept_ret_handler,accept_entry_handler,0);
	    index +=1;
		if(ret < 0)
			return -1;


	    ret = instantiationKRETProbe((kretprobes+index),"sys_close",close_ret_handler,close_entry_handler,(ssize_t)sizeof(struct cell));
	    index +=1;
		if(ret < 0)
			return -1;

		ret = instantiationKRETProbe((kretprobes+index),"sys_sendto",sendto_ret_handler,sendto_entry_handler,0);
		index +=1;
		if(ret < 0)
			return -1;


	    ret = instantiationKRETProbe((kretprobes+index),"sys_recvfrom",recvfrom_ret_handler,recvfrom_entry_handler,0);
	    index +=1;
		if(ret < 0)
			return -1;

		return 0;
}

int destroy_kretprobes_syscalls(int *initial)
{

	return 0;
}


/*
 * syscalls_monitor.c
 *
 *  Created on: Nov 9, 2010
 *      Author: nuno
 */
#include "config.h"

#include <asm/ptrace.h>

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

#ifdef MY_KPROBES

extern struct kretprobe *kretprobes;
extern int instantiationKRETProbe(struct kretprobe *kret,
		const char *function_name,
		kretprobe_handler_t func_handler,
		kretprobe_handler_t func_entry_handler,
		ssize_t data_size);

extern char *application_name;
extern void print_regs(const char *function, struct pt_regs *regs);
extern pid_t monitor_pid;
#ifdef UDP_PROBES
static int sendto_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	//int *fd = (int *)regs->di;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
#else
	int fd = regs->di;
#endif
	struct cell *my_data = (struct cell *)ri->data;

	CHECK_MONITOR_PID;

	my_data->fd = fd;
	
	return 0;
}
static int sendto_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packetInfo pi;
	int fd = my_data->fd;
	int err;
	
	if(retval >= 0 || retval == -11)
	{
		getLocalPacketInfoFromFd(fd,&pi,&err);
		if(err == 0)
			insertPort(&pi);
	}else
		pr_info("sendto retval < 0 which is %d ",retval);

	return 0;
}

static int recvfrom_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{	
	struct task_struct *task = ri->task;
	struct cell *my_data = (struct cell *)ri->data;
	//int *fd = (int *)regs->di;
	//int fd = regs->di;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
#else
	int fd = regs->di;
#endif

	CHECK_MONITOR_PID;

	my_data->fd = fd;

	return 0;
}
static int recvfrom_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{	
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell*)ri->data;
	struct packetInfo pi;
	int fd = my_data->fd;
	int err;

	if(retval >= 0 || retval == -11)
	{
		getLocalPacketInfoFromFd(fd,&pi,&err);
		if(err == 0)
			insertPort(&pi);
	}else{
#ifdef MY_DEBUG
	pr_info("recvfrom retval < 0 which is %d", retval);
#endif
	}	


	return 0;
}
#endif

#ifdef TCP_PROBES
static int close_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct packetInfo *my_data = (struct packetInfo *)ri->data;
	//void *stack = (void *)regs->bp;
	//struct socket *socket = stack+8;

#ifdef CONFIG_X86_32
	struct file *filp = regs->bx;
	struct inode *inode = regs->ax;
#elif CONFIG_X86_64
	struct file *filp = (struct file *)regs->si;
	struct inode *inode = (struct inode *)regs->di;
#endif

	int err = -1;

	CHECK_MONITOR_PID;

	getLocalPacketInfoFromFile(filp,my_data,&err);
	if(err >= 0){
#ifdef MY_DEBUG
		pr_emerg( "close_sock entry %s",task->comm);
		pr_emerg( "port %hu address %d.%d.%d.%d protocol %hu",my_data->port,NIPQUAD(my_data->address),my_data->protocol);
#endif	
	}
	else
		return 1;

	return 0;
}

static int close_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct packetInfo *pi = (struct packetInfo *)ri->data;
	

	if(retval == 0){
		deletePort(pi);
	}
	return 0;
}


static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	//int fd = regs->di;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
#else
	int fd = regs->di;
#endif
	struct cell *my_data = (struct cell *)ri->data;

	CHECK_MONITOR_PID;

	my_data->fd = fd;

	return 0;
}

static int bind_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packetInfo pi;
	int err;
	
	if(retval == 0)
	{
		getLocalPacketInfoFromFd(my_data->fd, &pi,&err);
		if(err == 0)
			insertPort(&pi);
	}

	return 0;
}


static int connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct cell *my_data =(struct cell *) ri->data;
	struct packetInfo pi;
	int err = -1;
	//int fd = regs->di;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
	struct sockaddr_in *in = regs->dx;
#else
	int fd = regs->di;
	struct sockaddr_in *in = regs->si;
	struct sockaddr *sa = regs->si;
#endif

	CHECK_MONITOR_PID;

	//pr_emerg("in 0x%p sa 0x%p sa data %s",in,sa,sa->sa_data);
	pr_emerg("\n");

	getLocalPacketInfoFromFd(fd,&pi,&err);
	if(err == 0){
		//insertPort(&pi);
		pr_emerg("before local: port %hu address %u and protocol %hu",pi.port, pi.address, pi.protocol);
	}
	pr_emerg("in family %hu port %hu",in->sin_family,ntohs(in->sin_port));
	my_data->fd = fd;

	return 0;
}

static int connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell*)ri->data;
	int fd = my_data->fd;
	struct packetInfo pi;
	int err;
	

	pr_emerg("sys connect ret from %s with pid %d",ri->task->comm, ri->task->pid);

	if(retval == 0 || retval == -115)
	{
		getLocalPacketInfoFromFd(fd,&pi,&err);
		if(err == 0){
			insertPort(&pi);
			pr_emerg("local: port %hu address %u and protocol %hu",pi.port, pi.address, pi.protocol);
		}
		
	}
	
	return 0;
}

static int accept_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;

	CHECK_MONITOR_PID;

	return 0;
}
static int accept_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct packetInfo pi;
	int err;

	if(retval > 0)
	{
		getLocalPacketInfoFromFd(retval,&pi,&err);
		if(err == 0)
			insertPort(&pi);
	}

	return 0;
}

static int socket_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	int type = regs->dx;
	int domain = regs->ax;
	//struct cell *my_data = (struct cell *)ri->data;

	CHECK_MONITOR_PID;

	if(domain==AF_INET || domain==AF_INET6){
		if(type==SOCK_STREAM || type==SOCK_DGRAM)
		{
			//ToDo: add a socket to cell with tcp
					//and which version so that ret can 
					// use it 
					//my_data->
		}else
			return 1;
	}
	else
		return 1;

	return 0;
}

static int socket_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	
	if(retval > 0)
	{
		//TODO: add this file descriptor to the system
		//my_data-> ... something
	}

	return 0;
}
/*
 * function called on module init to initialize kretprobes common to tcp and udp
 */
#endif

int init_kretprobes_syscalls(int *initial)
{
	int ret = -1;
	int index = *initial;


#ifdef TCP_PROBES
	    ret = instantiationKRETProbe((kretprobes+index),"sys_socket",socket_ret_handler,socket_entry_handler,(ssize_t)sizeof(struct cell));
	    index +=1;
		if(ret < 0)
			return -1;

	    ret = instantiationKRETProbe((kretprobes+index),"sys_bind",bind_ret_handler,bind_entry_handler,(ssize_t)sizeof(struct cell));
	    index +=1;
		if(ret < 0)
			return -1;

	    ret = instantiationKRETProbe((kretprobes+index),"sys_connect",connect_ret_handler,connect_entry_handler,(ssize_t)sizeof(struct cell));
	    index +=1;
		if(ret < 0)
			return -1;

	    ret = instantiationKRETProbe((kretprobes+index),"sys_accept4",accept_ret_handler,accept_entry_handler,(ssize_t)sizeof(struct cell));
	    index +=1;
		if(ret < 0)
			return -1;

/*
	    ret = instantiationKRETProbe((kretprobes+index),"sys_close",close_ret_handler,close_entry_handler,(ssize_t)sizeof(struct cell));
	    index +=1;
		if(ret < 0)
			return -1;
*/

		ret = instantiationKRETProbe((kretprobes+index),"sock_close",close_ret_handler,close_entry_handler,(ssize_t)sizeof(struct packetInfo));
		index +=1;
		if(ret < 0)
			return -1;
#endif
#ifdef UDP_PROBES
		ret = instantiationKRETProbe((kretprobes+index),"sys_sendto",sendto_ret_handler,sendto_entry_handler,(ssize_t)sizeof(struct cell));
		index +=1;
		if(ret < 0)
			return -1;


	    ret = instantiationKRETProbe((kretprobes+index),"sys_recvfrom",recvfrom_ret_handler,recvfrom_entry_handler,(ssize_t)sizeof(struct cell));
	    index +=1;
		if(ret < 0)
			return -1;
#endif
		return 0;
}

int destroy_kretprobes_syscalls(int *initial)
{

	return 0;
}

#endif

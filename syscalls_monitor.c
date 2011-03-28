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
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/sched.h>

#include "table_port.h"
#include "pcap_monitoring.h"
#include "debugfs_support.h"

#ifdef MY_DEBUG
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include "info_acquire.h"

struct syscall_info_acquire syscall_info;


static void *monitor_seq_start(struct seq_file *p, loff_t *pos)
{
	int i = 0;
	if(*pos > 0)
		return NULL;
	
		/*my_print_debug("on start return 0x%p\n",&syscall_info);

		for(i = 0 ; i < 5 ; i++)
		my_print_debug("position %d entry %d success %d unsucess %d\n",
				i,syscall_info.info[i].entry,syscall_info.info[i].success, syscall_info.info[i].unsuccess);
		my_print_debug("\n");
		*/
		return &syscall_info;
	
}

static void *monitor_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
	struct syscall_info_acquire *info = &syscall_info;
	int ipos = 0 ;
	*(pos)= *(pos)+1;
	ipos = *pos;

	//my_print_debug("on next %d\n",ipos);
	if(ipos <= 5)
	{
		/*my_print_debug("position %d entry %d success %d unsucess %d\n",
				ipos,info->info[ipos].entry,info->info[ipos].success, info->info[ipos].unsuccess);	
		
		my_print_debug("on next 0x%p and return 0x%p\n",v,&info->info[ipos]);
		*/
		return &info->info[ipos]; 
	}
	else
		return NULL;
	
}

static void monitor_seq_stop(struct seq_file *p, void *v)
{
	//kfree(v);
}

static int monitor_seq_show(struct seq_file *m, void *v)
{
	struct counters *c = NULL;

	//my_print_debug("on show 0x%p \n",v);
	if(v != NULL){
		c = v;
		seq_printf(m,"entry %d success %d unsucess %d\n",c->entry,c->success, c->unsuccess);
	}
	else{
		seq_printf(m,"v é nulo \n");
	}
	return 0;
}

static const struct seq_operations monitor_seq_ops = {
        .start  = monitor_seq_start,
        .next   = monitor_seq_next,
        .stop   = monitor_seq_stop,
        .show   = monitor_seq_show,
};

static int monitor_open(struct inode *inode, struct file *file)
{
	return seq_open(file,&monitor_seq_ops);
}

static int monitor_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations monitor_fops = {
        .open           = monitor_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        //.release        = monitor_release,
        .release = seq_release,
        .owner          = THIS_MODULE,
 };



#endif

pid_t monitor_pid;
u64 pid = -1, ppid = -1, tgid = -1;
extern struct dentry *my_debug_dir;
#ifdef MY_KPROBES
int kprobes_index;

static short isSon(pid_t pid, pid_t newpid)
{
	return pid == newpid ? 1 : 0;
}

static short itsMe(pid_t pid, pid_t newpid)
{
	return pid == newpid ? 1: 0;
}

static short isGroup(pid_t pid, pid_t newpid)
{
	return pid == newpid ? 1 : 0;
}

#define TO_MONITOR(t) \
	if(itsMe(pid,t->pid) || isSon(ppid,t->parent->pid) || isGroup(tgid,t->tgid)){ \
		goto monitor; \
	}else {\
		my_data->fd = -1; \
		return 0; \
		}
	

#define NR_PROBES 7

struct kretprobe *kretprobes = NULL;

struct cell{
	int fd;
};

struct closeInfo {
	int fd;
	struct packetInfo pi;
};


void print_regs(const char *function, struct pt_regs *regs)
{
#ifdef CONFIG_X86_64
	my_print_debug( "%s ax=%p bx=%p cx=%p dx=%p di=%p si=%p r8=%p r9=%p",function, (void *)regs->ax,(void *)regs->bx,(void *)regs->cx,(void *)regs->dx,(void*)regs->di,(void *) regs->si,(void *)regs->r8,(void *)regs->r9);
#endif
}

struct connect_extern_info {
	struct packetInfo external;
	int fd;
};

#ifdef UDP_PROBES
#ifdef SENDPROBE
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

	//CHECK_MONITOR_PID;
	syscall_info.info[0].entry++;
	TO_MONITOR(task)
	
monitor:
	my_data->fd = fd;
	syscall_info.info[0].success++;
	return 0;
}
static int sendto_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packetInfo pi;
	int fd = my_data->fd;
	int err;

	if(my_data->fd == -1){
		syscall_info.info[0].unsuccess++;
		return 0;
	}


	if(retval >= 0 || retval == -11 || retval == -111)
	{
		getLocalPacketInfoFromFd(fd,&pi,&err);
		if(err == 0)
			insertPort(&pi);
	}else
		my_print_debug("sendto retval < 0 which is %d ",retval);

	return 0;
}
#endif //SENDPROBE

#ifdef RECVPROBE
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
	syscall_info.info[1].entry++;
	TO_MONITOR(task)
	
monitor:
	my_data->fd = fd;
	syscall_info.info[1].success++;
	return 0;
}
static int recvfrom_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{	
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell*)ri->data;
	struct packetInfo pi;
	int fd = my_data->fd;
	int err;
	
	if(my_data->fd == -1){
		syscall_info.info[1].unsuccess++;
		return 0;
	}


	if(retval >= 0 || retval == -11)
	{
		getLocalPacketInfoFromFd(fd,&pi,&err);
		if(err == 0)
			insertPort(&pi);
	}else{
#ifdef MY_DEBUG_INFO
	my_print_debug("recvfrom retval < 0 which is %d", retval);
#endif
	}	


	return 0;
}
#endif //RECVPROBE

#endif // UDPPROBES

#ifdef TCP_PROBES
#ifdef ACCEPTPROBE
static int accept_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct cell *my_data = (struct cell *)ri->data;
	syscall_info.info[2].entry++;
	TO_MONITOR(task)
	
monitor:
	syscall_info.info[2].success++;
return 0;
}
static int accept_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packetInfo pi;
	int err;
	
	if(my_data->fd == -1){
		syscall_info.info[2].unsuccess++;
		return 0;
	}
	if(retval > 0)
	{
		getLocalPacketInfoFromFd(retval,&pi,&err);
		if(err == 0)
			insertPort(&pi);
	}

	return 0;
}
#endif //ACCEPTPROBE
#endif //TCP_PROBES

#ifdef COMMON_TCP_UDP

#ifdef CLOSEPROBE
static int close_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct closeInfo *my_data = (struct closeInfo *)ri->data;
	//void *stack = (void *)regs->bp;
	//struct socket *socket = stack+8;

#ifdef CONFIG_X86_32
	struct file *filp = (struct file *)regs->bx;
	struct inode *inode = (struct inode *)regs->ax;
#else
	struct file *filp = (struct file *)regs->si;
	struct inode *inode = (struct inode *)regs->di;
#endif

	int err = -1;
	syscall_info.info[3].entry++;
	TO_MONITOR(task)
	
monitor:

	getLocalPacketInfoFromFile(filp,&(my_data->pi),&err);
	if(err >= 0){
#ifdef MY_DEBUG_INFO
		my_print_debug( "close_sock entry %s",task->comm);
		my_print_debug( "port %hu address %d.%d.%d.%d protocol %hu",my_data->pi.port,NIPQUAD(my_data->pi.address),my_data->pi.protocol);
#endif
		syscall_info.info[3].success++;
	}
	else {
		my_data->fd = -1;
	}

	return 0;
}

static int close_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct closeInfo *cI = (struct closeInfo *)ri->data;
	
	if(cI->fd == -1){
		syscall_info.info[3].unsuccess++;
		return 0;
	}
	if(retval == 0){
#ifdef MY_DEBUG_INFO
		my_print_debug( "close_ret: port %hu address %d.%d.%d.%d protocol %hu",cI->pi.port,NIPQUAD(cI->pi.address),cI->pi.protocol);
#endif
		deletePort(&(cI->pi));
	}
	return 0;
}
#endif //CLOSEPROBE

#ifdef BINDPROBE
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
	syscall_info.info[4].entry++;
	TO_MONITOR(task)
	
monitor:
	my_data->fd = fd;
	syscall_info.info[4].success++;
	return 0;
}

static int bind_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct cell *my_data = (struct cell *)ri->data;
	struct packetInfo pi;
	int err;
	int fd = my_data->fd;	

	if(my_data->fd == -1){
		syscall_info.info[4].unsuccess++;
		return 0;
	}
	if(retval == 0)
	{
		getLocalPacketInfoFromFd(fd, &pi,&err);
		if(err == 0)
			insertPort(&pi);
	}

	return 0;
}
#endif //BINDPROBE

#ifdef CONNECTPROBE
static int connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	struct connect_extern_info *my_data =(struct connect_extern_info *) ri->data;
	int err = -1;
	//int fd = regs->di;
#ifdef CONFIG_X86_32
	int fd = regs->ax;
	struct sockaddr_in *in = (struct sockaddr_in *)regs->dx;
#else
	int fd = regs->di;
	struct sockaddr_in *in = (struct sockaddr_in *)regs->si;
#endif
	syscall_info.info[5].entry++;
	TO_MONITOR(task)
	
monitor:
	my_data->fd = fd;

	getLocalPacketInfoFromFd(fd,&(my_data->external),&err);
	if(err == 0){
		my_data->external.address = ntohl(in->sin_addr.s_addr);
		my_data->external.port = ntohs(in->sin_port);
		insertPort(&(my_data->external));
#ifdef MY_DEBUG_INFO
		my_print_debug("before local: port %hu address %d.%d.%d.%d and protocol %hu\n",my_data->external.port, NIPQUAD(my_data->external.address), my_data->external.protocol);
#endif
		syscall_info.info[5].success++;
	}else {
		my_data->fd = -1;
	}

	return 0;
}

static int connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct connect_extern_info *my_data = (struct connect_extern_info *)ri->data;
	int fd = my_data->fd;
	struct packetInfo pi;
	int err;

	if(fd == -1){
		syscall_info.info[5].unsuccess++;
		return 0;
	}

	if(retval == 0 || retval == -115)
	{
		deletePort(&(my_data->external));
		getLocalPacketInfoFromFd(fd,&pi,&err);
		if(err == 0){
			insertPort(&pi);
#ifdef MY_DEBUG_INFO
			my_print_debug("local: port %hu address %d.%d.%d.%d and protocol %hu",pi.port, NIPQUAD(pi.address), pi.protocol);
#endif
		}
		
	}
	
	return 0;
}
#endif //CONNECTPROBE
#ifdef SOCKETPROBE
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

	}

	return 0;
}

#endif //SOCKETPROBE

#endif //COMMON_TCP_UDP



static int instantiationKRETProbe(struct kretprobe *kret,
				const char *function_name,
				kretprobe_handler_t func_handler,
				kretprobe_handler_t func_entry_handler,
				ssize_t data_size)
{
	int ret = -1;

	struct kprobe kp = {
	.symbol_name = function_name,
	};

	kret->kp = kp;
	kret->handler = func_handler;
	kret->entry_handler = func_entry_handler;
	kret->data_size		= data_size;
	kret->maxactive		= 20;

	ret = register_kretprobe(kret);
    if (ret < 0) {
		my_print_debug( "register_kretprobe failed, returned %d\n", ret);
		return -1;
	}

	my_print_debug( "Planted kretprobe at %p, handler addr %p\n",
	       kret->kp.symbol_name, kret->kp.addr);

	return ret;
}

static void initializeTreeWithTaskInfo(void)
{
	struct task_struct *t;

	for_each_process(t){
		if (t->tgid == pid || t->parent->tgid == pid)
		{
			//ToDo: change all structures according to pid
			//ToDo: get all ports from the task that has new_pid

			struct files_struct *files;
			struct file **fd;
			struct fdtable *fdt;

			files = t->files;
			fdt = files->fdt;

			my_print_debug( "application %s with pid %lu", t->comm,(unsigned long)t->pid);

			while(fdt != NULL)
			{
				unsigned long file_descriptor = 0;
				struct file *file;

				fd = fdt->fd;
				for(file_descriptor=0; file_descriptor < fdt->max_fds; file_descriptor++)
				{
					if((file=fd[file_descriptor]) != NULL){
						struct packetInfo p;
						int err;
						getLocalPacketInfoFromFile(file,&p,&err);

						if(err == 0)
						{
							if(insertPort(&p) > 0){
								my_print_debug("insertion was ok");
							}
							else{
								my_print_debug("something was wrong with the insertion");

							}
						}

					}
				}
				//end of for or while more internal ...
				fdt = fdt->next; //verifica se existem mais fdtable
			}  //end of while / no more fdtables in files_struct

		}
	}
}

static ssize_t options(struct file *file, const char __user *user_buf,size_t size, loff_t *ppos)
{
	unsigned long option;
	char *buf;
	char *endp;

	my_print_debug( "pid_write function called");
	buf = kmalloc(size,GFP_KERNEL);

	copy_from_user(buf,user_buf,size);
	/*
	 * ToDo: actualizar todas as estruturas necessárias ao funcionamento da monitorização inclusivé
	 * o pid
	 * Esta função irá fazer o parsing do pid
	 * Se for -1 irá limpar todas as estruturas, se for diferente de -1 reinicia o processo de
	 * monitorização
	 *
	 */
	option = simple_strtoul(buf,&endp,10);
	if(endp == buf)
	{
		my_print_debug( "could not convert value into long");
		return size;
	}
	kfree(buf);
	my_print_debug( "option = %lu",option);

	switch(option)
	{
	case 0:
		printTree();		
		break;
	case 1:
		initializeTreeWithTaskInfo();
		break;
	case 2:
		clearInfo();
		break;
	default:
		my_print_debug("OPTION NOT DEFINED \n");
		break;
	}

	return size;
}


static const struct file_operations pid_fops = {
		.owner = THIS_MODULE,
		.write = options,
};

void createMonitoringSystem(void)
{

	struct dentry *parent = NULL;
	memset(&syscall_info,0,sizeof(syscall_info));
	register_debugfs_file("option", &pid_fops);

#ifdef MY_DEBUG

	parent = createMonitorStatDir();
	debugfs_create_file("stats",S_IRUSR,parent,NULL,&monitor_fops);

#endif
	register_monitor_id("pid",&pid);
	register_monitor_id("ppid",&ppid);
	register_monitor_id("tgid",&tgid);
}
/*
 * function called on module init to initialize kretprobes common to tcp and udp
 */

int init_kretprobes_syscalls(void)
{
	int ret = 0;

	monitor_pid = -1;

	createMonitoringSystem();


	kretprobes = kmalloc(sizeof(*kretprobes)*NR_PROBES,GFP_KERNEL);

	if(!kretprobes){
		my_print_debug( "problem allocating memory");
		return -1;
	}

#ifdef COMMON_TCP_UDP
#ifdef BINDPROBE
	ret = instantiationKRETProbe((kretprobes+kprobes_index),"sys_bind",bind_ret_handler,bind_entry_handler,(ssize_t)sizeof(struct cell));
	kprobes_index +=1;
	if(ret < 0)
		return -1;
#endif //BINDPROBE
#ifdef CONNECTPROBE
	ret = instantiationKRETProbe((kretprobes+kprobes_index),"sys_connect",connect_ret_handler,connect_entry_handler,(ssize_t)sizeof(struct connect_extern_info));
	kprobes_index +=1;
	if(ret < 0)
		return -1;
#endif //CONNECTPROBE
#ifdef SOCKETPROBE
	ret = instantiationKRETProbe((kretprobes+kprobes_index),"sys_socket",socket_ret_handler,socket_entry_handler,(ssize_t)sizeof(struct cell));
	kprobes_index +=1;
	if(ret < 0)
		return -1;

#endif //SOCKETPROBE
#ifdef CLOSEPROBE
	ret = instantiationKRETProbe((kretprobes+kprobes_index),"sock_close",close_ret_handler,close_entry_handler,(ssize_t)sizeof(struct packetInfo));
	kprobes_index +=1;
	if(ret < 0)
		return -1;
#endif //CLOSEPROBE
#endif //COMMON_TCP_UDP

#ifdef TCP_PROBES
#ifdef 	ACCEPTPROBE
	ret = instantiationKRETProbe((kretprobes+kprobes_index),"sys_accept4",accept_ret_handler,accept_entry_handler,(ssize_t)sizeof(struct cell));
	kprobes_index +=1;
		if(ret < 0)
			return -1;
#endif // ACCEPTPROBE
#endif // TCP_PROBES

#ifdef UDP_PROBES
#ifdef SENDPROBE
	ret = instantiationKRETProbe((kretprobes+kprobes_index),"sys_sendto",sendto_ret_handler,sendto_entry_handler,(ssize_t)sizeof(struct cell));
	kprobes_index +=1;
	if(ret < 0)
		return -1;
#endif //SENDPROBE
#ifdef RECVPROBE
	ret = instantiationKRETProbe((kretprobes+kprobes_index),"sys_recvfrom",recvfrom_ret_handler,recvfrom_entry_handler,(ssize_t)sizeof(struct cell));
	kprobes_index +=1;
	if(ret < 0)
		return -1;
#endif //RECVPROBE
#endif //UDP_PROBES

	return kprobes_index;
}

static void removeKprobe(int index)
{
	if((kretprobes+index)!=NULL){
		my_print_debug( "in index %d missed %d probes" , index,(kretprobes+index)->nmissed);
		unregister_kretprobe((kretprobes+index));
		my_print_debug( "kretprobe at %p named %s unregistered\n", (kretprobes+index)->kp.addr, (kretprobes+index)->kp.symbol_name);
	}
}

void destroy_kretprobes_syscalls(void)
{
	int i=-1;

	for(i=0; i < kprobes_index ; i++)
	{
		removeKprobe(i);
	}

	if(kretprobes)
		kfree(kretprobes);
}

#endif

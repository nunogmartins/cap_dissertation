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

//#define DEBUG_D 0

char *application_name = "server";

struct kretprobe *kretprobes = NULL;
struct jprobe *jprobes = NULL;

extern int init_debug(void);
extern void destroy_debug(void);
static void print_regs(const char *function, struct pt_regs *regs)
{
	#ifdef DEBUG_D
	printk(KERN_INFO "%s ax=%p bx=%p cx=%p dx=%p bp=%p sp=%p", function, (void *)regs->ax,(void *)regs->bx,(void *)regs->cx,(void *)regs->dx,(void*)regs->bp,(void *) regs->sp);
	#endif
}

/*
static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;	
	int family = regs->cx;
	int type = regs->dx;
	int domain = regs->ax;

	if(!current->mm)
		return 1;	
	
	if(strcmp(task->comm,"server")!=0)
		return 1;

return 0;
}
static int bind_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}
*/

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
	return 0;
}


static int close_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;
	
	if(!current->mm)
		return 1;

	if(application_name == NULL)
		return 1;	
	
	if(strcmp(task->comm,application_name)!=0)
		return 1;

	print_regs("close",regs);

	return 0;
}

static int close_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	
	if(retval == 0)
		deletePort(0);
	
	return 0;
}


static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;	
	int fd = regs->ax;
	struct sockaddr_in in;

	if(!current->mm)
		return 1;

	if(application_name == NULL)
		return 1;		
	
	if(strcmp(task->comm,application_name)!=0)
		return 1;
	
	memcpy(&in,(void *)regs->dx,regs->cx);
	#ifdef DEBUG_D
	printk(KERN_INFO "bind to port %d and fd %d",ntohs(in.sin_port),fd);
	#endif

	return 0;
}

static int bind_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
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
	return 0;
}

static int accept_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = ri->task;	
	int server_fd = regs->ax;
	int sockaddr_addr = regs->dx;
	struct sockaddr addr;
	int clilen_addr = regs->cx;
	int clilen = -1;

	if(!current->mm)
		return 1;	

	if(application_name == NULL)
		return 1;	
	
	if(strcmp(task->comm,application_name)!=0)
		return 1;

	memcpy(&clilen,(void *)clilen_addr,4);
	memcpy(&addr,(void *)sockaddr_addr,clilen);
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
#ifdef DEBUG_D
	printk(KERN_INFO "accept returned file descriptor %d",retval);
#endif
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
#ifdef DEBUG_D
	printk(KERN_INFO "to port %d ",htons(addr.sin_port));
#endif

	print_regs("accept",regs);
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
		}
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
#ifdef DEBUG_D
	printk(KERN_INFO "domain %d type %d family %d",domain,type, family);
	printk(KERN_INFO "the file descriptor is %d", retval);
#endif

	return 0;
}

/*
static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct task_struct *task = NULL;
	void *stack = NULL;
	//struct files_struct *files;

	if (!current->mm)
		return 1;
	
	//dump_stack();

	return 0;
}

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	struct task_struct *task;
	struct files_struct *files;
	struct kretprobe *rp = NULL;
	struct kprobe kp;
	const char *name = NULL;
	struct socket *sock = NULL;
	void *stack = NULL;
	struct sock *sk;
	int addr_len = -1;
	struct sockaddr_in in;
	struct inet_sock *inet = NULL;
	int addr;
	short int my_port = -1;
	int *p = NULL;

	task = (struct task_struct *)ri->task;

	rp = ri->rp;
	kp = rp->kp;
    name = kp.symbol_name;

	printk(KERN_INFO "%s returned %d application %s\n",
	name, retval, task->comm);

	//stack = task->stack;
	stack = regs->bp;

	printk(KERN_INFO "before copy -- size %d bytes", addr_len);
	memcpy(&addr_len, stack+16, 4);
	memcpy(&addr,stack+8,4);
	p = stack+12;
	memcpy(&in,*p,16);

	//sock = (struct socket *) (stack + 8);
	//sk = sock->sk;
	//inet = inet_sk(sk);
	//in = kmalloc(*in,GFP_KERNEL);
	//in = (struct sockaddr_in*)(stack + 12);
	//sk = (struct sock *)(stack - 12);
	//printk(KERN_INFO "%p and dport = %d",sock, inet->num);	
printk(KERN_INFO "my port %d and fd = %d",ntohs(in.sin_port),addr);
	printk(KERN_INFO "after copy -- size %zu bytes", addr_len);
	return 0;
}
*/


static int instantiationKRETProbe(struct kretprobe *kret,
								const char *function_name,
								kretprobe_handler_t func_handler,
								kretprobe_handler_t func_entry_handler)
{
	int ret = -1;
	
	struct kprobe kp = {
	.symbol_name = function_name,
	};
	
	kret->kp = kp;
	kret->handler = func_handler;
	kret->entry_handler = func_entry_handler;
	kret->data_size		= 0;
	kret->maxactive		= 20;

	ret = register_kretprobe(kret);
    if (ret < 0) {
		printk(KERN_INFO "register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
		
	printk(KERN_INFO "Planted kretprobe at %p, handler addr %p\n",
	       kret->kp.symbol_name, kret->kp.addr);
	
	return ret;
}

static void changeApplicationName(const char *newname)
{
	/*deve ser verificado o tamanho do newname e limitado a um valor 
		decente para o tamanho do nome da aplicacao */

	if(application_name == NULL)
		application_name = kmalloc(strlen(newname),GFP_KERNEL);

		strcpy(application_name,newname);
}

static int __init instrument_init(void)
{
    int ret = -1;
    kretprobes = kmalloc(sizeof(*kretprobes)*7,GFP_KERNEL);
	if(!kretprobes)
		printk(KERN_INFO "problem allocating memory");


    ret = instantiationKRETProbe(kretprobes,"sys_socket",socket_ret_handler,socket_entry_handler);
	if(ret < 0)
		return -1;

    ret = instantiationKRETProbe(kretprobes+1,"sys_bind",bind_ret_handler,bind_entry_handler);
	if(ret < 0)
		return -1;

    ret = instantiationKRETProbe(kretprobes+2,"sys_connect",connect_ret_handler,connect_entry_handler);
	if(ret < 0)
		return -1;

    ret = instantiationKRETProbe(kretprobes+3,"sys_accept4",accept_ret_handler,accept_entry_handler);
	if(ret < 0)
		return -1;

	
    ret = instantiationKRETProbe(kretprobes+4,"sys_close",close_ret_handler,close_entry_handler);
	if(ret < 0)
		return -1;

	ret = instantiationKRETProbe(kretprobes+5,"sys_sendto",sendto_ret_handler,sendto_entry_handler);
	if(ret < 0)
		return -1;

	
    ret = instantiationKRETProbe(kretprobes+6,"sys_recvfrom",recvfrom_ret_handler,recvfrom_entry_handler);
	if(ret < 0)
		return -1;

	init_debug();
/*
    ret = instantiationKRETProbe(kretprobes+4,"sys_bind",bin_ret_handler,bind_entry_handler);
	if(ret < 0)
		return -1;

    ret = instantiationKRETProbe(kretprobes+5,"sys_bind",bin_ret_handler,bind_entry_handler);
	if(ret < 0)
		return -1;

    ret = instantiationKRETProbe(kretprobes+2,"tcp_close",ret_handler,entry_handler);
	if(ret < 0)
		return -1;
*/
    //register all probes
	return 0;
}

static void __exit instrument_exit(void)
{
	destroy_debug();
    //unregister all probes ...
    unregister_kretprobe(kretprobes);
	printk(KERN_INFO "kretprobe at %p unregistered\n", kretprobes->kp.addr);

    unregister_kretprobe(kretprobes+1);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+1)->kp.addr);
   
    unregister_kretprobe(kretprobes+2);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+2)->kp.addr);

    unregister_kretprobe(kretprobes+3);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+3)->kp.addr);
    
	unregister_kretprobe(kretprobes+4);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+4)->kp.addr);

	unregister_kretprobe(kretprobes+5);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+5)->kp.addr);
    
	unregister_kretprobe(kretprobes+6);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+6)->kp.addr);


/*
	unregister_kretprobe(kretprobes+2);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+2)->kp.addr);
*/    
	if(kretprobes)
        kfree(kretprobes);
    if(jprobes)
        kfree(jprobes);
}

module_init(instrument_init)
module_exit(instrument_exit)
MODULE_LICENSE("GPL");


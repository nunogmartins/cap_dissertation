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

struct kretprobe *kretprobes = NULL;
struct jprobe *jprobes = NULL;

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
//	struct task_struct *task;
//	struct files_struct *files;

//	if (!current->mm)
//		return 1;	/* Skip kernel threads */
	
	dump_stack();

	return 1;
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

	if (!current->mm)
		return 1;	/* Skip kernel threads */
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



static int instantiationKRETProbe(struct kretprobe *kret,
								const char *function_name,
								kretprobe_handler_t handler,
								kretprobe_handler_t entry_handler)
{
	int ret = -1;
	
	struct kprobe kp = {
	.symbol_name = function_name,
	};
	
	kret->kp = kp;
	kret->handler = handler;
	kret->entry_handler = entry_handler;
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


static int __init instrument_init(void)
{
    int ret = -1;
    kretprobes = kmalloc(sizeof(*kretprobes)*3,GFP_KERNEL);
	if(!kretprobes)
		printk(KERN_INFO "problem allocating memory");


    ret = instantiationKRETProbe(kretprobes,"inet_bind",ret_handler,entry_handler);
	if(ret < 0)
		return -1;
/*

    ret = instantiationKRETProbe(kretprobes+1,"tcp_fin",ret_handler,entry_handler);
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
    //unregister all probes ...
    unregister_kretprobe(kretprobes);
	printk(KERN_INFO "kretprobe at %p unregistered\n", kretprobes->kp.addr);
/*
    unregister_kretprobe(kretprobes+1);
	printk(KERN_INFO "kretprobe at %p unregistered\n", (kretprobes+1)->kp.addr);
    
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


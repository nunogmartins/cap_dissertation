/*
 * common_monitor_func.c
 *
 *  Created on: Nov 8, 2010
 *      Author: nuno
 */

#include <linux/kprobes.h>

extern struct kretprobe *kretprobes;
extern int instantiationKRETProbe(struct kretprobe *kret,
		const char *function_name,
		kretprobe_handler_t func_handler,
		kretprobe_handler_t func_entry_handler,
		ssize_t data_size);

/*
 * monitor function inet_csk_accept
 * struct sock *inet_csk_accept(struct sock *sk, int flags, int *err)
 *
 */

static int accept_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int accept_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}

/*
 * monitor function inet_bind
 * int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
 *
 */
static int bind_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int bind_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}

/*
 * monitor function inet_create
 * static int inet_create(struct net *net, struct socket *sock, int protocol,int kern)
 *
 */

static int socket_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int socket_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}


/*
 * function called on module init to initialize kretprobes common to tcp and udp
 */

int init_kretprobes_common(int *initial)
{
	int ret = 0;
	int index = *initial;

	ret = instantiationKRETProbe((kretprobes+index),"inet_csk_accept",accept_ret_handler,accept_entry_handler,0);
	index +=1;
	if(ret < 0)
		return -1;

	ret = instantiationKRETProbe((kretprobes+index),"inet_bind",bind_ret_handler,bind_entry_handler,0);
	index +=1;
	if(ret < 0)
		return -1;

	ret = instantiationKRETProbe((kretprobes+index),"inet_create",socket_ret_handler,socket_entry_handler,0);
	index +=1;
	if(ret < 0)
		return -1;

	*initial = index;
	return 0;
}

int destroy_kretprobes_common(int *initial)
{

	return 0;
}


/*
 * tcp_monitor_func.c
 *
 *  Created on: Nov 7, 2010
 *      Author: nuno
 */

#include <linux/kprobes.h>

extern kretprobe *kretprobes;
extern int instantiationKRETProbe(struct kretprobe *kret,
								const char *function_name,
								kretprobe_handler_t func_handler,
								kretprobe_handler_t func_entry_handler);


/*
 * Monitor function tcp_v4_connect
 *int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 *
 */

static int tcp_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int tcp_connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}

/*
 * Monitor function tcp_close
 * void tcp_close(struct sock *sk, long timeout)
 *
 */
static int tcp_close_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int tcp_close_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}

/*
 * function called on module init to initialize kretprobes specific to tcp
 */

int init_kretprobes_tcp(int *initial)
{
	int ret = 0;
	int index = *initial;

	ret = instantiationKRETProbe((kretprobes+index),"tcp_v4_connect",tcp_connect_ret_handler,tcp_connect_entry_handler);
	index +=1;
	if(ret < 0)
		return -1;

	ret = instantiationKRETProbe((kretprobes+index),"tcp_close",tcp_close_ret_handler,tcp_close_entry_handler);
	index +=1;
	if(ret < 0)
		return -1;

	*ìnitial = index;
	return 0;
}

int destroy_kretprobes_tcp(int *initial)
{

	return 0;
}

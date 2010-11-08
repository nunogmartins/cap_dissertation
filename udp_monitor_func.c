/*
 * udp_monitor_func.c
 *
 *  Created on: Nov 8, 2010
 *      Author: nuno
 */

#include <linux/kprobes.h>


extern kretprobe kretprobes;
static int position = 0;

extern int instantiationKRETProbe(struct kretprobe *kret,
		const char *function_name,
		kretprobe_handler_t func_handler,
		kretprobe_handler_t func_entry_handler);

/*
 * monitor function ip4_datagram_connect
 * int ip4_datagram_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
 *
 */

static int udp_connect_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int udp_connect_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}

/*
 * Monitor function tcp_close
 * inline void udp_lib_close(struct sock *sk, long timeout)
 *  so we can use it with sk_common_release(struct sock *sk) that is called
 *  inside udp_lib_close
 *
 */
static int udp_close_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	return 0;
}

static int udp_close_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval = regs_return_value(regs);
	return 0;
}

/*
 * function called on module init to initialize kretprobes specific to udp
 */

int init_kretprobes_udp(int *initial)
{
	int ret = 0;
	int index = *initial;

	ret = instantiationKRETProbe((kretprobes+index),"ip4_datagram_connect",udp_connect_ret_handler,udp_connect_entry_handler);
	if(ret < 0)
		return -1;
	*ìnitial = index;
	return 0;
}

int destroy_kretprobes_udp(int *initial)
{

	return 0;
}

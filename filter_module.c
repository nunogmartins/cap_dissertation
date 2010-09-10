#include <linux/module.h>
#include "filter_module.h"

void process_filter(void)
{
	printk(KERN_INFO "process_filter callled\n");
}


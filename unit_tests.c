
#include "config.h"

//#ifdef UNIT_TESTING

#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/limits.h>

#include "table_port.h"

#define INITIAL_PORT 1
#define FINAL_PORT 1024

#define MAX_DATA 1024

static struct packetInfo *ports;

int populate(void)
{
	int i=0;
	int iteration = 0;
	s64 delta;
	ktime_t initial, end;
	struct packetInfo *sentinel = NULL;

	ports = kmalloc(MAX_DATA*sizeof(*ports),GFP_KERNEL);
	pr_info("Populate\n");

	initial = ktime_get();	
	for(i=INITIAL_PORT,iteration=0;i < FINAL_PORT ; i++,iteration++)
	{
		sentinel = (ports)+iteration;
		sentinel->port = (u16)i;
		sentinel->address = 0x7f000001;
		sentinel->protocol = 0x06;
		insertPort(sentinel);
	}
	end = ktime_get();
	delta = ktime_to_ns(ktime_sub(end,initial));
	pr_info("%lld ns to execute a insert\n",(long long)delta);

	initial = ktime_get();
	searchPort(sentinel);
	end = ktime_get();
	delta = ktime_to_ns(ktime_sub(end,initial));
	pr_info("%lld ns to execute one search\n",(long long)delta);

    printTree();

	return 0;
}

int depopulate(void)
{
	int i = INITIAL_PORT;
	int iteration = 0;
	s64 delta;
	ktime_t initial, end;

	pr_info("DePopulate\n");
	initial = ktime_get();
	for(i=INITIAL_PORT, iteration=0;i < FINAL_PORT; i++,iteration++)
	{
		deletePort((ports+iteration));
	}
	end = ktime_get();
	delta = ktime_to_ns(ktime_sub(end,initial));
	pr_info("%lld ns to execute a remove\n",(long long)delta);
	
	printTree();

	kfree(ports);
	ports = NULL;
	return 0;
}

//#endif

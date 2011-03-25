
#include "config.h"

//#ifdef UNIT_TESTING

#include <linux/slab.h>

#include "table_port.h"

#define INITIAL_PORT 1
#define FINAL_PORT 1024

#define MAX_DATA 1024

static struct packetInfo *ports;

int populate(void)
{
	int i=0;
	int iteration = 0;

	ports = kmalloc(MAX_DATA*sizeof(*ports),GFP_KERNEL);
	pr_info("Populate\n");
	for(i=INITIAL_PORT,iteration=0;i < FINAL_PORT; i++,iteration++)
	{
		struct packetInfo *sentinel = (ports)+iteration;
		sentinel->port = (u16)i;
		sentinel->address = 0x7f000001;
		sentinel->protocol = 0x06;
		insertPort(sentinel);
	}

    printTree();

	return 0;
}

int depopulate(void)
{
	int i = INITIAL_PORT;
	int iteration = 0;

	pr_info("DePopulate\n");
	for(i=INITIAL_PORT, iteration=0;i < FINAL_PORT; i++,iteration++)
	{
		deletePort((ports+iteration));
	}

	printTree();

	kfree(ports);
	ports = NULL;
	return 0;
}

//#endif

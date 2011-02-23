
#include "config.h"

#ifdef UNIT_TESTING

#include <linux/slab.h>

#include "table_port.h"

#define INITIAL_PORT 2010
#define FINAL_PORT 2050

#define MAX_DATA 5

static struct packetInfo *ports;

int populate(void)
{
	int i=0, j=0;
	int iteration = 0;
	struct packetInfo pi;

	ports = kmalloc(MAX_DATA*sizeof(*ports),GFP_KERNEL);
	pr_emerg("Populate\n");
	for(i=INITIAL_PORT,iteration=0;i < FINAL_PORT; i+=10,iteration++)
	{
		struct packetInfo *sentinel = (ports)+iteration;
		sentinel->port = (u16)i;
		sentinel->address = 0x7f000001;
		sentinel->protocol = 0x06;
		insertPort(sentinel);
	}

	for(j=0; j < 10 ; j++ )
	{
		pi = *ports;
		pi.address = pi.address + j;
		insertPort(&pi);
	}


	{
		pi = *ports;
		pi.protocol = 0x11;
		insertPort(&pi);
	}

	//(ports)->address = (ports->address);

	printTree();
	return 0;	
}

int depopulate(void)
{
	int i = INITIAL_PORT;
	int iteration = 0;
	//do for all ports my_erase
	pr_emerg("DePopulate\n");
	for(i=INITIAL_PORT;i < FINAL_PORT; i+=10,iteration++)
	{
		deletePort((ports+iteration));

	}

	deletePort((ports+0));
	{
		struct packetInfo pi;
		pi = *(ports);
		pi.protocol = 0x11;
		deletePort(&pi);
	}
	printTree();

	kfree(ports);
	ports = NULL;
	return 0;
}

#endif

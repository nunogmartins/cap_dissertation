
#include "config.h"

#ifdef UNIT_TESTING

#include <linux/slab.h>

#include "portsDB.h"

#define INITIAL_PORT 2010
#define FINAL_PORT 2050

#define MAX_DATA 5

extern struct rb_root db;

static struct portInfo *ports;

int populate(void)
{
	int i=0;
	int iteration = 0;

	ports = kmalloc(MAX_DATA*sizeof(struct portInfo),GFP_KERNEL);

	for(i=INITIAL_PORT;i < FINAL_PORT; i+=10)
	{
		//create port to use in my_insert
		struct portInfo *sentinel = (ports)+iteration;
		sentinel->port = (u16)i;
		sentinel->address = 0x7f000001;
		sentinel->protocol = 0x06;
		//my_insert();
		my_insert(&db, sentinel);
		iteration++;
	} 
	
	return 0;	
}

int depopulate(void)
{
	int i = INITIAL_PORT;
	printAll(&db);
	//do for all ports my_erase
	for( ; i < FINAL_PORT ; i+=10)
	{
		my_erase(&db,(u16)i);
	}
	kfree(ports);
	ports = NULL;

	return 0;
}

#endif

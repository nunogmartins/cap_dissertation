/*
parsing module which has the previous filter and the tables
created for accounting which ports are open

*/

#include <linux/module.h>
#include <linux/filter.h>

#define MY_MAX 100
#define SMAX ((1 << (sizeof(unsigned short int) * 8))-1)
unsigned short int tcp[SMAX];
unsigned short int udp[SMAX];

void initialize(void)
{
	unsigned int i;
	unsigned short int k;

	k = SMAX;
	for(i=0;i < k ; i++)
	{
		tcp[i]=0;
		udp[i]=0;
	}
	
	printk(KERN_INFO "%d 0x%04hx\n",i,k);

}


void insertTCPPort(unsigned short int port)
{

}

void removeTCPPort(unsigned short int port)
{

}

void insertUDPPort(unsigned short int port)
{

}

void removeUDPPort(unsigned short int port)
{

}

void process_filter(void)
{
	printk(KERN_INFO "process_filter callled\n");
}


void updateFilter(void)
{
}

EXPORT_SYMBOL(process_filter);

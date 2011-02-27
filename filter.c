/*
 * filter.c
 *
 *  Created on: Feb 27, 2011
 *      Author: nuno
 */


#include "config.h"

#ifdef MY_DEBUG
#include "info_acquire.h"
struct filter_info_acquire filter_info = {.entry = 0,.src = 0, .dst = 0 };
#endif

extern unsigned int (*portExists)(struct packetInfo *src_pi,struct packetInfo *dst_pi);
unsigned int (*Backup_portExists)(struct packetInfo *pi,struct packetInfo *dst_pi);

unsigned int my_portExists(struct packetInfo *src_pi,struct packetInfo *dst_pi)
{

	struct portInfo *sentinel_src = NULL;
	struct portInfo *sentinel_dst = NULL;
#ifdef MY_DEBUG
	filter_info.entry++;
#endif
	if(src_pi!=NULL && dst_pi!=NULL)
	{

		if((src_pi->protocol == 0x11 || src_pi->protocol == 0x06)){

			sentinel_src = my_search(&db,src_pi);

			if(sentinel_src != NULL)
			{
#ifdef MY_DEBUG
				filter_info.src++;
#endif
				return 1;
			}

			sentinel_dst = my_search(&db,dst_pi);

			if(sentinel_dst != NULL)
			{
#ifdef MY_DEBUG
				filter_info.dst++;
#endif
				return 1;
			}

		}
	}

	return 0;
}

void backupFilter(void)
{
	Backup_portExists = portExists;
	portExists = my_portExists;
}

void restoreFilter(void){
	portExists = Backup_portExists;
}

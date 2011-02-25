/*
 * syscall_overhead.c
 *
 *  Created on: Feb 25, 2011
 *      Author: nuno
 */
#include <stdio.h>
#include <time.h>
#include <asm/unistd.h>
//#include <unistd.h>



int main(int argc, char **argv)
{
	clock_t t1,t2;
	int i;
	int iterations;

	if(argc != 2)
	{
		printf("errado ...\n");
		return 0;
	}

	iterations = atoi(argv[1]);
	t1 = clock();
	for(i=0; i < iterations; i++)
	{
		__SYSCALL(__NR_getpid, sys_getpid);
	}
	t2 = clock();

	printf("%.4lf seconds of processing\n", (t2-t1)/(double)CLOCKS_PER_SEC);
	printf("%.8lf mili of processing\n", (double)(t2-t1));


	return 0;
}

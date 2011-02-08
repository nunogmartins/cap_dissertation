/*
 * one_hundred.c
 *
 *  Created on: Jan 26, 2011
 *      Author: nuno
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define MAX_IPV4 16

#define PORT 2010

int main(int argc, char **argv)
{
	int *sockfds;
	int number_of_sockets = atoi(argv[1]);
	int number_of_times = atoi(argv[2]);
	int i,j;
	struct sockaddr_in serv_addr;
	int garbage;
	char address[MAX_IPV4];
	clock_t t1,t2;

	if(argc != 4)
		return -1;

	inet_pton(AF_INET,argv[3],&(serv_addr.sin_addr));
	scanf("%d",&garbage);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(PORT);

	sockfds = malloc(number_of_sockets*sizeof(int));
	t1=clock();
	for(j=0; j < number_of_times; j++){
		for(i= 0; i < number_of_sockets; i++)
		{
			serv_addr.sin_port = htons(PORT+i);
			sockfds[i] = socket(AF_INET, SOCK_STREAM, 0);
			if(sockfds[i] < 0)
				printf("create error on %d\t",i);
			else{
			bind(sockfds[i], (struct sockaddr *)&serv_addr, sizeof(serv_addr));
			listen(sockfds[i], 5);
			}
		}
		i--;

		for(i;i >= 0; --i)
		{
			if(sockfds[i] > 0)
				close(sockfds[i]);
			else
				printf("close error on %d\t",i);
		}
	}
	t2=clock();
	free(sockfds);
    printf("%.4lf seconds of processing\n", (t2-t1)/(double)CLOCKS_PER_SEC);
    printf("%.8lf mili of processing\n", (double)(t2-t1));
	return 0;
}

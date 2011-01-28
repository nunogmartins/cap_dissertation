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

#define PORT 2010

int main(int argc, char **argv)
{
	int *sockfds;
	int number_of_sockets = atoi(argv[1]);
	int number_of_times = atoi(argv[2]);
	int i,j;
	struct sockaddr_in serv_addr;
	int garbage;
	scanf("%d",&garbage);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(PORT);

	sockfds = malloc(number_of_sockets*sizeof(int));
	for(j=0; j < number_of_times; j++){
		for(i= 0; i < number_of_sockets; i++)
		{
			serv_addr.sin_port = htons(PORT+i);
			sockfds[i] = socket(AF_INET, SOCK_STREAM, 0);
			bind(sockfds[i], (struct sockaddr *)&serv_addr, sizeof(serv_addr));
			listen(sockfds[i], 5);
		}

		for(i;i >= 0; --i)
		{
			close(sockfds[i]);
		}
	}
	free(sockfds);
	return 0;
}

/*
 * udp_server.c
 *
 *  Created on: Nov 12, 2010
 *      Author: nuno
 */



/* Sample UDP server */

#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <stdio.h>

int main(int argc, char**argv)
{
   int sockfd,n;
   struct sockaddr_in servaddr,cliaddr;
   socklen_t len;
   char mesg[1000];

   sockfd=socket(AF_INET,SOCK_DGRAM,0);

   bzero(&servaddr,sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
   servaddr.sin_port=htons(32000);
   bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));

   for (;;)
   {
      len = sizeof(cliaddr);
      n = recvfrom(sockfd,mesg,1000,0,(struct sockaddr *)&cliaddr,&len);
      sendto(sockfd,mesg,n,0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
      printf("-------------------------------------------------------\n");
      mesg[n] = 0;
      printf("Received the following:\n");
      printf("%s",mesg);
	  printf("from port %d ",ntohs(cliaddr.sin_port));
      printf("-------------------------------------------------------\n");
   }

   close(sockfd);
   return 0;
}

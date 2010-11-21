/*
 * udp_client.c
 *
 *  Created on: Nov 12, 2010
 *      Author: nuno
 */

/* Sample UDP client */


#include <sys/socket.h>
#include <netinet/in.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char**argv)
{
   int sockfd,n;
   struct sockaddr_in servaddr,cliaddr;
   char sendline[1000];
   char recvline[1000];
   socklen_t len;

   if (argc != 1)
   {
      printf("usage:  udp_client \n");
      return 0;
   }

   sockfd=socket(AF_INET,SOCK_DGRAM,0);

   bzero(&servaddr,sizeof(servaddr));
   //bzero(&cliaddr,sizeof(cliaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_addr.s_addr=inet_addr("10.0.2.15");
   servaddr.sin_port=htons(32000);

   while (fgets(sendline, 10000,stdin) != NULL)
   {
      sendto(sockfd,sendline,strlen(sendline),0,
             (struct sockaddr *)&servaddr,sizeof(servaddr));
	  printf("sended message to server on port %d\n",ntohs(servaddr.sin_port));
      n=recvfrom(sockfd,recvline,10000,0,(struct sockaddr *)&cliaddr,&len);
      recvline[n]=0;
	  printf("socket len %zu \n",len);
	  printf("received message on port %d\n",htons(cliaddr.sin_port));
      fputs(recvline,stdout);
   }
   close(sockfd);

   return 0;
}

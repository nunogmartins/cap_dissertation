#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
//#include <error.h>

void error(char *msg)
{
  perror(msg);
  exit(0);
}

#define READ_BUFFER 50000

int main(int argc, char *argv[])
{
	int sockfd, newsockfd, portno, clilen;
//, childpid;
	char buffer[READ_BUFFER];
	struct sockaddr_in serv_addr, cli_addr;
	int n;
	//signal(SIGCHLD, SIG_IGN);

	if(argc < 2)
	{
		fprintf(stderr, "ERROR: no port number provided\n");
		exit(1);
	}

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(sockfd < 0)
	{
		error("ERROR opening socket");
	}

	bzero((char*)&serv_addr, sizeof(serv_addr));
	
	portno = atoi(argv[1]);

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(portno);

	printf("sizeof serv_addr e %d \n",sizeof(serv_addr));

	if( bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("ERROR on binding");
		exit(2);
	}

	listen(sockfd, 5);
	
	while(1)
	{
		clilen = sizeof(cli_addr);
		newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, (socklen_t *)&clilen);

		if(newsockfd < 0)
		{
			perror("ERROR on accept");
		}

		/*if((childpid = fork()) < 0 )
		{
			error("server: fork error");
			exit(3);
		}
		else
			if(childpid == 0)
			{
				close(sockfd);
				while(1)
				{*/
					bzero(buffer, READ_BUFFER);
					n = read(newsockfd, buffer, READ_BUFFER-1);
					if( n < 0)
						perror("ERROR reading from socket");

					
					char ola[READ_BUFFER];
					bzero(ola,READ_BUFFER);
					strncpy(ola,buffer,strlen(buffer)-2); // minus 2 because it has \r\n in the buffer

					if(strcmp("ola",ola) == 0)
					{
						printf("equal zero\n");
						close(newsockfd);
						break;

					}else {
						printf("not equal zero\n");
						}						
					strcat(ola," telnet\n");
					n = write(newsockfd, ola, READ_BUFFER-1);
					if( n < 0)
						perror("ERROR writing to socket");

					//exit(0);
		
				//}
				//exit(0);
			//}
			close(newsockfd);
	}
	close(sockfd);
	return 0;
}

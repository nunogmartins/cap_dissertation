/*
 * manager.c
 *
 *  Created on: Feb 21, 2011
 *      Author: nuno
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char **argv)
{

	pid_t pid;

	printf("%s",argv[1]);

	pid = fork();

	if(pid == 0)
	{
		setuid(1000);
		execv(argv[1],NULL);
	}else{
		if(pid > 0)
		{
			int fd = open("/sys/kernel/debug/pcap_debug/pid_monitor",O_WRONLY);
			int status;

			if(fd > 0)
			{
				write(fd,(const void *)&pid,sizeof(pid_t));
				close(fd);
			}

			waitpid(pid,&status,0);
		}
	}

	return 0;
}

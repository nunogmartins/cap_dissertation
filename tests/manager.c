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

	pid = fork();

	if(pid == 0)
	{
		setuid(1000);
		execv(argv[1],NULL);
	}else
		if(pid > 0)
		{
			int fd = open("/sys/kernel/debug/pcap_debug/pid_monitor",O_WRONLY);

			if(fd > 0)
			{
				write(fd,pid,sizeof(pid_t));
				close(fd);
			}
			waitpid(pid);
		}

	return 0;
}

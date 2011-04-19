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

	printf("%s\n",argv[1]);

	pid = fork();

	if(pid == 0)
	{
		int fd[3];
		int i=0;
		pid_t my_pid;

		 fd [0] = open("/sys/kernel/debug/pcap_debug/pid",O_WRONLY);
		 fd [1] = open("/sys/kernel/debug/pcap_debug/ppid",O_WRONLY);
		 fd [2] = open("/sys/kernel/debug/pcap_debug/tgid",O_WRONLY);

		my_pid = getpid();
		for(i=0; i < 3 ; i++)
		if(fd[i] > 0)
		{
			char buf[10];
			snprintf(buf,9,"%lu",(unsigned long)my_pid);
			write(fd[i],(const void *)buf,sizeof(buf));
			close(fd[i]);
		}
		setuid(1000);
		//sleep(5);
		execv(argv[1],argv+1);
	}else{
		if(pid > 0)
		{
			int status;
			waitpid(pid,&status,0);
		}
	}

	return 0;
}

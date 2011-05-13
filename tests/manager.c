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
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include <signal.h>

struct manager {
	pid_t process;
	pid_t tcpdump;
	char *config_filename;
	char **process_args;
	char **tcpdump_args;
	char **module_load;
	char **module_unload;
};

void transformMonitorStats(int fd);
void transformFilterStats(int fd);
void executeProgram(struct manager *man);
void executeTcpdump(struct manager *man);

void readConfigFile(struct manager *man);
void clearManagerInfo(struct manager *man);
void executeModule(struct manager *man, int load);

int main(int argc, char **argv)
{
	int c;
	char *my_arg;
	int i=0;
	char *config_filename = NULL;
	struct manager man;
	bzero(&man,sizeof(struct manager));
	unsigned int option = 0;
	
	while((c=getopt(argc,argv,"c:tpm"))!=-1)
	{
		switch(c){
		case 't':
			printf("Option tcpdump is activated\n");
			option = option | 2;
			printf("value of option is %d \n",option);
			break;
		case 'p':
			printf("Option process is activated\n");
			option = option | 4;
			printf("value of option is %d \n",option);
			break;
			
		case 'c':
			config_filename = malloc(sizeof(char)*(strlen(optarg)+1));
			strncpy(config_filename,optarg,strlen(optarg));
			man.config_filename = config_filename;
			printf("config file is %s\n",man.config_filename);
			break;
		case 'm':
			printf("Option module is activated \n");
			option = option | 1;
			printf("value of option is %d \n",option);
		}
	}
	
	printf("value of option is %x \n",option);
	
	if(man.config_filename != NULL)
		readConfigFile(&man);
	
	if(option & 1 && man.module_load != NULL && man.module_unload != NULL)
	{
		executeModule(&man, 1);
	}
		
	if(option & 2 && man.tcpdump_args != NULL)
	{
#ifdef DEBUG
		char **new_pointer = man.tcpdump_args;
		int i=0;
		while(*new_pointer !=NULL )
		{
			printf("tcpdump: %d %s \n",i,*new_pointer);
			i++;
			new_pointer++;
		}
#endif
		executeTcpdump(&man);
	}
	
	if(option & 4 && man.process_args != NULL)
	{
#ifdef DEBUG	
		char **new_pointer = man.process_args;
		int i=0;
		while(*new_pointer !=NULL )
		{
			printf("process: %d %s \n",i,*new_pointer);
			i++;
			new_pointer++;
		}
#endif		
		executeProgram(&man);
	}
	
	if(option & 1 && man.module_load != NULL && man.module_unload != NULL)
	{
		executeModule(&man, 0);
	}
	
	clearManagerInfo(&man);
	printf("ended gracefully\n");
	
	return 0;
}

void clearArgs(char **args)
{
	int i=0;
	char *tmp = args[i];
	
	while(tmp != NULL)
	{
		free(tmp);
		i++;
		tmp = args[i];
	}
}

void clearManagerInfo(struct manager *man)
{
	if(man->config_filename != NULL)
		free(man->config_filename);
	
	if(man->process_args != NULL){
		clearArgs(man->process_args);
		free(man->process_args);
	}
	if(man->tcpdump_args != NULL){
		clearArgs(man->tcpdump_args);
		free(man->tcpdump_args);
	}
	if(man->module_load != NULL){
		clearArgs(man->module_load);
		free(man->module_load);
	}
	if(man->module_unload != NULL){
		clearArgs(man->module_unload);
		free(man->module_unload);
	}
}

void transformMonitorStats(int fd)
{

}
void transformFilterStats(int fd)
{

}

char ** readTuple(void)
{
	char *strip_str = NULL;
	int number = 1;
	char **pointer = NULL;
	
	pointer = malloc(sizeof(long)*number);
	
	strip_str = strtok(NULL," \n");
	
	if(strip_str != NULL){
		do{
			char *part = malloc(sizeof(char) * strlen(strip_str));
			strncpy(part,strip_str,strlen(strip_str));
					
			strip_str = strtok(NULL," \n");
			pointer[number-1] = part;
			number++;
			pointer = realloc(pointer,sizeof(long)*number);
		}while(strip_str != NULL);
				
		pointer[number-1] = NULL;
	}
	
	return pointer;
}

void readConfigFile(struct manager *man)
{
	FILE *fp = NULL;
	char str[256];
	fp = fopen(man->config_filename,"r");
	char **pointer = NULL;
	char *what = NULL;
	if(fp != NULL)
	{
		char *strip_str;
		int number = 0;
		while(fgets(str,256,fp)!=NULL){
#ifdef DEBUG		
			printf("str is %d len and is %s \n",(int)strlen(str),str);
#endif
			strip_str = strtok(str,"=");
			what = malloc(sizeof(char)*strlen(strip_str));
			strncpy(what,strip_str,strlen(strip_str));
			if(strip_str != NULL){
		
				pointer = readTuple();
			
				if(pointer != NULL && strcmp(what,"PROGRAM")==0)
				{
					man->process_args = pointer;
				}else
				if(pointer != NULL && strcmp(what,"TCPDUMP")==0)
				{
					man->tcpdump_args = pointer;
				}else 
				if(pointer != NULL && strcmp(what,"MODULE_LOAD")==0)
				{
					man->module_load = pointer;
				}
				else
				if(pointer != NULL && strcmp(what,"MODULE_UNLOAD")==0)
				{
					man->module_unload = pointer;
				}
				else
				printf("what is %s \n",what);
				
				free(what);
			}
		
		}
						
		printf("\n");
		fclose(fp);
	}
}

void executeProgram(struct manager *man){
	pid_t pid;

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
		if(fd[i] >= 0)
		{
			char buf[10];
			snprintf(buf,9,"%lu",(unsigned long)my_pid);
			write(fd[i],(const void *)buf,sizeof(buf));
			close(fd[i]);
		}
		setuid(1000);
		execv(man->process_args[0],man->process_args);
	}else{
		if(pid > 0)
		{
			int status;
			int ofd[2];
			man->process = pid;
			waitpid(pid,&status,0);
			
			if(man->tcpdump != 0){
				kill(man->tcpdump,SIGKILL);
			}
			
			ofd[0] = open("/sys/kernel/debug/pcap_debug/monitor/stats",O_RDONLY);
			ofd[1] = open("/sys/kernel/debug/pcap_debug/filter/stats",O_RDONLY);
			if(ofd[0] >= 0 && ofd[1] >=0 )
			{
				transformMonitorStats(ofd[0]);
				transformFilterStats(ofd[1]);
				close(ofd[0]);
				close(ofd[1]);
			}
		}
	}
}

void executeModule(struct manager *man, int load)
{
	pid_t pid;

	pid = fork();

	if(pid == 0)
	{
		if(load)
			execv(man->module_load[0],man->module_load);
		else
			execv(man->module_unload[0],man->module_unload);
	}
}


void executeTcpdump(struct manager *man){
	pid_t pid;

	pid = fork();

	if(pid == 0)
	{
		execv(man->tcpdump_args[0],man->tcpdump_args);
	}else{
		if(pid > 0)
		{
			man->tcpdump = pid;
		}
	}
}

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	FILE *fp = fopen("/proc/net/dev","r");
	char str[50];
	int i=0;
	if(fp == NULL)
		return -1;
	//memset(str,0,50);
	fscanf(fp,"%s",str);
	while(strcmp("eth0:",str)!=0){
		//memset(str,0,50);
		fscanf(fp,"%s",str);
	}	
	for(i=0; i < 10 ; i++){
		fscanf(fp,"%s",str);
		if(i==1 || i==9)
			printf("%s \n",str);

		//memset(str,0,50);
	}

	return 0;
}

#define ENOTIMPLEMENTED 255 
struct entry {
	unsigned short proto;
	unsigned short port;
	unsigned int fd;
};

int insertPort(int port);
int deletePort(int port);


#ifndef TABLE_PORT_H
#define TABLE_PORT_H

#define ENOTIMPLEMENTED 255 
/*struct entry {
	unsigned short proto;
	unsigned short port;
	unsigned int fd;
};
*/
int insertPort(u16 port);
int deletePort(u16 port);

#endif

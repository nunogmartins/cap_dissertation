#ifndef CONFIG_H
#define CONFIG_H

//#define UNIT_TESTING
#undef UNIT_TESTING

#ifdef UNIT_TESTING

#undef MY_KPROBES
#undef TCP_PROBES
#undef UDP_PROBES
#undef COMMON_TCP_UDP

#else

#define MY_KPROBES
#define TCP_PROBES
#define UDP_PROBES
#define COMMON_TCP_UDP
#endif

#ifdef TCP_PROBES
#define ACCEPTPROBE
#endif

#ifdef UDP_PROBES
#define RECVPROBE
#define SENDPROBE
#endif

#ifdef COMMON_TCP_UDP
//#define SOCKETPROBE
//#define CLOSEPROBE
#define CONNECTPROBE
#define BINDPROBE
#endif

#endif //UNIT_TESTING


#define MY_DEBUG

#define DEBUGFS_SUPPORT
#define FILTER_SUPPORT
#define DB_SUPPORT
#define SYSCALLS_SUPPORT


#define DFITLER
//#undef DFILTER

#define MY_DEBUG_INFO
//#undef DEBUG_INFO

#ifndef CONFIG_H
#define CONFIG_H

#define UNIT_TESTING
//#undef UNIT_TESTING

#ifdef UNIT_TESTING
#undef MY_KPROBES
#undef TCP_PROBES
#undef UDP_PROBES
#else
#define MY_KPROBES
#define TCP_PROBES
#define UDP_PROBES
#endif

//#define OLD_PHASE
#undef OLD_PHASE

#define NEXT_PHASE
//#undef NEXT_PHASE

#define DFITLER
//#undef DFILTER

#define DEBUG_INFO
//#undef DEBUG_INFO

#endif

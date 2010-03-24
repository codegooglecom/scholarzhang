#ifndef _GFWKEYWORD_H_
#define _GFWKEYWORD_H_

#include "dstmaintain.h"
#include "connmanager.h"

extern char GK_OPT_SYNTAX[];

void gk_read_config(char *line, char *device, char *ip, int *maxconn, int *maxdst, char *candlist, int *control_wait, int *times, int *time_interval, int *expire_timeout, int *tcp_mss, double *kps, int *pps);
int gk_read_config_file(char *file, char *device, char *ip, int *maxconn, int *maxdst, char *candlist, int *control_wait, int *times, int *time_interval, int *expire_timeout, int *tcp_mss, double *kps, int *pps);

#endif /* _GFWKEYWORD_H_ */

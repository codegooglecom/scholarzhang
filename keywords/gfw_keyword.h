#ifndef _KEYWORD_H_
#define _KEYWORD_H_

#include "dstmaintain.h"
#include "connmanager.h"

int keyword_read_config(char *line, char *device, char *ip, int *maxconn, int *maxdst, int *control_wait, int *times, int *time_interval, int *expire_timeout, int *tcp_mss, int *kps, int *pps);
int keyword_read_config_file(char *file, char *device, char *ip, int *maxconn, int *maxdst, int *control_wait, int *times, int *time_interval, int *expire_timeout, int *tcp_mss, int *kps, int *pps);

#endif /* _KEYWORD_H_ */

#ifndef _CONNMANAGER_H_
#define _CONNMANAGER_H

#include "dstmaintain.h"

#define DEFAULT_CONN 10000
typedef void (*gk_callback_f)(char *content, char result, void *arg);

int gk_add_context(char * const content, const int length, char *const result, const int type, gk_callback_f cb, void *arg);

int gk_cm_init(char *device, char *ip, struct dstlist *list, int capa);
int gk_cm_fd();
long gk_cm_conn_next_time();
long gk_cm_conn_step();
void gk_cm_read_cap();
void gk_cm_finalize();
void gk_cm_config(char _times, int _time_interval, int _expire_timeout, int _tcp_mss, double _kps, int _pps);

#endif /* _CONNMANAGER_H_ */

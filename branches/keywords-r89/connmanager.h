#ifndef _CONNMANAGER_H_
#define _CONNMANAGER_H

#include "dstmaintain.h"

#define DEFAULT_CONN 10000
typedef void (*gk_callback_f)(char *content, char result, void *arg);

int gk_add_context(char * const content, const int length, char *const result, const int type, gk_callback_f cb, void *arg);

int gk_cm_run();
void gk_cm_abort();
void gk_cm_finish();
int gk_cm_init(char *device, char *ip, struct dstlist *list, int capa);
void gk_cm_finalize();
void gk_cm_config(int _control_wait, int _times, int _time_interval, int _expire_timeout, int _tcp_mss, double _kps, int _pps);

#endif /* _CONNMANAGER_H_ */

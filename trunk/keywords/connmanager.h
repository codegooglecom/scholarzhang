#ifndef _CONNMANAGER_H_
#define _CONNMANAGER_H

#define DEFAULT_CONN 10000
typedef void (*callback_f)(char result, void *arg);

int add_context(const char * const content, const int length, const char * const result, const int type, callback_f cb, void *arg);

int connmanager_run();
void connmanager_finish();
int connmanager_init(char *device, char *ip, struct dstlist *list, int capa);
void connmanager_finalize();
int connmanager_config(int _control_wait, int _times, int _time_interval, int _expire_timeout, int _tcp_mss, int _bps, int _pps);

#endif /* _CONNMANAGER_H_ */

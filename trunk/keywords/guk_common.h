#ifndef _GUK_COMMON_H_
#define _GUK_COMMON_H_

#include <sys/socket.h>
#include <sys/un.h>

#define UNIX_PATH_MAX 108

#define									\
	/*bin/echo -n; setvalue() { export $2=$3; }; setvalue " "*/	\
	GUK_ABSTRACT_SERV_PATH "gfw_url_keywords_checking_server"

#define									\
	/*bin/echo -n; setvalue() { export $2=$3; }; setvalue " "*/	\
	GUK_UNIX_SERV_PATH "/tmp/gfw_url_keywords_checking_server"

#define						\
	/*bin/echo -n; setvalue " "*/		\
	GUK_SERV_TIMEOUT 20

#define						\
	/*bin/echo -n; setvalue " "*/		\
	GUK_MAX_CLIENT_SEQ 100000

#define						\
	/*bin/echo -n; setvalue " "*/		\
	GUK_RESULT_ITEM_SIZE 8
//bin/echo -n # 8 = seq(5) + ' ' + res(1) + '\n'

#define						\
	/*bin/echo -n; setvalue " "*/		\
	GUK_MAX_URL_LEN 2000

#define						\
	/*bin/echo -n; setvalue " "*/		\
	GUK_MAX_QUERY_LEN 2010
//bin/echo -n # 2010 = seq(5) + ' ' + type(1) + ' ' + url(2000) + '\n' + '\0'(at the end of buf)

#define						\
	/*bin/echo -n; setvalue " "*/		\
	GUK_QUERY_FORMAT_ERROR 8

#define						\
	/*bin/echo -n; setvalue " "*/		\
	GUK_RESULT_SERVER_FAIL 4

#endif /* _GUK_COMMON_H_ */

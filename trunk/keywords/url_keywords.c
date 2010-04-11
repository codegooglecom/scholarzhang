#define MAX_URLLEN 2000

#include "gfwkeyword.h"
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <semaphore.h>
#include <pthread.h>

char device[100], ip[100];
char config_file[1000] = "/etc/gfwkeyword.conf";
char candlist[1000];
struct port_range *cand;
int cand_count;
int maxconn, maxdst;
int time_interval, expire_timeout, tcp_mss, pps;
char times;
int mode = 1, local_mode, offset;
double kps;
struct dstlist *dest;

pthread_mutex_t mutex_conn;
pthread_t gk_cm_bg;
struct gk_cm_stat {
	char running;
	char context_add;
} cm_status = {0, 0};

#define HH_ADD_LEN 24
#define HH_PRE_LEN 11
#define HH_PST_LEN 13

static inline void quit() {
	void *ret;

	cm_status.running = 0;
	pthread_join(gk_cm_bg, &ret);
	pthread_mutex_lock(&mutex_conn);
	gk_cm_finalize();
	pthread_mutex_unlock(&mutex_conn);
	free_dstlist(dest);
	free(cand);
	pthread_mutex_destroy(&mutex_conn);
}

void inthandler (int _) {
	(void)_;
	quit();
	exit(-2);
}

void release_single_query(char *content, char result, void *arg) {
	sem_post(arg);
}

void gk_add_context_blocking(char * const content, const int length, char *const result, const int type, gk_callback_f cb, void *arg) {
	int ret;
	long time;
	while (cm_status.running) {
		pthread_mutex_lock(&mutex_conn);
		ret = gk_add_context(content, length, result, type, cb, arg);
		if (ret)
			time = gk_cm_conn_next_time() - gettime();
		pthread_mutex_unlock(&mutex_conn);
		if (ret) {
			if (time / 1000)
				sleep(time / 1000);
			usleep(1000 * (time % 1000));
			pthread_mutex_lock(&mutex_conn);
			time = gk_cm_conn_step() - gettime();
			pthread_mutex_unlock(&mutex_conn);
		}
		else
			break;
	}
	cm_status.context_add = 1;
}

void *gk_cm_loop(void *arg) {
	long time, delta;
	fd_set readfds;
	struct timeval tv;
	int ret, pcap_fd = gk_cm_fd();

	if (pcap_fd == -1)
		return NULL;

	while (((struct gk_cm_stat *)arg)->running) {
		pthread_mutex_lock(&mutex_conn);
		time = gk_cm_conn_step();
		((struct gk_cm_stat *)arg)->context_add = 0;
		pthread_mutex_unlock(&mutex_conn);
		if (time == -1)
			delta = 1000;
		else
			delta = time - gettime();

		while (((struct gk_cm_stat *)arg)->context_add == 0) {
			if (delta <= 0)
				break;
			tv.tv_sec = delta / 1000;
			tv.tv_usec = 1000 * ((delta + 999) % 1000);
			FD_ZERO(&readfds);
			FD_SET(pcap_fd, &readfds);
			if ((ret = select(pcap_fd + 1, &readfds, NULL, NULL, &tv)) == 1)
				gk_cm_read_cap();
			delta = time - gettime();
		}
	}
	return NULL;
}

void gk_cm_run() {
	cm_status.running = 1;
	pthread_create(&gk_cm_bg, NULL, gk_cm_loop, &cm_status);
}

char match_type(char *url, int len) {
	char *content = malloc(len + HH_ADD_LEN);
	char result1, result2;
	if (content == NULL) {
		perror("match_type");
		return -1;
	}

	memcpy(content, "GET http://", HH_PRE_LEN);
	memcpy(content + HH_PRE_LEN, url, len);
	memcpy(content + HH_PRE_LEN + len, " HTTP/1.1\r\n\r\n", HH_PST_LEN);

	sem_t sem;
	sem_init(&sem, 0, 0);
	gk_add_context(content, len + HH_ADD_LEN, &result2, HK_TYPE2, release_single_query, &sem);
	sem_wait(&sem);
	if (result2 & HK_TYPE1)
		result1 = HK_TYPE1;
	else {
		content[len + HH_ADD_LEN - 4] = '\n';
		gk_add_context(content, len + HH_ADD_LEN - 2, &result1, HK_TYPE1, release_single_query, &sem);
		sem_wait(&sem);
	}
	free(content);
	sem_destroy(&sem);

	return result1 | result2;
}

struct count_and_sem {
	int c;
	sem_t sem;
};

void release_grouped_query(char *content, char result, void *arg) {
	if (--(((struct count_and_sem *)arg)->c) == 0)
		sem_post(&((struct count_and_sem *)arg)->sem);
}

void find_single(char *url, int len) {
	char hit;
	int i;
	char *result1 = NULL, *result2 = NULL, *content;
	struct count_and_sem a;

	hit = match_type(url, len);
	if (hit == -1) {
		perror("find_single");
		inthandler(0);
	}

	a.c = 0;
	if (hit & HK_TYPE1) {
		result1 = malloc(len);
		if (result1 == NULL)
			goto no_mem;
		a.c += len;
	}
	if (hit & HK_TYPE2) {
		result2 = malloc(len);
		if (result2 == NULL)
			goto no_mem;
		a.c += len;
	}

	if (hit == 0) {
		printf("no keyword found\n");
		return;
	}

	sem_init(&a.sem, 0, 0);
	if (hit & HK_TYPE1) {
		for (i = 0; i < len; ++i) {
			content = malloc(len + (HH_ADD_LEN - 1));
			if (content == NULL)
				goto no_mem;
			memcpy(content, "GET http://", HH_PRE_LEN);
			memcpy(content + HH_PRE_LEN, url, i);
			memcpy(content + HH_PRE_LEN + i, url + i + 1, len - i - 1);
			memcpy(content + HH_PRE_LEN + len - 1, " HTTP/1.1\n\n", HH_PST_LEN - 2);
			gk_add_context(content, len + HH_ADD_LEN - 3, result1 + i, HK_TYPE1, release_grouped_query, &a);
		}
	}
	if (hit & HK_TYPE2) {
		for (i = 0; i < len; ++i) {
			content = malloc(len + (HH_ADD_LEN - 1));
			if (content == NULL)
				goto no_mem;
			memcpy(content, "GET http://", HH_PRE_LEN);
			memcpy(content + HH_PRE_LEN, url, i);
			memcpy(content + HH_PRE_LEN + i, url + i + 1, len - i - 1);
			memcpy(content + HH_PRE_LEN + len - 1, " HTTP/1.1\r\n\r\n", HH_PST_LEN);
			gk_add_context(content, len + HH_ADD_LEN - 1, result2 + i, HK_TYPE2, release_grouped_query, &a);
		}
	}

	sem_wait(&a.sem);
	sem_destroy(&a.sem);

	if (hit & HK_TYPE1) {
		for (i = 0; i < len; ++i)
			if ((result1[i] & HK_TYPE1) == 0)
				result1[i] = url[i];
			else
				result1[i] = 0;
		fputs("type1 keyword: ", stdout);
		for (i = 0; i < len && result1[i] == 0; ++i);
		while (i < len) {
			if (result1[i])
				putchar(result1[i]);
			else {
				do {
					++i;
				} while (i < len && result1[i] == 0);
				if (i < len)
					printf(" && %c", result1[i]);
			}
			++i;
		}
		putchar('\n');
		free(result1);
	}
	if (hit & HK_TYPE2) {
		for (i = 0; i < len; ++i)
			if ((result2[i] & HK_TYPE2) == 0)
				result2[i] = url[i];
			else
				result2[i] = 0;
		fputs("type2 keyword: ", stdout);
		for (i = 0; i < len && result2[i] == 0; ++i);
		while (i < len) {
			if (result2[i])
				putchar(result2[i]);
			else {
				do {
					++i;
				} while (i < len && result2[i] == 0);
				if (i < len)
					printf(" && %c", result2[i]);
			}
			++i;
		}
		putchar('\n');
		free(result2);
	}

	return;
no_mem:
	perror("find_single");
	free(result1);
	free(result2);
	inthandler(0);
}

void find_multisimple(char *url, int len) {
}

void find_multiple(char *url, int len) {
}

int main(int argc, char *argv[]) {
	int opt;

	while ((opt = getopt(argc, argv, "i:s:f:h")) != -1) {
		switch (opt) {
		case 'i':
		case 's':
			break;
		case 'f':
			strncpy(config_file, optarg, 1000);
			if (config_file[999]) {
				fputs("config_file name too long\n", stderr);
				return 1;
			}
			break;
		case 'h':
		default:
			printf("USAGE: \n"
			       "# %s [OPTIONS]\n"
			       "  -i <device>	   : network interface used for sending and receiving.\n"
			       "  -f <config_file> : configuration file name.\n"
			       "  -s <ip addr>	   : the source ip address of the current machine.\n", argv[0]);
			return 0;
		}
	}

	fprintf(stderr,
		"[COMMAND SYNTAX]\n"
		"LINE	  = [MODE \" \"] URL | MODE | \" \" GK_OPTS\n"
		"MODE	  = \"s\" | \"ms\" | \"m\"\n"
		"	   # s means single keyword\n"
		"	   # ms means multiple simple keywords\n"
		"	   # m means mutliple keywords\n%s", GK_OPT_SYNTAX);


	if (signal(SIGINT, inthandler) == SIG_ERR) {
		perror("signal");
		return -1;
	}
	if (signal(SIGTERM, inthandler) == SIG_ERR) {
		perror("signal");
		return -1;
	}
	if (signal(SIGHUP, SIG_IGN) == SIG_ERR) {
		perror("signal");
		return -1;
	}

	if (gk_read_config_file(config_file, device, ip, &maxconn, &maxdst, candlist, &times, &time_interval, &expire_timeout, &tcp_mss, &kps, &pps))
		fprintf(stderr, "warning: configuration file %s doesn't exist.\n", config_file);
	else
		gk_cm_config(times, time_interval, expire_timeout, tcp_mss, kps, pps);

	optind = 1;
	while ((opt = getopt(argc, argv, "i:s:f:h")) != -1) {
		switch (opt) {
		case 'i':
			strncpy(device, optarg, 100);
			if (device[99]) {
				fputs("device name too long\n", stderr);
				return 1;
			}
			break;
		case 's':
			strncpy(ip, optarg, 100);
			if (ip[99]) {
				fputs("IP too long\n", stderr);
				return 1;
			}
			break;
		}
	}

	if ((dest = new_dstlist(maxdst)) == NULL) {
		fputs("new_dstlist: memory allocation failed.\n", stderr);
		return -1;
	}
	if (candlist[0] == '\0') {
		fputs("critical: no dstlist specified.\n", stderr);
		return -1;
	}
	cand = new_candlist(candlist, &cand_count);
	if (cand == NULL) {
		free_dstlist(dest);
		fputs("new_candlist: format error\n", stderr);
		return -1;
	}
	if (init_dstlist(dest, cand, cand_count) != 0) {
		free_dstlist(dest);
		free(cand);
		fputs("dstlist initialize failed.\n", stderr);
		return -1;
	}
	if (gk_cm_init(device, ip, dest, 0)) {
		free_dstlist(dest);
		free(cand);
		fputs("gk_cm_init: failed.\n", stderr);
		return -1;
	}
	if (pthread_mutex_init(&mutex_conn, NULL)) {
		free_dstlist(dest);
		free(cand);
		perror("pthread_mutex_init");
		return -1;
	}
	gk_cm_run();

#define LINE_LEN 10000
	char line[LINE_LEN];
	line[LINE_LEN - 1] = 1;
	int url_len;
	while (fgets(line, LINE_LEN, stdin)) {
		if (line[LINE_LEN - 1] == 0 && line[LINE_LEN - 2] != '\n') {
			fputs("line too long\n", stderr);
			continue;
		}

		if (line[0] == ' ') {
			gk_read_config(line + 1, device, ip, &maxconn, &maxdst, candlist, &times, &time_interval, &expire_timeout, &tcp_mss, &kps, &pps);
			gk_cm_config(times, time_interval, expire_timeout, tcp_mss, kps, pps);
		}
		else {
			offset = 1;
			if (line[0] == 'm')
				if (line[1] == 's') {
					offset = 2;
					local_mode = 2;
				}
				else
					local_mode = 2;
			else if (line[0] == 's')
				local_mode = 1;
			else {
				offset = 0;
				local_mode = 0;
			}
			if (line[offset] != ' ' || line[offset] != '\t' || line[offset] != '\0') {
				local_mode = mode;
				offset = 0;
			}
			else {
				while (line[offset] == ' ' || line[offset] == '\t')
					++offset;
				if (line[offset] == '\0') {
					mode = local_mode;
					continue;
				}
			}

			url_len = strlen(line + offset);
			if (line[offset + url_len - 1] == '\n')
				--url_len;
			switch (local_mode) {
			case 1:
				find_single(line + offset, url_len);
				break;
			case 2:
				find_multisimple(line + offset, url_len);
				break;
			case 3:
				find_multiple(line + offset, url_len);
				break;
			}
		}
	}

	quit();
	return 0;
}

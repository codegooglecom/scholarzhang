#define MAX_URLLEN 2000

#include "gfwkeyword.h"
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

char device[100], ip[100];
char config_file[1000] = "/etc/gfwkeyword.conf";
char candlist[1000];
struct port_range *cand;
int cand_count;
int maxconn, maxdst;
int control_wait, times, time_interval, expire_timeout, tcp_mss, pps;
double kps;
struct dstlist *dest;

static inline void quit() {
	free_dstlist(dest);
	free(cand);
	connmanager_finalize();
}

void inthandler (int _) {
	(void)_;
	connmanager_abort();
	quit();
	exit(-2);
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
			       "  -i <device>      : network interface used for sending and receiving.\n"
			       "  -f <config_file> : configuration file name.\n"
			       "  -s <ip addr>     : the source ip address of the current machine.\n", argv[0]);
			return 0;
		}
	}

	fprintf(stderr,
		"[COMMAND SYNTAX]\n"
		"LINE     = [MODE \" \"] URL | MODE | \" \" GK_OPTS\n"
		"MODE     = \"s\" | \"ms\" | \"m\"\n"
		"          # s means single keyword\n"
		"          # ms means multiple simple keywords\n"
		"          # m means mutliple keywords\n%s", GK_OPT_SYNTAX);


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

	if (gk_read_config_file(config_file, device, ip, &maxconn, &maxdst, candlist, &control_wait, &times, &time_interval, &expire_timeout, &tcp_mss, &kps, &pps))
		fprintf(stderr, "warning: configuration file %s doesn't exist.\n", config_file);

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
	if (connmanager_init(device, ip, dest, 0)) {
		free_dstlist(dest);
		fputs("connmanager_init: failed.\n", stderr);
		return -1;
	}
	connmanager_run();

#define LINE_LEN 10000
	char line[LINE_LEN];
	line[LINE_LEN - 1] = 1;
	while (fgets(line, LINE_LEN, stdin)) {
		if (line[LINE_LEN - 1] == 0 && line[LINE_LEN - 2] != '\n') {
			fputs("line too long\n", stderr);
			continue;
		}

		if (line[0] == ' ') {
			if (line[1] == 'q')
				break;
			gk_read_config(line + 1, device, ip, &maxconn, &maxdst, candlist, &control_wait, &times, &time_interval, &expire_timeout, &tcp_mss, &kps, &pps);
			connmanager_config(control_wait, times, time_interval, expire_timeout, tcp_mss, kps, pps);
		}
		else {
			/* !!!! */
		}
	}

	quit();
	return 0;
}

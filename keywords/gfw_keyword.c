#include "gfw_keyword.h"
#include <stdio.h>
#include <string.h>

void keyword_read_config(char *line, char *device, char *ip, int *maxconn, int *maxdst, int *control_wait, int *times, int *time_interval, int *expire_timeout, int *tcp_mss, int *kps, int *pps) {
	char par[20];
	while (sscanf(line, "%s", par)) {
		if (strcmp(par, "i") == 0 || strcmp(par, "device") == 0)
			sscanf(line, "%s", device);
		if (strcmp(par, "s") == 0)
			sscanf(line, "%s", ip);
		if (strcmp(par, "maxconn") == 0)
			sscanf(line, "%d", maxconn);
		if (strcmp(par, "maxdst") == 0)
			sscanf(line, "%d", maxdst);
		if (strcmp(par, "w") == 0)
			sscanf(line, "%d", control_wait);
		if (strcmp(par, "x") == 0)
			sscanf(line, "%d", times);
		if (strcmp(par, "t") == 0 || strcmp(par, "interval") == 0)
			sscanf(line, "%d", time_interval);
		if (strcmp(par, "e") == 0 || strcmp(par, "expire") == 0)
			sscanf(line, "%d", expire_timeout);
		if (strcmp(par, "S") == 0 || strcmp(par, "seg") == 0)
			sscanf(line, "%d", tcp_mss);
		if (strcmp(par, "kps") == 0)
			sscanf(line, "%d", kps);
		if (strcmp(par, "pps") == 0)
			sscanf(line, "%d", pps);
	}
}

int keyword_read_config_file(char *file, char *device, char *ip, int *maxconn, int *maxdst, int *control_wait, int *times, int *time_interval, int *expire_timeout, int *tcp_mss, int *kps, int *pps) {
	FILE *fp = fopen(file, "r");
	if (fp == NULL) {
		perror("keyword_read_config");
		return -1;
	}

#define LINE_LEN 1000
	char line[LINE_LEN];
	int i;

	line[LINE_LEN - 1] = 1;
	for (i = 1; fgets(line, 1000, fp); ++i) {
		if (line[LINE_LEN - 1] == 0 && line[LINE_LEN - 2] != '\n')
			fprintf(stderr, "keyword_read_config: line #%d too long\n", i);
		if (line[0] == '#')
			continue;
		keyword_read_config(line+1, device, ip, maxconn, maxdst, control_wait, times, time_interval, expire_timeout, tcp_mss, kps, pps);
	}

	if (*maxdst == 0)
		*maxdst = DEFAULT_DST;

	return 0;
}

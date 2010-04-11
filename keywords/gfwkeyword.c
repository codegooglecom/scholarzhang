#include "gfwkeyword.h"
#include <stdio.h>
#include <string.h>

char GK_OPT_SYNTAX[] =
        "GK_OPTS = OPTION [GK_OPTS]\n"
        "OPTION  = (\"i\" | \"device\") DEVICE\n"
        "        | \"s\" IP\n"
        "        | \"maxconn\" INTEGER\n"
        "        | \"maxdst\" INTEGER\n"
        "        | (\"d\" | \"dstlist\") DSTLIST\n"
        "        | \"x\" INTEGER # repeat times of each packet\n"
        "        | (\"t\" | \"interval\") INTEGER\n"
        "          # sleeping time between two packet in a single\n"
        "          # tcp session (uint in ms)\n"
        "        | (\"e\" | \"expire\") INTEGER # expire timeout of a tcp session\n"
        "        | (\"S\" | \"seg\") INTEGER # TCP_MSS(equals to MTU minus 40\n"
        "                                # normally), default is set to 1300\n"
        "        | \"kps\" DOUBLE  # speed limit in KB/s\n"
        "        | \"pps\" INTEGER # speed limit in packets/second\n"
        "                        # only one of these is accepted\n"
        "DSTLIST = DSTITEM [\",\" DSTLIST]\n"
        "DSTITEM = IP[\"-\"IP]:PORT[-PORT]\n";

void gk_read_config(char *line, char *device, char *ip, int *maxconn, int *maxdst, char *candlist, char *times, int *time_interval, int *expire_timeout, int *tcp_mss, double *kps, int *pps) {
#define PAR_LEN 20
	char par[PAR_LEN];
	int status, j;
	char *p, *q;

#define SKIP_SPACE while (*p == ' ' || *p == '\t') ++p
	p = line; status = 0;
	SKIP_SPACE;
	while (*p) {
		for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
			par[j] = *p;
		par[j] = '\0';
		SKIP_SPACE;
		if (*p == '\0')
			fputs("gk_read_config: syntax error.\n", stderr);
		if (strcmp(par, "i") == 0 || strcmp(par, "device") == 0) {
			for (j = 0; *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				device[j] = *p;
			device[j] = '\0';
		}
		else if (strcmp(par, "s") == 0) {
			for (j = 0; *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				ip[j] = *p;
			ip[j] = '\0';
		}
		else if (strcmp(par, "maxconn") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*maxconn = atoi(par);
		}
		else if (strcmp(par, "maxdst") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*maxdst = atoi(par);
		}
		else if (strcmp(par, "d") == 0 || strcmp(par, "dstlist") == 0) {
			while (1) {
				for (j = 0; *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
					candlist[j] = *p;
				if (candlist[j - 1] == ',')
					candlist[j] = '\0';
				else
					break;
			}
		}
		else if (strcmp(par, "x") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*times = atoi(par);
		}
		else if (strcmp(par, "t") == 0 || strcmp(par, "interval") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*time_interval = atoi(par);
		}
		else if (strcmp(par, "e") == 0 || strcmp(par, "expire") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*expire_timeout = atoi(par);
		}
		else if (strcmp(par, "S") == 0 || strcmp(par, "seg") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*tcp_mss = atoi(par);
		}
		else if (strcmp(par, "kps") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*kps = strtod(par, &q);
		}
		else if (strcmp(par, "pps") == 0) {
			for (j = 0; j < (PAR_LEN - 1) && *p != '\0' && *p != '\t' && *p != ' '; ++j, ++p)
				par[j] = *p;
			par[j] = '\0';
			*pps = atoi(par);
		}
		else
			fprintf(stderr, "unrecognized parameter: %s.\n", par);
		SKIP_SPACE;
	}
#undef PAR_LEN
}

int gk_read_config_file(char *file, char *device, char *ip, int *maxconn, int *maxdst, char *candlist, char *times, int *time_interval, int *expire_timeout, int *tcp_mss, double *kps, int *pps) {
	FILE *fp = fopen(file, "r");
	if (fp == NULL) {
		perror("gk_read_config");
		return -1;
	}

#define LINE_LEN 10000
	char line[LINE_LEN];
	int i;

	line[LINE_LEN - 1] = 1;
	for (i = 1; fgets(line, 1000, fp); ++i) {
		if (line[LINE_LEN - 1] == 0 && line[LINE_LEN - 2] != '\n') {
			fprintf(stderr, "gk_read_config: line #%d too long\n", i);
			continue;
		}
		if (line[0] == '#')
			continue;
		gk_read_config(line, device, ip, maxconn, maxdst, candlist, times, time_interval, expire_timeout, tcp_mss, kps, pps);
	}

	if (*maxdst == 0)
		*maxdst = DEFAULT_DST;

#undef LINE_LEN
	return 0;
}

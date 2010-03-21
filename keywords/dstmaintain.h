#ifndef _DSTMAINTAIN_H_
#define _DSTMAINTAIN_H_

#include <sys/time.h>

long gettime();
#define DAY_NS 86400000
extern inline long gettime() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec % DAY_s) * 1000 + tv.tv_usec / 1000;
}

#define DEFAULT_DST 500000

struct port_range {
	uint32_t addr;
	uint16_t portL, portR;
};

struct dstinfo;
struct idle_t;

struct dstinfo {
	uint32_t da;
	uint16_t dport;
	char used, type;
	int pos_type1, pos_type2;
	/* pos here is the index of this dst in heap typeX + 1 (index
	   count starts from 0) */
};

struct dstlist {
	int capacity;
	struct dstinfo *head;
	struct dstinfo *data;
	int count_type1, count_type2; // number of members in idle_
	struct idle_t *idle_type1, *idle_type2;
	int cand_count;
	struct port_range *candidates;
	int removed_type1, removed_type2;
};

struct dstlist *new_dstlist(const int capacity);
void free_dstlist(const struct dstlist *const list);
int init_dstlist(struct dstlist *const list, struct port_range *cand, int count);
void dstlist_delete( struct dstlist *const list, dstinfo *const dst );

void supply_type1(struct dstlist *const list);
void supply_type2(struct dstlist *const list);
struct dstinfo *get_type1(struct dstlist *const list);
struct dstinfo *get_type2(struct dstlist *const list);

extern inline void dstlist_delete( struct dstlist *const list, dstinfo *const dst ) {
	*(dstinfo **)dst = list->head;
	list->head = dst;
}

#endif /* _DSTMAINTAIN_H_ */

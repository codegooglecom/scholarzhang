#include "dstmaintain.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

long gettime() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000;
}

struct idle_t {
	long time;
	dstinfo *dst;
};

/* idle_t maintenance */

static inline void type1_lift( idle_t *const hsub, int p ) {
	/* hsub == heap - 1, *(hsub + p) is the operated object */
	idle_t orig;

	if (p > 1) {
		int n = p >> 1;
		if ( (hsub + p)->time - (hsub + n)->time > 0 )
			return;
		memcpy(&orig, hsub + p, sizeof(struct idle_t));
		do {
			if ( (hsub + n)->time - orig.time > 0 ) {
				memcpy(hsub + p, hsub + n, sizeof(struct idle_t));
				(hsub + p)->dst->pos_type1 = p;
				p = n;
				n = p >> 1;
			}
			else
				break;
		} while (n != 0);
		memcpy(hsub + p, &orig, sizeof(struct idle_t));
		(hsub + p)->dst->pos_type1 = p;
	}
}

static inline void type1_sink( idle_t *const hsub, int p, const int size ) {
	/* hsub == heap - 1, *(hsub + p) is the operated object */
	int min;
	idle_t orig;

	if ((min = p << 1) <= size) {
		if ( (hsub + min)->time - (hsub + (min + 1))->time > 0 )
			++min;
	}
	else
		++min;
	if ( (hsub + p)->time - (hsub + min)->time > 0 ) {
		memcpy(&orig, hsub + p, sizeof(struct idle_t));
		do {
			memcpy(hsub + p, hsub + min, sizeof(struct idle_t));
			(hsub + p)->dst->pos_type1 = p;
			p = min;
			if ((min = p << 1) <= size) {
				if ( (hsub + min)->time - (hsub + (min + 1))->time
				     > 0 )
					++min;
			}
			else
				++min;
		} while ( orig.time - (hsub + min)->time > 0 );
		memcpy(hsub + p, &orig, sizeof(struct idle_t));
		(hsub + p)->dst->pos_type1 = p;
	}
}

static inline void init_type1( struct dstlist *const list ) {
	int i;
	for ( i = list->count_type1 / 2; i > 0; --i )
		type1_sink(list->idle_type1 - 1, i, list->count_type1);
}

static inline void type1_delmin( idle_t *const heap, int *const size ) {
//	heap->dst->pos_type1 = 0; // not necessary
	memcpy( heap, heap + (--*size), sizeof(struct idle_t) );
	type1_sink( heap - 1, 1, size);
}

static inline void type1_insert( idle_t *const heap, const long time,
				 const void *const dst, int *const size ) {
	(heap + *size)->time = time;
	(heap + *size)->dst = dst;
	type1_lift( heap - 1, ++(*size) );
}

static inline void type1_delete( idle_t *const heap, const int p,
				 int *const size ) {
//	(heap + p)->dst->pos_type1 = 0; // not necessary
	memcpy( heap + p, heap + (--*size), sizeof(struct idle_t) );
	type1_lift( heap - 1, p + 1 );
	type1_sink( heap - 1, p + 1, size );
}

static inline void type2_lift( idle_t *const hsub, int p ) {
	/* hsub == heap + 1, *(hsub - p) is the operated object */
	idle_t orig;

	if (p > 1) {
		int n = p >> 1;
		if ( (hsub - p)->time - (hsub - n)->time > 0 )
			return;
		memcpy(&orig, hsub - p, sizeof(struct idle_t));
		do {
			if ( (hsub - n)->time - orig.time > 0 ) {
				memcpy(hsub - p, hsub - n, sizeof(struct idle_t));
				(hsub - p)->dst->pos_type2 = p;
				p = n;
				n = p >> 1;
			}
			else
				break;
		} while (n != 0);
		memcpy(hsub - p, &orig, sizeof(struct idle_t));
		(hsub - p)->dst->pos_type2 = p;
	}
}

static inline void type2_sink( idle_t *const hsub, int p, const int size ) {
	/* hsub == heap + 1, *(hsub - p) is the operated object */
	int min;
	idle_t orig;

	if ((min = p << 1) <= size) {
		if ( (hsub - min)->time - (hsub - (min + 1))->time > 0 )
			++min;
	}
	else
		++min;
	if ( (hsub - p)->time - (hsub - min)->time > 0 ) {
		memcpy(&orig, hsub - p, sizeof(struct idle_t));
		do {
			memcpy(hsub - p, hsub - min, sizeof(struct idle_t));
			(hsub - p)->dst->pos_type2 = p;
			p = min;
			if ((min = p << 1) <= size) {
				if ( (hsub - min)->time - (hsub - (min + 1))->time
				     > 0 )
					++min;
			}
			else
				++min;
		} while ( orig.time - (hsub - min)->time > 0 );
		memcpy(hsub - p, &orig, sizeof(struct idle_t));
		(hsub - p)->dst->pos_type2 = p;
	}
}

static inline void init_type2( struct dstlist *const list ) {
	int i;
	for ( i = list->count_type2 / 2; i > 0; --i )
		type2_sink(list->idle_type2 + 1, i, list->count_type2);
}

static inline void type2_delmin( idle_t *const heap, int *const size ) {
//	heap->dst->pos_type2 = 0; // not necessary
	memcpy( heap, heap - (--*size), sizeof(struct idle_t) );
	type2_sink( heap + 1, 1, size);
}

static inline void type2_insert( idle_t *const heap, const long time,
				 const void *const dst, int *const size ) {
	(heap - *size)->time = time;
	(heap - *size)->dst = dst;
	type2_lift( heap + 1, ++(*size) );
}

static inline void type2_delete( idle_t *const heap, const int p,
				 int *const size ) {
//	(heap - p)->dst->pos_type2 = 0; // not necessary
	memcpy( heap - p, heap - (--*size), sizeof(struct idle_t) );
	type2_lift( heap + 1, p + 1 );
	type2_sink( heap + 1, p + 1, size );
}

/* dstlist maintenance */
struct dstlist *new_dstlist(const int capacity) {
	struct dstlist *list;

	list = malloc(sizeof(dstlist));
	if (list) {
		list->capacity = capacity;
		list->dst = malloc(2 * capacity * sizeof(struct dstinfo));
		if (list->dst == NULL) {
			free(list);
			return NULL;
		}
		list->idle_type1 = malloc(3 * capacity * sizeof(struct idle_t));
		if (list->idle_type1 == NULL) {
			free(list->dst);
			free(list);
			return NULL;
		}
		list->idle_type2 = list->idle_type1 + 3 * capacity - 1;
	}
	return list;
}

void free_dstlist(const struct dstlist *const list) {
	free(list->candidates);
	free(list->dst);
	free(list->idle_type1);
	free(list);
}

static inline void empty_dstlist(struct dstlist *const list) {
	register struct dstinfo *last;

	list->head = list->dst + 2 * list->capacity - 1;
	*(struct dstinfo **)(list->head) = NULL;
	while (list->head >= list->dst) {
		last = list->head;
		*(struct dstinfo **)(list->head = last - 1) = last;
	}
	list->count_type1 = 0;
	list->count_type2 = 0;
}

static inline void fill_dstlist_without_maintain_heap(struct dstlist *const list,
					       const int n) {
	int i;
	if ( (i = list->cand_count - 1) < 0 )
		return;

	int j, k, l;
	long inittime = gettime();
	struct dstinfo *newdst;
	idle_t *idle;

	do {
		k = list->candidates[i].addr;
		l = list->candidates[i].portL;
		for ( j = list->candidates[i].portR; j >= l; --j ) {
			newdst = list->head;
			list->head = *(struct dstinfo **)(list->head);
			newdst->da = k;
			newdst->sa = source_addr;
			newdst->used = 0;
			newdst->dport = j;
			newdst->type = (HK_TYPE1 | HK_TYPE2);

			idle = list->idle_type1 + list->count_type1;
			idle->dst = newdst;
			idle->time = inittime;
			++list->count_type1;
			idle = list->idle_type2 - list->count_type2;
			idle->dst = newdst;
			idle->time = inittime;
			++list->count_type2;

			newdst->pos_type1 = list->count_type1;
			newdst->pos_type2 = list->count_type2;

			if (--n == 0) {
				if (j == l)
					list->cand_count = i;
				else  {
					list->cand_count = i + 1;
					list->candidates[i].portR = j - 1;
				}
				return;
			}
		}
		--i;
	} while (i >= 0);
	removed_type1 = capacity - list->count_type1;
	removed_type2 = capacity - list->count_type2;
}

int init_dstlist(struct dstlist *const list, struct port_range *cand, int count) {
	int i;
	if ((list->candidates = malloc(cand_count * sizeof(struct port_range))) == NULL) {
		perror("init_dstlist");
		return -1;
	}
	memcpy(list->candidates, cand, cand_count * sizeof(struct port_range));
	list->cand_count = count;

	empty_dstlist(list);
	fill_dstlist_without_maintain_heap(list, list->capacity);
	init_type1(list);
	init_type2(list);
	return 0;
}

inline void dstlist_delete( struct dstlist *const list, dstinfo *const dst ) {
	*(dstinfo **)dst = list->head;
	list->head = dst;
}

inline void supply_type1(struct dstlist *const list) {
	int k = list->capacity - list->removed_type1;

	if ( k < list->removed_type1 && cand_count > 0 ) {
		fill_dstlist_without_maintain_heap(list, k);
		init_type1(list);
		init_type2(list);
	}
}

inline void supply_type2(struct dstlist *const list) {
	int k = list->capacity - list->removed_type2;

	if ( k < list->removed_type2 && cand_count > 0 ) {
		fill_dstlist_without_maintain_heap(list, k);
		init_type1(list);
		init_type2(list);
	}
}

inline struct dstinfo *get_type1(struct dstlist *const list) {
	idle_t *idle = list->idle_type1;

	if (list->count_type1 == 0)
		return NULL;
	long time = idle->dst->time - gettime();
	if (time > 0) {
		sleep(time / 1000);
		usleep(1000 * (time % 1000));
	}
	type1_delmin( idle, &list->count_type1 );
	(list->idle_type2 - (idle->dst->pos_type2 - 1))->time += DAY_NS;
	type2_sink( list->idle_type2 + 1, idle->dst->pos_type2 );

	return idle->dst;
}

inline struct dstinfo *get_type2(struct dstlist *const list) {
	idle_t *idle = list->idle_type2;

	if (list->count_type1 == 0)
		return NULL;
	long time = idle->dst->time - gettime();
	if (time > 0) {
		sleep(time / 1000);
		usleep(1000 * (time % 1000));
	}
	type2_delmin( idle, &list->count_type2 );
	(list->idle_type1 + (idle->dst->pos_type1 - 1))->time += DAY_NS;
	type1_sink( list->idle_type1 - 1, idle->dst->pos_type1 );

	return idle->dst;
}

#include "dstmaintain.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

long gettime() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000;
}

/* idle_t maintenance */

inline void type1_lift(struct idle_t *const hsub, int p) {
	/* hsub == heap - 1, *(hsub + p) is the operated object */
	struct idle_t orig;

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

inline void type1_sink(struct idle_t *const hsub, int p, const int size) {
	/* hsub == heap - 1, *(hsub + p) is the operated object */
	int min;
	struct idle_t orig;

	if ((min = p << 1) < size) {
		if ( (hsub + min)->time - (hsub + (min + 1))->time > 0 )
			++min;
	}
	if (min > size)
		return;
	if ( (hsub + p)->time - (hsub + min)->time > 0 ) {
		memcpy(&orig, hsub + p, sizeof(struct idle_t));
		do {
			memcpy(hsub + p, hsub + min, sizeof(struct idle_t));
			(hsub + p)->dst->pos_type1 = p;
			p = min;
			if ((min = p << 1) < size) {
				if ( (hsub + min)->time - (hsub + (min + 1))->time
				     > 0 )
					++min;
			}
			if (min > size)
				break;
		} while ( orig.time - (hsub + min)->time > 0 );
		memcpy(hsub + p, &orig, sizeof(struct idle_t));
		(hsub + p)->dst->pos_type1 = p;
	}
}

inline void init_type1( struct dstlist *const list) {
	int i;
	for ( i = list->count_type1 / 2; i > 0; --i )
		type1_sink(list->idle_type1 - 1, i, list->count_type1);
}

inline void type1_delmin(struct idle_t *const heap, int *const size ) {
//	heap->dst->pos_type1 = 0; // not necessary
	memcpy( heap, heap + (--*size), sizeof(struct idle_t) );
	type1_sink( heap - 1, 1, *size);
}

inline void type1_insert(struct idle_t *const heap, const long time,
			 void *const dst, int *const size ) {
	(heap + *size)->time = time;
	(heap + *size)->dst = dst;
	type1_lift( heap - 1, ++(*size) );
}

inline void type1_delete(struct idle_t *const heap, const int p,
			 int *const size) {
//	(heap + p)->dst->pos_type1 = 0; // not necessary
	memcpy( heap + p, heap + (--*size), sizeof(struct idle_t) );
	type1_lift( heap - 1, p + 1 );
	type1_sink( heap - 1, p + 1, *size );
}

inline void type2_lift(struct idle_t *const hsub, int p) {
	/* hsub == heap + 1, *(hsub - p) is the operated object */
	struct idle_t orig;

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

inline void type2_sink(struct idle_t *const hsub, int p, const int size) {
	/* hsub == heap + 1, *(hsub - p) is the operated object */
	int min;
	struct idle_t orig;

	if ((min = p << 1) < size) {
		if ( (hsub - min)->time - (hsub - (min + 1))->time > 0 )
			++min;
	}
	if (min > size)
		return;
	if ( (hsub - p)->time - (hsub - min)->time > 0 ) {
		memcpy(&orig, hsub - p, sizeof(struct idle_t));
		do {
			memcpy(hsub - p, hsub - min, sizeof(struct idle_t));
			(hsub - p)->dst->pos_type2 = p;
			p = min;
			if ((min = p << 1) < size) {
				if ( (hsub - min)->time - (hsub - (min + 1))->time
				     > 0 )
					++min;
			}
			if (min > size)
				break;
		} while ( orig.time - (hsub - min)->time > 0 );
		memcpy(hsub - p, &orig, sizeof(struct idle_t));
		(hsub - p)->dst->pos_type2 = p;
	}
}

inline void init_type2( struct dstlist *const list) {
	int i;
	for ( i = list->count_type2 / 2; i > 0; --i )
		type2_sink(list->idle_type2 + 1, i, list->count_type2);
}

inline void type2_delmin(struct idle_t *const heap, int *const size) {
//	heap->dst->pos_type2 = 0; // not necessary
	memcpy( heap, heap - (--*size), sizeof(struct idle_t) );
	type2_sink( heap + 1, 1, *size);
}

inline void type2_insert(struct idle_t *const heap, const long time,
			 void *const dst, int *const size) {
	(heap - *size)->time = time;
	(heap - *size)->dst = dst;
	type2_lift( heap + 1, ++(*size) );
}

inline void type2_delete(struct idle_t *const heap, const int p,
			 int *const size) {
//	(heap - p)->dst->pos_type2 = 0; // not necessary
	memcpy( heap - p, heap - (--*size), sizeof(struct idle_t) );
	type2_lift( heap + 1, p + 1 );
	type2_sink( heap + 1, p + 1, *size );
}

/* port_range */
struct port_range *new_candlist(char *candlist, int *count) {
	struct port_range *cand;
	int status, j;
#define P_LEN 20
	char c[P_LEN];
	char *p, end;

	if ((cand = malloc(MAX_CAND * sizeof(struct port_range))) && c != NULL) {
		*count = 0;
		j = 0;
		for (p = candlist, end = 0; end == 0; ++p)
			switch (*p) {
			case ':':
				c[j] = '\0';
				cand[*count].addrR = inet_network(c);
				if ((status & 1) == 0)
					cand[*count].addrL = cand[*count].addrR;
				status = 2;
				j = 0;
				break;
			case '-':
				c[j] = '\0';
				if (status & 2)
					cand[*count].portL = atoi(c);
				else
					cand[*count].addrL = inet_network(c);
				j = 0;
				++status;
				break;
			case ' ':
			case '\t':
				if (status != 3)
					break;
				else
					end = 1;
			case '\0':
				end = 1;
			case ',':
				c[j] = '\0';
				cand[*count].portR = atoi(c);
				if ((status & 1) == 0)
					cand[*count].portL = cand[*count].portR;
				cand[*count].port = cand[*count].portR;
				++(*count);
				j = 0;
				status = 0;
				break;
			default:
				c[j++] = *p;
				if (j == P_LEN)
					goto error;
#undef P_LEN
			}

		if (status != 0)
			goto error;

		struct port_range *p = realloc(cand, *count * sizeof(struct port_range));
		if (p)
			return p;
	}
	else
		perror("new_candlist");
	return cand;
error:
	free(cand);
	*count = 0;
	return NULL;
}

/* dstlist maintenance */
struct dstlist *new_dstlist(int capacity) {
	struct dstlist *list;

	if (capacity == 0)
		capacity = DEFAULT_DST;
	list = malloc(sizeof(struct dstlist));
	if (list) {
		list->capacity = capacity;
		list->data = malloc(2 * capacity * sizeof(struct dstinfo));
		if (list->data == NULL) {
			free(list);
			return NULL;
		}
		list->idle_type1 = malloc(3 * capacity * sizeof(struct idle_t));
		if (list->idle_type1 == NULL) {
			free(list->data);
			free(list);
			return NULL;
		}
		list->idle_type2 = list->idle_type1 + 3 * capacity - 1;
		list->candidates = NULL;
	}
	return list;
}

void free_dstlist(struct dstlist *const list) {
	free(list->data);
	free(list->idle_type1);
	free(list->candidates);
	free(list);
}

inline void empty_dstlist(struct dstlist *const list) {
	register struct dstinfo *last;

	list->head = list->data + 2 * list->capacity - 1;
	*(struct dstinfo **)(list->head) = NULL;
	while (list->head > list->data) {
		last = list->head;
		*(struct dstinfo **)(list->head = last - 1) = last;
	}
	list->count_type1 = 0;
	list->count_type2 = 0;
	list->removed_type1 = list->capacity;
	list->removed_type2 = list->capacity;
}

inline void fill_dstlist_without_maintain_heap(struct dstlist *const list,
					       int n) {
	int i;
	if ( (i = list->cand_count - 1) < 0 )
		return;

	int nn = n;
	int j, l;
	u_int32_t k, m;
	long inittime = gettime();
	struct dstinfo *newdst;
	struct idle_t *idle;

	do {
		m = list->candidates[i].addrL;
		for ( k = list->candidates[i].addrR; k >= m; --k ) {
			l = list->candidates[i].portL;
			for ( j = list->candidates[i].port; j >= l; --j ) {
				newdst = list->head;
				list->head = *(struct dstinfo **)(list->head);
				newdst->da = htonl(k);
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
				
				if (--nn == 0)
					goto out;
			}
		}
		--i;
	} while (i >= 0);
 out:
	if (j < l) {
		if (--k < m)
			--i;
		else {
			list->candidates[i].addrR = k;
			list->candidates[i].port = list->candidates[i].portR;
		}
	}
	else
		list->candidates[i].port = j - 1;
	list->cand_count = i + 1;

	list->removed_type1 -= (n - nn);
	list->removed_type2 -= (n - nn);
}

int init_dstlist(struct dstlist *const list, struct port_range *cand, int count) {
	if ((list->candidates = malloc(count * sizeof(struct port_range))) == NULL) {
		perror("init_dstlist");
		return -1;
	}
	memcpy(list->candidates, cand, count * sizeof(struct port_range));
	list->cand_count = count;

	empty_dstlist(list);
	fill_dstlist_without_maintain_heap(list, list->capacity);
	init_type1(list);
	init_type2(list);
	return 0;
}

inline void dstlist_delete( struct dstlist *const list, struct dstinfo *const dst) {
	*(struct dstinfo **)dst = list->head;
	list->head = dst;
}

inline void supply_type1(struct dstlist *const list) {
	int k = list->capacity - list->removed_type1;

	if ( k < list->removed_type1 && list->cand_count > 0 ) {
		fill_dstlist_without_maintain_heap(list, k);
		init_type1(list);
		init_type2(list);
	}
}

inline void supply_type2(struct dstlist *const list) {
	int k = list->capacity - list->removed_type2;

	if ( k < list->removed_type2 && list->cand_count > 0 ) {
		fill_dstlist_without_maintain_heap(list, k);
		init_type1(list);
		init_type2(list);
	}
}

inline struct dstinfo *get_type1(struct dstlist *const list) {
	struct idle_t *idle = list->idle_type1;

	if (list->count_type1 == 0)
		return NULL;
	long time = idle->time - gettime();
	if (time > 0) {
		sleep(time / 1000);
		usleep(1000 * (time % 1000));
	}
	type1_delmin( idle, &list->count_type1 );
	(list->idle_type2 - (idle->dst->pos_type2 - 1))->time += DAY_NS;
	type2_sink( list->idle_type2 + 1, idle->dst->pos_type2, list->count_type2 );

	return idle->dst;
}

inline struct dstinfo *get_type2(struct dstlist *const list) {
	struct idle_t *idle = list->idle_type2;

	if (list->count_type1 == 0)
		return NULL;
	long time = idle->time - gettime();
	if (time > 0) {
		sleep(time / 1000);
		usleep(1000 * (time % 1000));
	}
	type2_delmin( idle, &list->count_type2 );
	(list->idle_type1 + (idle->dst->pos_type1 - 1))->time += DAY_NS;
	type1_sink( list->idle_type1 - 1, idle->dst->pos_type1, list->count_type1 );

	return idle->dst;
}

#ifndef _HEAP_H_
#define _HEAP_H_

#include <string.h>

struct heap_t {
	long time;
	void *data;
};

static inline void heap_lift( heap_t * const hsub, int p ) {
	/* hsub == heap - 1, *(hsub + p) is the operated object */
	heap_t orig;

	if (p > 1) {
		int n = p >> 1;
		if ( (hsub + p)->time - (hsub + n)->time > 0 )
			return;
		memcpy(&orig, hsub + p, sizeof(struct heap_t));
		do {
			if ( (hsub + n)->time - orig.time > 0 ) {
				memcpy(hsub + p, hsub + n, sizeof(struct heap_t));
				p = n;
				n = p >> 1;
			}
			else
				break;
		} while (n != 0);
		memcpy(hsub + p, &orig, sizeof(struct heap_t));
	}
}

static inline void heap_sink( heap_t * const hsub, int p, const int size ) {
	/* hsub == heap - 1, *(hsub + p) is the operated object */
	int min;
	heap_t orig;

	if ((min = p << 1) <= size) {
		if ( (hsub + min)->time - (hsub + (min + 1))->time > 0 )
			++min;
	}
	else
		++min;
	if ( (hsub + p)->time - (hsub + min)->time > 0 ) {
		memcpy(&orig, hsub + p, sizeof(struct heap_t));
		do {
			memcpy(hsub + p, hsub + min, sizeof(struct heap_t));
			p = min;
			if ((min = p << 1) <= size) {
				if ( (hsub + min)->time - (hsub + (min + 1))->time > 0)
					++min;
			}
			else
				++min;
		} while ( orig.time - (hsub + min)->time > 0 );
		memcpy(hsub + p, &orig, sizeof(struct heap_t));
	}
}

static inline void init_heap( heap_t * const heap, const int size ) {
	int i;
	for ( i = size / 2; i > 0; --i )
		heap_sink(heap - 1, i, size);
}

static inline void heap_delmin( heap_t * const heap, int * const size ) {
	memcpy( heap, heap + (--*size), sizeof(struct heap_t) );
	heap_sink( heap - 1, 1, size);
}

static inline void heap_insert( heap_t * const heap, const long time,
				 const void * const dst, int * const size ) {
	(heap + *size)->time = time;
	(heap + *size)->dst = dst;
	heap_lift( heap - 1, ++(*size) );
}

static inline void heap_delete( heap_t * const heap, const int p,
				 int * const size ) {
	memcpy( heap + p, heap + (--*size), sizeof(struct heap_t) );
	heap_lift( heap - 1, p + 1 );
	heap_sink( heap - 1, p + 1, size );
}

#endif /* _HEAP_H_ */

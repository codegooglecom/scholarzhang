#ifdef _CONNMANAGER_
/* this is part of connmanager.c */

static inline void return_type1(struct dstlist *const list, struct dstinfo *const dst, char status) {
	if ((status & STATUS_TYPE1) == 0) {
		// not usable for GFW type1
		dst->type &= HK_TYPE2;
		++list->removed_type1;
		supply_type1(list);
	}
	else {
		// GFW type1 is hit
		long available = gettime() + GFW_TIMEOUT - expire_timeout;
		type1_insert(list->idle_type1, available, dst, &list->count_type1);
	}

	if (dst->type & HK_TYPE2) {
		if ((status & STATUS_TYPE2) == 0) {
			if (status & STATUS_CHECK) {
				// should remove dst from GFW type2 dstlist
				type2_delete(list->idle_type2, dst->pos_type2 - 1,
					     &list->count_type2);
				dst->type &= HK_TYPE1;
				++list->removed_type2;
				supply_type2(list);
			}
			else {
				/* it's either not hit or not usable, so that
				   we recover its available time */
				(list->idle_type2 - (dst->pos_type2 - 1))->time -= DAY_MS;
				type2_lift(list->idle_type2 + 1, dst->pos_type2);
			}
		}
		else {
			// GFW type2 is hit
			long available = gettime() + GFW_TIMEOUT - expire_timeout;
			(list->idle_type2 - (dst->pos_type2 - 1))->time = available;
			type2_lift(list->idle_type2 + 1, dst->pos_type2);
			/* since after get_type1, the available time of type2
			   is add by one day, so here it is _lift not _sink */
		}
	}

	if (dst->type == 0)
		dstlist_delete(list, dst);
}

static inline void return_type2(struct dstlist *const list, struct dstinfo *const dst, char status) {
	if ((status & STATUS_TYPE2) == 0) {
		// not usable for GFW type2
		dst->type &= HK_TYPE1;
		++list->removed_type2;
		supply_type2(list);
	}
	else {
		// GFW type2 is hit
		long available = gettime() + GFW_TIMEOUT - expire_timeout;
		type2_insert(list->idle_type2, available, dst, &list->count_type2);
	}

	if (dst->type & HK_TYPE1) {
		if ((status & STATUS_TYPE1) == 0) {
			if (status & STATUS_CHECK) {
				// should remove dst from GFW type1 dstlist
				type1_delete(list->idle_type1, dst->pos_type1 - 1,
					     &list->count_type1);
				dst->type &= HK_TYPE2;
				++list->removed_type1;
				supply_type1(list);
			}
			else {
				/* it's either not hit or not usable, so that
				   we recover its available time */
				(list->idle_type1 + (dst->pos_type1 - 1))->time -= DAY_MS;
				type1_lift(list->idle_type1 - 1, dst->pos_type1);
			}
		}
		else {
			// GFW type1 is hit
			long available = gettime() + GFW_TIMEOUT - expire_timeout;
			(list->idle_type1 + (dst->pos_type1 - 1))->time = available;
			type1_lift(list->idle_type1 - 1, dst->pos_type1);
			/* since after get_type2, the available time of type1
			   is add by one day, so here it is _lift not _sink */
		}
	}

	if (dst->type == 0)
		dstlist_delete(list, dst);
}

static inline void return_dst_delete_hash(struct dstlist *const list, struct dstinfo *const dst, char type, char status, struct hash_t **hash) {
	(type == HK_TYPE1)?
		return_type1(list, dst, status):
		return_type2(list, dst, status);
	if (hash)
		hash_delete(hash);
	// mutex_hash is operated outside.
}

#endif /* _CONNMANAGER_ */

#ifdef _CONNMANAGER_
/* this is part of connmanager.c */

struct hash_t;
struct hash_t {
	struct conncontent *conn;
	struct hash_t *next;
	uint32_t da;
	uint16_t dp;
}

static inline uint32_t dst_hash(uint32_t da, uint16_t dp) {
	long long tmp = (da % event_capa);
	tmp = tmp * (dp + tmp) % event_capa;
	return tmp;
}

static inline struct hash_t **hash_insert(uint32_t da, uint16_t dp, struct conncontent *conn) {
	struct hash_t *item = malloc(sizeof(struct hash_t));
	uint32_t key = dst_hash(da, dp);

	if (hash[key])
		hash[key]->conn->hash = &item->next;
	item->da = da;
	item->dp = dp;
	item->conn = conn;
	item->next = hash[key];
	hash[key] = item;
	return hash + key;
}

static inline void hash_delete(struct hash_t **prev) {
	struct hash_t *item = *prev;
	*prev = item->next;
	if (*prev)
		(*prev)->conn->hash = prev;
	free(item);
}

static struct conncontent *hash_match(uint32_t da, uint16_t dp) {
	struct hash_t *item;
	uint32_t key = dst_hash(da, dp);

	for (item = hash[key]; item; item = item->next)
		if (item->da == da && item->dp == dp)
			return item->conn;
	return NULL;
}

#endif /* _CONNMANAGER_ */

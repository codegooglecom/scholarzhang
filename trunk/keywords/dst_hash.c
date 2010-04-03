#ifdef _CONNMANAGER_
/* this is part of connmanager.c */

struct hash_t;
struct hash_t {
	struct conncontent *conn;
	struct hash_t *next;
	u_int32_t da;
	u_int16_t dp;
};

static inline u_int32_t dst_hash(u_int32_t da, u_int16_t dp) {
	long long tmp = (da % event_capa);
	tmp = tmp * (dp + tmp) % event_capa;
	return tmp;
}

static struct hash_t **hash = NULL;

static inline struct hash_t **hash_insert(u_int32_t da, u_int16_t dp, struct conncontent *conn) {
	struct hash_t *item = malloc(sizeof(struct hash_t));
	u_int32_t key = dst_hash(da, dp);

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

static struct conncontent *hash_match(u_int32_t da, u_int16_t dp) {
	struct hash_t *item;
	u_int32_t key = dst_hash(da, dp);

	for (item = hash[key]; item; item = item->next)
		if (item->da == da && item->dp == dp)
			return item->conn;
	return NULL;
}

#endif /* _CONNMANAGER_ */

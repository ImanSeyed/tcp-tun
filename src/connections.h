#ifndef __TCP_TUN_CONNECTIONS_H__
#define __TCP_TUN_CONNECTIONS_H__
#include "types.h"

struct connection {
	struct connection_quad quad;
	enum tcp_state state;
	struct connection *next;
};

struct connections_hashmap {
	struct connection **entries;
};

uint32_t xorshift32(uint32_t x);
uint32_t pair_hash(uint32_t x, uint32_t y);
uint32_t hash_func(struct connection_quad *quad);
struct connection *connections_hashmap_pair(struct connection_quad *key,
					    enum tcp_state *value);
struct connections_hashmap *connections_hashmap_create(void);
void connections_hashmap_set(struct connections_hashmap *hashmap,
			     struct connection_quad *key,
			     enum tcp_state *value);
enum tcp_state *connections_hashmap_get(struct connections_hashmap *hashmap,
					struct connection_quad *key);
void connections_hashmap_del(struct connections_hashmap *hashmap,
			     struct connection_quad *key);
void connections_hashmap_dump(struct connections_hashmap *hashmap);

#endif

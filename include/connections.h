#ifndef __TCP_TUN_CONNECTIONS_H__
#define __TCP_TUN_CONNECTIONS_H__
#include <stdbool.h>
#include "common/types.h"

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
uint32_t hash_func(const struct connection_quad *quad);
struct connections_hashmap *connections_create(void);
struct connection *connections_pair(struct connection_quad *key,
				    enum tcp_state value);
void connections_set(struct connections_hashmap *hashmap,
		     struct connection_quad *key, enum tcp_state value);
enum tcp_state *connections_get(const struct connections_hashmap *hashmap,
				const struct connection_quad *key);
void connections_del(struct connections_hashmap *hashmap,
		     struct connection_quad *key);
void connections_dump(const struct connections_hashmap *hashmap);
bool connections_entry_is_occupied(struct connections_hashmap *hashmap,
				   struct connection_quad *key);

#endif

#ifndef __TCP_TUN_CONNECTIONS_H__
#define __TCP_TUN_CONNECTIONS_H__
#include <stdbool.h>
#include "ipv4_addr.h"
#include "types.h"

struct connection {
	struct connection_quad quad;
	enum tcp_state state;
	struct connection *next;
};

struct connections_hashmap {
	struct connection **entries;
};

u32 xorshift32(u32 x);
u32 pair_hash(u32 x, u32 y);
u32 hash_func(const struct connection_quad *quad);
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

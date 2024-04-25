#ifndef __TCP_TUN_CONNECTIONS_H__
#define __TCP_TUN_CONNECTIONS_H__
#include <stdbool.h>
#include "ipv4_addr.h"
#include "states.h"
#include "types.h"

struct conn_table_entry {
	struct conn_quad quad;
	enum tcp_state state;
	struct conn_table_entry *next;
};

struct conn_table {
	struct conn_table_entry **entries;
};

u32 xorshift32(u32 x);
u32 pair_hash(u32 x, u32 y);
u32 hash_func(const struct conn_quad *quad);
struct conn_table *init_conn_table(void);
struct conn_table_entry *init_conn_table_entry(struct conn_quad *key,
					       enum tcp_state value);
void conn_table_insert(struct conn_table *hashmap, struct conn_quad *key,
		       enum tcp_state value);
enum tcp_state *conn_table_get_value(const struct conn_table *hashmap,
				     const struct conn_quad *key);
void conn_table_remove(struct conn_table *hashmap, struct conn_quad *key);
void conn_table_dump(const struct conn_table *table);
bool conn_table_is_entry_occupied(struct conn_table *table,
				  struct conn_quad *key);

#endif

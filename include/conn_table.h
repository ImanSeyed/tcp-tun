#pragma once

#include <stdbool.h>
#include "ipv4_addr.h"
#include "states.h"
#include "types.h"
#include "list.h"

struct conn_table_entry {
	struct conn_quad quad;
	struct tcb *ctrl_block;
	struct list_head list;
};

struct conn_table {
	size_t size;
	size_t count;
	struct list_head *buckets;
};

struct conn_table *init_conn_table(void);
struct conn_table_entry *init_conn_table_entry(struct conn_quad *key,
					       struct tcb *value);
void conn_table_insert(struct conn_table *hashmap, struct conn_quad *key,
		       struct tcb *value);
struct tcb *conn_table_get(const struct conn_table *hashmap,
			   const struct conn_quad *key);
void conn_table_remove(struct conn_table *hashmap, struct conn_quad *key);
void conn_table_dump(const struct conn_table *table);
bool conn_table_key_exist(struct conn_table *table, struct conn_quad *key);

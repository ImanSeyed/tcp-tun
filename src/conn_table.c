#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "print.h"
#include "states.h"
#include "conn_table.h"

#define TABLE_SIZE 20000

u32 xorshift32(u32 x)
{
	x ^= ~(x << 15);
	x += (x >> 10);
	x ^= (x << 3);
	x += ~(x >> 16);
	return x;
}

u32 pair_hash(u32 x, u32 y)
{
	return xorshift32((x << 3) ^ (y >> 2) ^ (x >> 3) ^ (y << 4));
}

u32 hash_func(const struct conn_quad *quad)
{
	u32 f0 = quad->src.ip.byte_value;
	u32 f1 = quad->dest.ip.byte_value;
	u16 ports[] = { quad->src.port, quad->dest.port };
	u32 f2;
	memcpy(&f2, ports, sizeof(u32));
	return pair_hash(pair_hash(f0, f1), f2) % TABLE_SIZE;
}

struct conn_table_entry *init_conn_table_entry(struct conn_quad *key,
					       enum tcp_state value)
{
	struct conn_table_entry *entry =
		malloc(sizeof(struct conn_table_entry));
	entry->quad = *key;
	entry->state = value;
	entry->next = NULL;
	return entry;
}

struct conn_table *init_conn_table(void)
{
	struct conn_table *table = malloc(sizeof(struct conn_table));
	table->entries = malloc(sizeof(struct conn_table_entry *) * TABLE_SIZE);

	for (int i = 0; i < TABLE_SIZE; ++i)
		table->entries[i] = NULL;

	return table;
}

void conn_table_insert(struct conn_table *table, struct conn_quad *key,
		       enum tcp_state value)
{
	u32 slot = hash_func(key);
	struct conn_table_entry *entry = table->entries[slot];

	if (entry == NULL) {
		table->entries[slot] = init_conn_table_entry(key, value);
		return;
	}

	struct conn_table_entry *prev;

	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0) {
			entry->state = value;
			return;
		}
		prev = entry;
		entry = prev->next;
	}
	prev->next = init_conn_table_entry(key, value);
}

enum tcp_state *conn_table_get(const struct conn_table *table,
			       const struct conn_quad *key)
{
	u32 slot = hash_func(key);
	struct conn_table_entry *entry = table->entries[slot];
	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0)
			return &entry->state;
		entry = entry->next;
	}
	return NULL;
}

void conn_table_remove(struct conn_table *table, struct conn_quad *key)
{
	u32 slot = hash_func(key);
	struct conn_table_entry *entry = table->entries[slot];

	if (entry == NULL)
		return;

	struct conn_table_entry *prev;
	int index = 0;

	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0) {
			/* first item and no next entry */
			if (entry->next == NULL && index == 0)
				table->entries[slot] = NULL;

			/* first item with a next entry */
			if (entry->next != NULL && index == 0)
				table->entries[slot] = entry->next;

			/* last item */
			if (entry->next == NULL && index != 0)
				prev->next = NULL;

			/* middle item */
			if (entry->next != NULL && index != 0)
				prev->next = entry->next;

			free(entry);
			return;
		}

		prev = entry;
		entry = prev->next;
		++index;
	}
}

void conn_table_dump(const struct conn_table *table)
{
	for (int i = 0; i < TABLE_SIZE; ++i) {
		struct conn_table_entry *entry = table->entries[i];
		if (entry == NULL)
			continue;

		printf("slot[%u]: ", i);
		do {
			pr_quad(entry->quad);
			printf(" => ");
			pr_state(entry->state);
			printf(" ");
			entry = entry->next;
		} while (entry != NULL);
		printf("\n");
		fflush(stdout);
	}
}

bool conn_table_is_entry_occupied(struct conn_table *table,
				  struct conn_quad *key)
{
	u32 slot = hash_func(key);
	struct conn_table_entry *entry = table->entries[slot];
	if (entry == NULL)
		goto notfound;
	if (!memcmp(&entry->quad, key, sizeof(struct conn_quad)))
		return true;
notfound:
	return false;
}

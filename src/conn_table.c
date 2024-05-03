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
					       struct TCB *value)
{
	struct conn_table_entry *entry;

	entry = malloc(sizeof(struct conn_table_entry));
	entry->quad = *key;
	entry->ctrl_block = value;
	entry->next = NULL;

	return entry;
}

struct conn_table *init_conn_table(void)
{
	struct conn_table *table;

	table = malloc(sizeof(struct conn_table));
	table->entries = calloc(TABLE_SIZE, sizeof(struct conn_table_entry *));

	return table;
}

void conn_table_insert(struct conn_table *table, struct conn_quad *key,
		       struct TCB *value)
{
	u32 slot = hash_func(key);
	struct conn_table_entry *entry;
	struct conn_table_entry *prev;

	entry = table->entries[slot];
	if (entry == NULL) {
		table->entries[slot] = init_conn_table_entry(key, value);
		return;
	}

	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0) {
			entry->ctrl_block = value;
			return;
		}
		prev = entry;
		entry = prev->next;
	}

	prev->next = init_conn_table_entry(key, value);
}

struct TCB *conn_table_get(const struct conn_table *table,
			   const struct conn_quad *key)
{
	u32 slot = hash_func(key);
	struct conn_table_entry *entry;

	entry = table->entries[slot];
	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0)
			return entry->ctrl_block;
		entry = entry->next;
	}

	return NULL;
}

void conn_table_remove(struct conn_table *table, struct conn_quad *key)
{
	u32 slot = hash_func(key);
	struct conn_table_entry *entry;
	struct conn_table_entry *prev;
	size_t index = 0;

	entry = table->entries[slot];
	if (entry == NULL)
		return;

	free(entry->ctrl_block);
	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0) {
			/* first item and no next entry */
			if (entry->next == NULL && index == 0)
				table->entries[slot] = NULL;
			/* first item with a next entry */
			else if (entry->next != NULL && index == 0)
				table->entries[slot] = entry->next;
			/* last item */
			else if (entry->next == NULL && index != 0)
				prev->next = NULL;
			/* middle item */
			else if (entry->next != NULL && index != 0)
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
	struct conn_table_entry *entry;

	for (int i = 0; i < TABLE_SIZE; ++i) {
		entry = table->entries[i];
		if (entry == NULL)
			continue;

		printf("slot[%u]: ", i);
		do {
			pr_quad(entry->quad);
			printf(" => ");
			pr_state(entry->ctrl_block->state);
			printf(" ");
			entry = entry->next;
		} while (entry != NULL);
		printf("\n");
		fflush(stdout);
	}
}

bool conn_table_key_exist(struct conn_table *table, struct conn_quad *key)
{
	return (conn_table_get(table, key) != NULL) ? true : false;
}

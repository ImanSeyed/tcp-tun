#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "print.h"
#include "states.h"
#include "conn_table.h"

#define DEFAULT_TABLE_SIZE 20
#define DEFAULT_LOAD_FACTOR 0.75
#define FNV1A_OFFSET_BASIS 2166136261U
#define FNV1A_PRIME 16777619U

static size_t hash_func_sized(const struct conn_quad *quad, size_t table_size)
{
	const uint8_t *data = (const uint8_t *)quad;
	size_t hash = FNV1A_OFFSET_BASIS;

	for (size_t i = 0; i < sizeof(struct conn_quad); i++) {
		hash ^= data[i];
		hash *= FNV1A_PRIME;
	}

	return hash % table_size;
}

static bool conn_table_resize(struct conn_table *table)
{
	size_t old_size = table->size;
	size_t new_size = old_size * 2;
	struct list_head *old_buckets = table->buckets;
	struct list_head *new_buckets;
	struct conn_table_entry *entry, *tmp;
	u32 new_slot;

	new_buckets = malloc(new_size * sizeof(struct list_head));
	if (!new_buckets)
		return false;

	for (size_t i = 0; i < new_size; i++)
		list_head_init(&new_buckets[i]);

	table->buckets = new_buckets;
	table->size = new_size;

	/* rehash all existing entries */
	for (size_t i = 0; i < old_size; i++) {
		list_for_each_entry_safe(entry, tmp, &old_buckets[i], list)
		{
			list_del(&entry->list);

			new_slot = hash_func_sized(&entry->quad, new_size);
			list_add(&entry->list, &new_buckets[new_slot]);
		}
	}

	free(old_buckets);
	return true;
}

struct conn_table_entry *init_conn_table_entry(struct conn_quad *key,
					       struct tcb *value)
{
	struct conn_table_entry *entry;
	entry = malloc(sizeof(struct conn_table_entry));

	if (!entry)
		return NULL;
	entry->quad = *key;
	entry->ctrl_block = value;
	list_head_init(&entry->list);

	return entry;
}

struct conn_table *init_conn_table(void)
{
	struct conn_table *table;

	table = malloc(sizeof(struct conn_table));
	if (!table)
		return NULL;

	table->buckets = malloc(DEFAULT_TABLE_SIZE * sizeof(struct list_head));
	if (!table->buckets) {
		free(table);
		return NULL;
	}

	for (size_t i = 0; i < DEFAULT_TABLE_SIZE; i++) {
		list_head_init(&table->buckets[i]);
	}

	table->size = DEFAULT_TABLE_SIZE;
	table->count = 0;

	return table;
}

void conn_table_insert(struct conn_table *table, struct conn_quad *key,
		       struct tcb *value)
{
	struct conn_table_entry *entry;
	size_t slot;

	if ((double)table->count / table->size > DEFAULT_LOAD_FACTOR) {
		if (!conn_table_resize(table))
			fprintf(stderr,
				"Warning: Failed to resize hash table\n");
	}

	slot = hash_func_sized(key, table->size);

	list_for_each_entry(entry, &table->buckets[slot], list)
	{
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0) {
			entry->ctrl_block = value;
			return;
		}
	}

	entry = init_conn_table_entry(key, value);
	if (!entry)
		return;

	list_add(&entry->list, &table->buckets[slot]);
	table->count++;
}

struct tcb *conn_table_get(const struct conn_table *table,
			   const struct conn_quad *key)
{
	size_t slot = hash_func_sized(key, table->size);
	struct conn_table_entry *entry;

	list_for_each_entry(entry, &table->buckets[slot], list)
	{
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0)
			return entry->ctrl_block;
	}
	return NULL;
}

void conn_table_remove(struct conn_table *table, struct conn_quad *key)
{
	size_t slot = hash_func_sized(key, table->size);
	struct conn_table_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &table->buckets[slot], list)
	{
		if (memcmp(&entry->quad, key, sizeof(struct conn_quad)) == 0) {
			list_del(&entry->list);
			free(entry->ctrl_block);
			free(entry);
			table->count--;
			return;
		}
	}
}

void conn_table_dump(const struct conn_table *table)
{
	struct conn_table_entry *entry;

	for (size_t i = 0; i < table->size; i++) {
		if (list_empty(&table->buckets[i]))
			continue;

		printf("slot[%zu]: ", i);
		list_for_each_entry(entry, &table->buckets[i], list)
		{
			pr_quad(entry->quad);
			printf(" => ");
			pr_state(entry->ctrl_block->state);
			printf(" ");
		}
		printf("\n");
		fflush(stdout);
	}
}

bool conn_table_key_exist(struct conn_table *table, struct conn_quad *key)
{
	return (conn_table_get(table, key) != NULL) ? true : false;
}

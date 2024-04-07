#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "print.h"
#include "connections.h"

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

u32 hash_func(const struct connection_quad *quad)
{
	u32 f0 = quad->src.ip.byte_value;
	u32 f1 = quad->dest.ip.byte_value;
	u16 ports[] = { quad->src.port, quad->dest.port };
	u32 f2;
	memcpy(&f2, ports, sizeof(u32));
	return pair_hash(pair_hash(f0, f1), f2) % TABLE_SIZE;
}

struct connection *connections_pair(struct connection_quad *key,
				    enum tcp_state value)
{
	struct connection *entry = malloc(sizeof(struct connection));
	entry->quad = *key;
	entry->state = value;
	entry->next = NULL;
	return entry;
}

struct connections_hashmap *connections_create(void)
{
	struct connections_hashmap *hashmap =
		malloc(sizeof(struct connections_hashmap));
	hashmap->entries = malloc(sizeof(struct connection *) * TABLE_SIZE);

	for (int i = 0; i < TABLE_SIZE; ++i)
		hashmap->entries[i] = NULL;

	return hashmap;
}

void connections_set(struct connections_hashmap *hashmap,
		     struct connection_quad *key, enum tcp_state value)
{
	u32 slot = hash_func(key);
	struct connection *entry = hashmap->entries[slot];

	if (entry == NULL) {
		hashmap->entries[slot] = connections_pair(key, value);
		return;
	}

	struct connection *prev;

	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct connection_quad)) ==
		    0) {
			entry->state = value;
			return;
		}
		prev = entry;
		entry = prev->next;
	}
	prev->next = connections_pair(key, value);
}

enum tcp_state *connections_get(const struct connections_hashmap *hashmap,
				const struct connection_quad *key)
{
	u32 slot = hash_func(key);
	struct connection *entry = hashmap->entries[slot];
	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct connection_quad)) ==
		    0)
			return &entry->state;
		entry = entry->next;
	}
	return NULL;
}

void connections_del(struct connections_hashmap *hashmap,
		     struct connection_quad *key)
{
	u32 bucket = hash_func(key);
	struct connection *entry = hashmap->entries[bucket];

	if (entry == NULL)
		return;

	struct connection *prev;
	int index = 0;

	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct connection_quad)) ==
		    0) {
			/* first item and no next entry */
			if (entry->next == NULL && index == 0)
				hashmap->entries[bucket] = NULL;

			/* first item with a next entry */
			if (entry->next != NULL && index == 0)
				hashmap->entries[bucket] = entry->next;

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

void connections_dump(const struct connections_hashmap *hashmap)
{
	for (int i = 0; i < TABLE_SIZE; ++i) {
		struct connection *entry = hashmap->entries[i];
		if (entry == NULL)
			continue;

		printf("slot[%u]: ", i);

		for (;;) {
			pr_quad(entry->quad);
			printf(" => ");
			pr_state(entry->state);
			printf(" ");
			if (entry->next == NULL)
				break;
			entry = entry->next;
		}
		printf("\n");
		fflush(stdout);
	}
}

bool connections_entry_is_occupied(struct connections_hashmap *hashmap,
				   struct connection_quad *key)
{
	for (int i = 0; i < TABLE_SIZE; ++i) {
		struct connection *entry = hashmap->entries[i];
		if (entry == NULL)
			continue;
		while (entry->next != NULL) {
			if (memcmp(&entry->quad, key,
				   sizeof(struct connection_quad)) == 0) {
				return true;
			}
			entry = entry->next;
		}
	}
	return false;
}

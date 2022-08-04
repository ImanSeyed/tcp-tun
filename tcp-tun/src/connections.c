#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../include/connections.h"
#include "../include/common/print.h"

#define TABLE_SIZE 20000

uint32_t xorshift32(uint32_t x)
{
	x ^= ~(x << 15);
	x += (x >> 10);
	x ^= (x << 3);
	x += ~(x >> 16);
	return x;
}

uint32_t pair_hash(uint32_t x, uint32_t y)
{
	return xorshift32((x << 3) ^ (y >> 2) ^ (x >> 3) ^ (y << 4));
}

uint32_t hash_func(struct connection_quad *quad)
{
	uint32_t f0 = quad->src.ip.byte_value;
	uint32_t f1 = quad->dest.ip.byte_value;
	uint16_t ports[] = { quad->src.port, quad->dest.port };
	uint32_t f2;
	memcpy(&f2, ports, sizeof(uint32_t));
	return pair_hash(pair_hash(f0, f1), f2) % TABLE_SIZE;
}

struct connection *connections_hashmap_pair(struct connection_quad *key,
					    enum tcp_state *value)
{
	struct connection *entry = malloc(sizeof(struct connection));
	entry->quad = *key;
	entry->state = *value;
	entry->next = NULL;
	return entry;
}

struct connections_hashmap *connections_hashmap_create(void)
{
	struct connections_hashmap *hashmap =
		malloc(sizeof(struct connections_hashmap));
	hashmap->entries = malloc(sizeof(struct connection *) * TABLE_SIZE);

	for (int i = 0; i < TABLE_SIZE; ++i)
		hashmap->entries[i] = NULL;

	return hashmap;
}

void connections_hashmap_set(struct connections_hashmap *hashmap,
			     struct connection_quad *key, enum tcp_state *value)
{
	uint32_t slot = hash_func(key);
	struct connection *entry = hashmap->entries[slot];

	if (entry == NULL) {
		hashmap->entries[slot] = connections_hashmap_pair(key, value);
		return;
	}

	struct connection *prev;

	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct connection_quad))) {
			entry->state = *value;
			return;
		}
		prev = entry;
		entry = prev->next;
	}
	prev->next = connections_hashmap_pair(key, value);
}

enum tcp_state *connections_hashmap_get(struct connections_hashmap *hashmap,
					struct connection_quad *key)
{
	uint32_t slot = hash_func(key);
	struct connection *entry = hashmap->entries[slot];
	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct connection_quad)))
			return &entry->state;
		entry = entry->next;
	}
	return NULL;
}

void connections_hashmap_del(struct connections_hashmap *hashmap,
			     struct connection_quad *key)
{
	uint32_t bucket = hash_func(key);
	struct connection *entry = hashmap->entries[bucket];

	if (entry == NULL)
		return;

	struct connection *prev;
	int index = 0;

	while (entry != NULL) {
		if (memcmp(&entry->quad, key, sizeof(struct connection_quad))) {
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

void connections_hashmap_dump(struct connections_hashmap *hashmap)
{
	for (int i = 0; i < TABLE_SIZE; ++i) {
		struct connection *entry = hashmap->entries[i];
		if (entry == NULL)
			continue;

		printf("slot[%u]: ", i);

		for (;;) {
			print_quad(entry->quad);
			printf(" => ");
			print_state(entry->state);
			printf(" ");
			if (entry->next == NULL)
				break;
			entry = entry->next;
		}
		printf("\n");
	}
}

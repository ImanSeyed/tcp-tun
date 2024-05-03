#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "ipv4_addr.h"

char *ipv4_addr_to_str(union ipv4_addr *addr)
{
	assert(addr != NULL);

	char *ipv4_addr_str = calloc(16, sizeof(char));
	if (ipv4_addr_str == NULL) {
		perror("ipv4_addr_to_str");
		return NULL;
	}

	sprintf(ipv4_addr_str, "%u.%u.%u.%u", addr->first, addr->second,
		addr->third, addr->fourth);

	return ipv4_addr_str;
}

void init_ipv4_addr(union ipv4_addr *addr, u8 a, u8 b, u8 c, u8 d)
{
	assert(addr != NULL);

	addr->first = a;
	addr->second = b;
	addr->third = c;
	addr->fourth = d;
}

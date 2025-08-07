#include <assert.h>
#include <stdio.h>
#include "ipv4_addr.h"

void ipv4_addr_to_str(union ipv4_addr *addr, char ip_str[IPV4_ADDR_STR_LEN])
{
	assert(addr != NULL);
	assert(ip_str != NULL);

	snprintf(ip_str, IPV4_ADDR_STR_LEN, "%u.%u.%u.%u", addr->first,
		 addr->second, addr->third, addr->fourth);
}

void init_ipv4_addr(union ipv4_addr *addr, u8 a, u8 b, u8 c, u8 d)
{
	assert(addr != NULL);

	addr->first = a;
	addr->second = b;
	addr->third = c;
	addr->fourth = d;
}

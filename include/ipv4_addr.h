#ifndef __TCP_TUN_IPV4_ADDR_H__
#define __TCP_TUN_IPV4_ADDR_H__
#include "types.h"

union ipv4_addr {
	struct {
		u8 fourth;
		u8 third;
		u8 second;
		u8 first;
	};
	u32 byte_value;
};

struct addrress_pair {
	union ipv4_addr ip;
	u16 port;
};

struct conn_quad {
	struct addrress_pair src;
	struct addrress_pair dest;
};

void init_ipv4_addr(union ipv4_addr *addr, u8 a, u8 b, u8 c, u8 d);
char *ipv4_addr_to_str(union ipv4_addr *addr);

#endif

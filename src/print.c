#include <stdio.h>
#include <stdint.h>
#include "types.h"

void print_addr(union ipv4_addr ip, uint16_t port)
{
	printf("%u.%u.%u.%u:%u", ip.first, ip.second, ip.third, ip.fourth,
	       port);
}

void print_bytes(uint8_t *bytes, size_t start, size_t end)
{
	for (size_t i = start; i < end; ++i)
		printf("%.2x ", bytes[i]);
	printf("\n");
}

void print_state(enum tcp_state state)
{
	switch (state) {
	case Closed:
		printf("ClOSED");
		break;
	case Listen:
		printf("LISTEN");
		break;
	case SynRecvd:
		printf("SYN_RECIVED");
		break;
	case Estab:
		printf("ESTAB");
		break;
	}
}

void print_quad(struct connection_quad quad)
{
	print_addr(quad.src.ip, quad.src.port);
	printf(" -> ");
	print_addr(quad.dest.ip, quad.dest.port);
}

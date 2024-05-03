#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "types.h"
#include "print.h"
#include "tcp_header.h"
#include "ipv4_addr.h"
#include "ipv4_header.h"

void pr_ipv4(union ipv4_addr ip)
{
	char *ipv4_addr_str = ipv4_addr_to_str(&ip);
	printf("%s", ipv4_addr_str);
	free(ipv4_addr_str);
}

void pr_addr(union ipv4_addr ip, u16 port)
{
	pr_ipv4(ip);
	printf(":%u", port);
}

void pr_bytes(const u8 *bytes, size_t start, size_t end)
{
	assert(start <= end);

	for (size_t i = start; i <= end; ++i)
		printf("%.2x ", bytes[i]);
	printf("\n");
}

void pr_state(enum tcp_state state)
{
	const char *STATES_STR[] = {
#define ENUMERATE_STATES_IMPL(name) #name,
		ENUMERATE_STATES()
#undef ENUMERATE_STATES_IMPL
	};

	printf("%s", STATES_STR[state]);
}

void pr_quad(struct conn_quad quad)
{
	pr_addr(quad.src.ip, quad.src.port);
	printf(" -> ");
	pr_addr(quad.dest.ip, quad.dest.port);
}

void pr_ipv4_header(const struct ipv4_header *ipv4h)
{
	printf("header size: %u\n"
	       "type_of_service: %u\n"
	       "total_length: %u\n"
	       "identification: %u\n"
	       "flags: %u\n"
	       "fragment_offset: %u\n"
	       "time_to_live: %u\n"
	       "protocol: %u\n"
	       "checksum: %.4x\n",
	       ipv4h_size(ipv4h), ipv4h->type_of_service, ipv4h->total_length,
	       ipv4h->identification, ipv4h_flags(ipv4h),
	       ipv4h_fragments(ipv4h), ipv4h->ttl, ipv4h->protocol,
	       ipv4h->checksum);

	printf("src addr: ");
	pr_ipv4(ipv4h->src_addr);
	printf("\ndest addr: ");
	pr_ipv4(ipv4h->dest_addr);
	printf("\n");
}

void pr_tcp_header(const struct tcp_header *tcph)
{
	printf("src port: %u\n"
	       "dest port: %u\n"
	       "seq number: %u\n"
	       "ack number: %u\n"
	       "header size: %u\n"
	       "flags: %u\n"
	       "win size: %u\n"
	       "checksum: %.4x\n"
	       "urg pointer: %u\n",
	       tcph->src_port, tcph->dest_port, tcph->seq_number,
	       tcph->ack_number, tcph_size(tcph), tcph_flags(tcph),
	       tcph->win_size, tcph->checksum, tcph->urg_pointer);
}

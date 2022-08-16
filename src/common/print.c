#include <stdint.h>
#include <stdio.h>
#include "common/types.h"
#include "common/print.h"

void print_ipv4(union ipv4_addr ip)
{
	printf("%u.%u.%u.%u", ip.first, ip.second, ip.third, ip.fourth);
}

void print_addr(union ipv4_addr ip, uint16_t port)
{
	print_ipv4(ip);
	printf(":%u", port);
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
	case SYNRECVD:
		printf("SYN_RECIVED");
		break;
	case ESTAB:
		printf("ESTAB");
		break;
	case FINWAIT1:
		printf("FIN_WAIT1");
		break;
	case FINWAIT2:
		printf("FIN_WAIT1");
		break;
	case CLOSING:
		printf("CLOSING");
		break;
	}
}

void print_quad(struct connection_quad quad)
{
	print_addr(quad.src.ip, quad.src.port);
	printf(" -> ");
	print_addr(quad.dest.ip, quad.dest.port);
}

void print_ipv4_header(struct ipv4_header *ipv4h)
{
	printf("version: %u\n"
	       "ihl: %u\n"
	       "type_of_service: %u\n"
	       "total_length: %u\n"
	       "identification: %u\n"
	       "flags: %u\n"
	       "fragment_offset: %u\n"
	       "time_to_live: %u\n"
	       "protocol: %u\n"
	       "checksum: %.4x\n"
	       "src addr: ",
	       ipv4h->version, ipv4h->ihl, ipv4h->type_of_service,
	       ipv4h->total_length, ipv4h->identification, ipv4h->flags,
	       ipv4h->fragment_offset, ipv4h->time_to_live, ipv4h->protocol,
	       ipv4h->checksum);

	print_ipv4(ipv4h->src_addr);
	printf("\ndest addr: ");
	print_ipv4(ipv4h->dest_addr);
	printf("\n");
}

void print_tcp_header(struct tcp_header *tcph)
{
	printf("src port: %u\n"
	       "dest port: %u\n"
	       "seq number: %u\n"
	       "ack number: %u\n"
	       "data offset: %u\n"
	       "is urg: %u\n"
	       "is ack: %u\n"
	       "is psh: %u\n"
	       "is rst: %u\n"
	       "is syn: %u\n"
	       "is fin: %u\n"
	       "win size: %u\n"
	       "checksum: %.4x\n"
	       "urg pointer: %u\n",
	       tcph->src_port, tcph->dest_port, tcph->seq_number,
	       tcph->ack_number, tcph->data_offset, tcph->is_urg, tcph->is_ack,
	       tcph->is_psh, tcph->is_rst, tcph->is_syn, tcph->is_fin,
	       tcph->win_size, tcph->checksum, tcph->urg_pointer);
}
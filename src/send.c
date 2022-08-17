#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "utils/ipv4_utility.h"
#include "utils/tcp_utility.h"
#include "common/endian.h"
#include "common/types.h"
#include "states.h"
#include "send.h"

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 uint8_t *buffer)
{
	uint8_t *pseudo_header = NULL, *ipv4h_ptr = NULL, *tcph_ptr = NULL;
	size_t ipv4h_len, tcph_len, buffer_len;
	memset(buffer, 0, 1504);
	convert_into_be16(IPv4_PROTO, buffer + 2);
	ipv4h_len = dump_ipv4_header(ipv4h, buffer, RAW_OFFSET);
	tcph_len = dump_tcp_header(tcph, buffer, ipv4h_len + RAW_OFFSET);
	buffer_len = RAW_OFFSET + ipv4h_len + tcph_len;
	ipv4h_ptr = buffer + RAW_OFFSET;
	tcph_ptr = buffer + RAW_OFFSET + ipv4h_len;

	/* let's calculate checksums */
	pseudo_header = get_pseudo_header(ipv4h);
	ipv4h->checksum = checksum(ipv4h_ptr, ipv4h_len / 2);
	tcph->checksum = tcp_checksum(tcph, pseudo_header);
	convert_into_be16(ipv4h->checksum, ipv4h_ptr + 10);
	convert_into_be16(tcph->checksum, tcph_ptr + 16);

	/* write the buffer over the tunnel device */
	if (write(nic_fd, buffer, buffer_len) == -1)
		perror("write over tun");

	free(pseudo_header);
}

void send_rst(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter)
{
	uint8_t buffer[1504];
	struct ipv4_header rst_ipv4h;
	struct tcp_header rst_tcph;
	/* write out the headers */
	/* TODO: fix sequence numbers */
	fill_tcp_header(&rst_tcph, tcph->dest_port, tcph->src_port, 0,
			starter->send.wnd);
	rst_tcph.ack_number = 0;
	rst_tcph.is_rst = true;
	fill_ipv4_header(&rst_ipv4h,
			 20 + (rst_tcph.data_offset * 4) + rst_tcph.options_len,
			 64, TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &rst_ipv4h, &rst_tcph, buffer);
}

void send_fin(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter)
{
	uint8_t buffer[1504];
	struct ipv4_header fin_ipv4h;
	struct tcp_header fin_tcph;
	/* write out the headers */
	fill_tcp_header(&fin_tcph, tcph->dest_port, tcph->src_port,
			starter->send.nxt, starter->send.wnd);
	fin_tcph.ack_number = 0;
	fin_tcph.is_fin = true;
	fill_ipv4_header(&fin_ipv4h,
			 20 + (fin_tcph.data_offset * 4) + fin_tcph.options_len,
			 64, TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &fin_ipv4h, &fin_tcph, buffer);
}
#include <stdbool.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils/tcp_utility.h"
#include "utils/ipv4_utility.h"
#include "common/endian.h"
#include "common/types.h"
#include "states.h"

#define RAW_OFFSET 4
#define TCP_PROTO 0x06

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 uint8_t *buffer)
{
	memset(buffer, 0, 1500);
	convert_into_be16(0x08, &buffer[2], &buffer[3]);
	size_t ipv4h_len = 0, tcph_len = 0, buffer_len = 0;
	ipv4h_len += dump_ipv4_header(ipv4h, buffer, RAW_OFFSET);
	tcph_len += dump_tcp_header(tcph, buffer, ipv4h_len + RAW_OFFSET);
	buffer_len = RAW_OFFSET + ipv4h_len + tcph_len;
	ipv4h->checksum = checksum(buffer + RAW_OFFSET, ipv4h_len / 2);
	tcph->checksum =
		checksum(buffer + RAW_OFFSET + ipv4h_len, tcph_len / 2);
	convert_into_be16(ipv4h->checksum, &buffer[RAW_OFFSET + 10],
			   &buffer[RAW_OFFSET + 11]);
	convert_into_be16(tcph->checksum, &buffer[RAW_OFFSET + ipv4h_len + 16],
			  &buffer[RAW_OFFSET + ipv4h_len + 17]);
	if (write(nic_fd, buffer, buffer_len) == -1)
		perror("write over tun");
}

void accept_request(int nic_fd, struct ipv4_header *ipv4h,
		    struct tcp_header *tcph)
{
	/* only expected SYN packet */
	if (!tcph->is_syn)
		return;

	struct TCB starter = {
		.state = SYNRECVD,
		.send = { .iss = 0,
			  .una = 0,
			  .nxt = 1,
			  .wnd = 10,
			  .up = false,
			  .wl1 = 0,
			  .wl2 = 0 },
		.recv = { .irs = tcph->seq_number,
			  .nxt = tcph->seq_number + 1,
			  .wnd = tcph->win_size,
			  .up = false },
	};

	/* start establishing a connection */
	struct tcp_header syn_ack;
	struct ipv4_header ip;
	uint8_t buffer[1500];

	/* write out the headers */
	fill_tcp_header(&syn_ack, tcph->dest_port, tcph->src_port,
			starter.send.iss, starter.send.wnd);
	syn_ack.ack_number = tcph->seq_number + 1;

	syn_ack.is_syn = true;
	syn_ack.is_ack = true;
	fill_ipv4_header(&ip, 20 + (syn_ack.data_offset * 4) + syn_ack.options_len,
			 64, TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &ip, &syn_ack, buffer);
}

void on_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph)
{
}

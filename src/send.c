#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ipv4_header.h"
#include "tcp_header.h"
#include "endian.h"
#include "types.h"
#include "states.h"
#include "send.h"

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 u8 *buffer)
{
	u8 *pseudo_header = NULL, *ipv4h_ptr = NULL, *tcph_ptr = NULL;
	size_t ipv4h_len = ipv4h->version_and_ihl.ihl * 4;
	size_t tcph_len = tcph->flags_and_data_offset.data_offset * 4;
	size_t buffer_len = ipv4h_len + tcph_len;

	memset(buffer, 0, 1504);
	write_toggle_endian16(IPV4_PROTO, buffer + 2);

	ipv4h_to_buff(ipv4h, buffer, 0);
	tcph_to_buff(tcph, buffer, ipv4h_len);
	ipv4h_ptr = buffer;
	tcph_ptr = buffer + ipv4h_len;

	/* let's calculate checksums */
	pseudo_header = get_pseudo_header(ipv4h);
	ipv4h->checksum = ipv4h_checksum(ipv4h_ptr, ipv4h_len);
	memcpy(ipv4h_ptr + 10, &ipv4h->checksum, sizeof(u16));
	tcph->checksum = tcph_checksum(tcph, pseudo_header);
	write_toggle_endian16(ipv4h->checksum, ipv4h_ptr + 10);
	write_toggle_endian16(tcph->checksum, tcph_ptr + 16);

	/* write the buffer over the tunnel device */
	if (write(nic_fd, buffer, buffer_len) == -1)
		perror("write over tun");

	free(pseudo_header);
}

void send_rst(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter)
{
	u8 buffer[1500];
	struct ipv4_header rst_ipv4h;
	struct tcp_header rst_tcph;
	/* write out the headers */
	/* TODO: fix sequence numbers */
	init_tcph(&rst_tcph, tcph->dest_port, tcph->src_port, RST, 0, 0,
		  starter->send.wnd);
	init_ipv4h(&rst_ipv4h,
		   20 + (rst_tcph.flags_and_data_offset.data_offset * 4), 64,
		   TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &rst_ipv4h, &rst_tcph, buffer);
}

void send_fin(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter)
{
	u8 buffer[1500];
	struct ipv4_header fin_ipv4h;
	struct tcp_header fin_tcph;
	/* write out the headers */
	init_tcph(&fin_tcph, tcph->dest_port, tcph->src_port, FIN,
		  starter->send.nxt, 0, starter->send.wnd);
	init_ipv4h(&fin_ipv4h,
		   20 + (fin_tcph.flags_and_data_offset.data_offset * 4), 64,
		   TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &fin_ipv4h, &fin_tcph, buffer);
}

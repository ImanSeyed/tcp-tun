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
#include "tun.h"

void send_packet(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
		 u8 *payload)
{
	u8 buffer[1504] = { 0 };
	u8 *pseudo_header = NULL, *ipv4h_ptr = NULL, *tcph_ptr = NULL;
	size_t ipv4h_len = ipv4h->version_and_ihl.ihl * 4;
	size_t tcph_len = tcph->flags_and_data_offset.data_offset * 4;
	size_t buffer_len = PI_LEN + ipv4h_len + tcph_len;

	buffer[ETH_TYPE_OFF] = IPV4_PROTO;
	u8 *packet = &buffer[PI_LEN];

	ipv4h_to_buff(ipv4h, packet, 0);
	tcph_to_buff(tcph, packet, ipv4h_len);
	ipv4h_ptr = packet;
	tcph_ptr = packet + ipv4h_len;

	/* calculate checksums */
	pseudo_header = get_pseudo_header(ipv4h);
	ipv4h->checksum = ipv4h_checksum(ipv4h_ptr, ipv4h_len);
	tcph->checksum = tcph_checksum(tcph, pseudo_header);
	memcpy(&ipv4h_ptr[IP_CHECKSUM_OFF], &ipv4h->checksum, sizeof(u16));
	memcpy(&tcph_ptr[TCP_CHECKSUM_OFF], &tcph->checksum, sizeof(u16));

	/* write the packet info + the packet over the tunnel device */
	if (write(nic_fd, buffer, buffer_len) == -1)
		perror("write over tun");

	free(pseudo_header);
}

void send_rst(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter)
{
	struct ipv4_header rst_ipv4h;
	struct tcp_header rst_tcph;
	/* write out the headers */
	/* TODO: fix sequence numbers */
	init_tcph(&rst_tcph, tcph->dest_port, tcph->src_port, RST, 0, 0,
		  starter->send.wnd);
	init_ipv4h(&rst_ipv4h,
		   20 + (rst_tcph.flags_and_data_offset.data_offset * 4), 64,
		   TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &rst_ipv4h, &rst_tcph, NULL);
}

void send_fin(int nic_fd, struct ipv4_header *ipv4h, struct tcp_header *tcph,
	      struct TCB *starter)
{
	struct ipv4_header fin_ipv4h;
	struct tcp_header fin_tcph;
	/* write out the headers */
	init_tcph(&fin_tcph, tcph->dest_port, tcph->src_port, FIN,
		  starter->send.nxt, 0, starter->send.wnd);
	init_ipv4h(&fin_ipv4h,
		   20 + (fin_tcph.flags_and_data_offset.data_offset * 4), 64,
		   TCP_PROTO, ipv4h->dest_addr, ipv4h->src_addr);
	send_packet(nic_fd, &fin_ipv4h, &fin_tcph, NULL);
}

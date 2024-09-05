#include <stdlib.h>
#include <string.h>
#include "ipv4_header.h"
#include "tcp_header.h"
#include "packet.h"
#include "tun.h"

struct packet *alloc_packet()
{
	struct packet *pkt;

	pkt = calloc(1, sizeof(struct packet));

	pkt->buff = calloc(TUN_MTU + PI_LEN, sizeof(u8));
	pkt->buff[ETH_TYPE_OFF] = IPV4_PROTO;

	pkt->pkt_buff = pkt->buff + PI_LEN;

	pkt->ipv4h_buff = pkt->pkt_buff;
	pkt->tcph_buff = pkt->pkt_buff + sizeof(struct ipv4_header);

	pkt->ipv4h = calloc(1, sizeof(struct ipv4_header));
	pkt->tcph = calloc(1, sizeof(struct tcp_header));

	return pkt;
}

void dealloc_packet(struct packet *pkt)
{
	free(pkt->ipv4h);
	free(pkt->tcph);
	free(pkt->buff);
	free(pkt);
}

void commit_packet(struct packet *pkt)
{
	u8 *pseudo_header;

	/* commit headers to the buffer */
	ipv4h_to_buff(pkt->ipv4h, pkt->pkt_buff, 0);
	tcph_to_buff(pkt->tcph, pkt->pkt_buff, ipv4h_size(pkt->ipv4h));

	/* update checksums */
	pseudo_header = get_pseudo_header(pkt->ipv4h);

	pkt->ipv4h->checksum =
		ipv4h_checksum(pkt->pkt_buff, ipv4h_size(pkt->ipv4h));
	pkt->tcph->checksum = tcph_checksum(
		pkt->tcph_buff, tcph_size(pkt->tcph), pseudo_header);

	memcpy(&pkt->ipv4h_buff[IP_CHECKSUM_OFF], &pkt->ipv4h->checksum,
	       sizeof(u16));
	memcpy(&pkt->tcph_buff[TCP_CHECKSUM_OFF], &pkt->tcph->checksum,
	       sizeof(u16));

	free(pseudo_header);
}

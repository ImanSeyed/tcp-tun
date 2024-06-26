/* in_cksum.c
* 4.4-Lite-2 Internet checksum routine, modified to take a vector of
* pointers/lengths giving the pieces to be checksummed.  Also using
* Tahoe/CGI version of ADDCARRY(x) macro instead of from portable version.
*/

/*
* Copyright (c) 1988, 1992, 1993
*	The Regents of the University of California.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. Neither the name of the University nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*
*	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
*/

#include <stdint.h>
#include "types.h"
#include "in_cksum.h"

/*
* Checksum routine for Internet Protocol family headers (Portable Version).
*
* This routine is very heavily used in the network
* code and should be modified for each CPU to be as fast as possible.
*/

u16 in_cksum(const struct cksum_vec *vec, int veclen)
{
	const u16 *w;
	int sum = 0;
	int mlen = 0;
	int byte_swapped = 0;

	union {
		u8 c[2];
		u16 s;
	} s_util;
	union {
		u16 s[2];
		u32 l;
	} l_util;

	for (; veclen != 0; vec++, veclen--) {
		if (vec->len == 0)
			continue;
		w = (const u16 *)(const void *)vec->ptr;
		if (mlen == -1) {
			/*
			* The first byte of this chunk is the continuation
			* of a word spanning between this chunk and the
			* last chunk.
			*
			* s_util.c[0] is already saved when scanning previous
			* chunk.
			*/
			s_util.c[1] = *(const u8 *)w;
			sum += s_util.s;
			w = (const u16 *)(const void *)((const u8 *)w + 1);
			mlen = vec->len - 1;
		} else
			mlen = vec->len;
		/*
		* Force to even boundary.
		*/
		if ((1 & (uintptr_t)w) && (mlen > 0)) {
			REDUCE;
			sum <<= 8;
			s_util.c[0] = *(const u8 *)w;
			w = (const u16 *)(const void *)((const u8 *)w + 1);
			mlen--;
			byte_swapped = 1;
		}
		/*
		* Unroll the loop to make overhead from
		* branches &c small.
		*/
		while ((mlen -= 32) >= 0) {
			sum += w[0];
			sum += w[1];
			sum += w[2];
			sum += w[3];
			sum += w[4];
			sum += w[5];
			sum += w[6];
			sum += w[7];
			sum += w[8];
			sum += w[9];
			sum += w[10];
			sum += w[11];
			sum += w[12];
			sum += w[13];
			sum += w[14];
			sum += w[15];
			w += 16;
		}
		mlen += 32;
		while ((mlen -= 8) >= 0) {
			sum += w[0];
			sum += w[1];
			sum += w[2];
			sum += w[3];
			w += 4;
		}
		mlen += 8;
		if (mlen == 0 && byte_swapped == 0)
			continue;
		REDUCE;
		while ((mlen -= 2) >= 0) {
			sum += *w++;
		}
		if (byte_swapped) {
			REDUCE;
			sum <<= 8;
			byte_swapped = 0;
			if (mlen == -1) {
				s_util.c[1] = *(const u8 *)w;
				sum += s_util.s;
				mlen = 0;
			} else
				mlen = -1;
		} else if (mlen == -1)
			s_util.c[0] = *(const u8 *)w;
	}
	if (mlen == -1) {
		/* The last mbuf has odd # of bytes. Follow the
		  standard (the odd byte may be shifted left by 8 bits
		  or not as determined by endian-ness of the machine) */
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	REDUCE;
	return (~sum & 0xffff);
}

/*
* Given the host-byte-order value of the checksum field in a packet
* header, and the network-byte-order computed checksum of the data
* that the checksum covers (including the checksum itself), compute
* what the checksum field *should* have been.
*/
u16 in_cksum_shouldbe(u16 sum, u16 computed_sum)
{
	u32 shouldbe;

	/*
	* The value that should have gone into the checksum field
	* is the negative of the value gotten by summing up everything
	* *but* the checksum field.
	*
	* We can compute that by subtracting the value of the checksum
	* field from the sum of all the data in the packet, and then
	* computing the negative of that value.
	*
	* "sum" is the value of the checksum field, and "computed_sum"
	* is the negative of the sum of all the data in the packets,
	* so that's -(-computed_sum - sum), or (sum + computed_sum).
	*
	* All the arithmetic in question is one's complement, so the
	* addition must include an end-around carry; we do this by
	* doing the arithmetic in 32 bits (with no sign-extension),
	* and then adding the upper 16 bits of the sum, which contain
	* the carry, to the lower 16 bits of the sum, and then do it
	* again in case *that* sum produced a carry.
	*
	* As RFC 1071 notes, the checksum can be computed without
	* byte-swapping the 16-bit words; summing 16-bit words
	* on a big-endian machine gives a big-endian checksum, which
	* can be directly stuffed into the big-endian checksum fields
	* in protocol headers, and summing words on a little-endian
	* machine gives a little-endian checksum, which must be
	* byte-swapped before being stuffed into a big-endian checksum
	* field.
	*
	* "computed_sum" is a network-byte-order value, so we must put
	* it in host byte order before subtracting it from the
	* host-byte-order value from the header; the adjusted checksum
	* will be in host byte order, which is what we'll return.
	*/
	shouldbe = sum;

	shouldbe += __builtin_bswap32(computed_sum);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
	shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
	return (u16)shouldbe;
}

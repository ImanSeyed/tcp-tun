#ifndef __TCP_TUN_IN_CKSUM_H__
#define __TCP_TUN_IN_CKSUM_H__
#include <stdint.h>
#include "types.h"

#define ADDCARRY(x)                   \
	{                             \
		if ((x) > 65535)      \
			(x) -= 65535; \
	}
#define REDUCE                                   \
	{                                        \
		l_util.l = sum;                  \
		sum = l_util.s[0] + l_util.s[1]; \
		ADDCARRY(sum);                   \
	}

u16 in_cksum(const struct cksum_vec *vec, int veclen);

#endif

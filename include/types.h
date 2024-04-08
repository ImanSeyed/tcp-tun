#ifndef __TCP_TUN_TYPES_H__
#define __TCP_TUN_TYPES_H__
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * 2 bytes for ether_flags, 2 bytes for ether_type
 * according to tuntap.txt in Linux kernel documentations
 * */

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

#define ENUMERATE_STATES()              \
	ENUMERATE_STATES_IMPL(SYNRECVD) \
	ENUMERATE_STATES_IMPL(ESTAB)    \
	ENUMERATE_STATES_IMPL(FINWAIT1) \
	ENUMERATE_STATES_IMPL(FINWAIT2) \
	ENUMERATE_STATES_IMPL(CLOSING)

enum tcp_state {
#define ENUMERATE_STATES_IMPL(name) name,
	ENUMERATE_STATES()
#undef ENUMERATE_STATES_IMPL
};

struct cksum_vec {
	const u8 *ptr;
	size_t len;
};

#endif

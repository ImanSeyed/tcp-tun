#include <stdint.h>
#include <string.h>

uint16_t convert_from_be16(uint8_t first, uint8_t second)
{
	uint8_t src[] = { first, second };
	uint16_t dest;
	memcpy(&dest, src, sizeof(uint16_t));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap16(dest);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return dest;
#endif
}

uint32_t convert_from_be32(uint8_t first, uint8_t second, uint8_t third,
			   uint8_t fourth)
{
	uint8_t src[] = { first, second, third, fourth };
	uint32_t dest;
	memcpy(&dest, src, sizeof(uint32_t));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return __builtin_bswap32(dest);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return dest;
#endif
}

void convert_into_be16(uint16_t data, uint8_t *first, uint8_t *second)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint16_t tmp = __builtin_bswap16(data);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint16_t tmp = data;
#endif
	*first = tmp & 0xff;
	*second = tmp >> 8;
}

void convert_into_be32(uint16_t data, uint8_t *first, uint8_t *second,
		       uint8_t *third, uint8_t *fourth)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	uint32_t tmp = __builtin_bswap32(data);
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	uint32_t tmp = data;
#endif
	*first = tmp & 0xff;
	*second = tmp >> 8;
	*third = tmp >> 16;
	*fourth = tmp >> 24;
}


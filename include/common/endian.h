#ifndef __TCP_TUN_ENDIAN_H__
#define __TCP_TUN_ENDIAN_H__
#include <stdint.h>

uint16_t convert_from_be16(uint8_t *addr);
uint32_t convert_from_be32(uint8_t first, uint8_t second, uint8_t third,
			   uint8_t fourth);
void convert_into_be16(uint16_t data, uint8_t *addr);
void convert_into_be32(uint32_t data, uint8_t *first, uint8_t *second,
		       uint8_t *third, uint8_t *fourth);

#endif

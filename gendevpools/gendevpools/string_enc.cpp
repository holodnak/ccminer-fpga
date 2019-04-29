#include "string_enc.h"

#define XOR_KEY 0x1B

unsigned char char_encode(unsigned char ch)
{
	unsigned char ret = 0;

	ret = ch ^ XOR_KEY;
	return ret;
}

unsigned char char_decode(unsigned char ch)
{
	unsigned char ret = 0;

	ret = ch ^ XOR_KEY;
	return ret;
}

void string_encode(char *dst, char *src)
{
	int i;

	for (i = 0; src[i]; i++) {
		dst[i] = char_encode(src[i]);
	}
	dst[i] = 0;
}

void string_decode(char *dst, char *src)
{
	int i;

	for (i = 0; src[i]; i++) {
		dst[i] = char_decode(src[i]);
	}
	dst[i] = 0;
}

#include <ccminer-config.h>

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include <curl/curl.h>
#include <openssl/sha.h>

#include <Windows.h>

#include "miner.h"
#include "fpga.h"
#include "serial.h"
#include "algos.h"

// CRC parameters (default values are for CRC-32):

const int order = 16;
const unsigned long polynom = 0x1021;
const int direct = 0;
const unsigned long crcinit = 0xffffffff;
const unsigned long crcxor = 0x0;
const int refin = 0;
const int refout = 0;

// 'order' [1..32] is the CRC polynom order, counted without the leading '1' bit
// 'polynom' is the CRC polynom without leading '1' bit
// 'direct' [0,1] specifies the kind of algorithm: 1=direct, no augmented zero bits
// 'crcinit' is the initial CRC value belonging to that algorithm
// 'crcxor' is the final XOR value
// 'refin' [0,1] specifies if a data byte is reflected before processing (UART) or not
// 'refout' [0,1] specifies if the CRC will be reflected before XOR

// Data character string

const unsigned char string[] = { "123456789" };

// internal global values:

unsigned long crcmask;
unsigned long crchighbit;
unsigned long crcinit_direct;
unsigned long crcinit_nondirect;
unsigned long crctab[256];

// subroutines

static unsigned long reflect(unsigned long crc, int bitnum) {

	// reflects the lower 'bitnum' bits of 'crc'

	unsigned long i, j = 1, crcout = 0;

	for (i = (unsigned long)1 << (bitnum - 1); i; i >>= 1) {
		if (crc & i) crcout |= j;
		j <<= 1;
	}
	return (crcout);
}

static void generate_crc_table() {

	// make CRC lookup table used by table algorithms

	int i, j;
	unsigned long bit, crc;

	for (i = 0; i < 256; i++) {

		crc = (unsigned long)i;
		if (refin) crc = reflect(crc, 8);
		crc <<= order - 8;

		for (j = 0; j < 8; j++) {

			bit = crc & crchighbit;
			crc <<= 1;
			if (bit) crc ^= polynom;
		}

		if (refin) crc = reflect(crc, order);
		crc &= crcmask;
		crctab[i] = crc;
	}
}

static unsigned long crctablefast(unsigned char* p, unsigned long len) {

	// fast lookup table algorithm without augmented zero bytes, e.g. used in pkzip.
	// only usable with polynom orders of 8, 16, 24 or 32.

	unsigned long crc = crcinit_direct;

	if (refin) crc = reflect(crc, order);

	if (!refin) while (len--) crc = (crc << 8) ^ crctab[((crc >> (order - 8)) & 0xff) ^ *p++];
	else while (len--) crc = (crc >> 8) ^ crctab[(crc & 0xff) ^ *p++];

	if (refout ^ refin) crc = reflect(crc, order);
	crc ^= crcxor;
	crc &= crcmask;

	return(crc);
}

static unsigned long crctable(unsigned char* p, unsigned long len) {

	// normal lookup table algorithm with augmented zero bytes.
	// only usable with polynom orders of 8, 16, 24 or 32.

	unsigned long crc = crcinit_nondirect;

	if (refin) crc = reflect(crc, order);

	if (!refin) while (len--) crc = ((crc << 8) | *p++) ^ crctab[(crc >> (order - 8)) & 0xff];
	else while (len--) crc = ((crc >> 8) | (*p++ << (order - 8))) ^ crctab[crc & 0xff];

	if (!refin) while (++len < order / 8) crc = (crc << 8) ^ crctab[(crc >> (order - 8)) & 0xff];
	else while (++len < order / 8) crc = (crc >> 8) ^ crctab[crc & 0xff];

	if (refout ^ refin) crc = reflect(crc, order);
	crc ^= crcxor;
	crc &= crcmask;

	return(crc);
}

static unsigned long crcbitbybit(unsigned char* p, unsigned long len) {

	// bit by bit algorithm with augmented zero bytes.
	// does not use lookup table, suited for polynom orders between 1...32.

	unsigned long i, j, c, bit;
	unsigned long crc = crcinit_nondirect;

	for (i = 0; i < len; i++) {

		c = (unsigned long)* p++;
		if (refin) c = reflect(c, 8);

		for (j = 0x80; j; j >>= 1) {

			bit = crc & crchighbit;
			crc <<= 1;
			if (c & j) crc |= 1;
			if (bit) crc ^= polynom;
		}
	}

	for (i = 0; i < order; i++) {

		bit = crc & crchighbit;
		crc <<= 1;
		if (bit) crc ^= polynom;
	}

	if (refout) crc = reflect(crc, order);
	crc ^= crcxor;
	crc &= crcmask;

	return(crc);
}

static unsigned long crcbitbybitfast(unsigned char* p, unsigned long len) {

	// fast bit by bit algorithm without augmented zero bytes.
	// does not use lookup table, suited for polynom orders between 1...32.

	unsigned long i, j, c, bit;
	unsigned long crc = crcinit_direct;

	for (i = 0; i < len; i++) {

		c = (unsigned long)* p++;
		if (refin) c = reflect(c, 8);

		for (j = 0x80; j; j >>= 1) {

			bit = crc & crchighbit;
			crc <<= 1;
			if (c & j) bit ^= crchighbit;
			if (bit) crc ^= polynom;
		}
	}

	if (refout) crc = reflect(crc, order);
	crc ^= crcxor;
	crc &= crcmask;

	return(crc);
}

static bool crc_init = false;

void fpga2_crc_init()
{
	crcmask = ((((unsigned long)1 << (order - 1)) - 1) << 1) | 1;
	crchighbit = (unsigned long)1 << (order - 1);
	generate_crc_table();
	if (!direct) {

		int i;
		unsigned long bit, crc;

		crcinit_nondirect = crcinit;
		crc = crcinit;
		for (i = 0; i < order; i++) {

			bit = crc & crchighbit;
			crc <<= 1;
			if (bit) crc ^= polynom;
		}
		crc &= crcmask;
		crcinit_direct = crc;
	}

	else {

		int i;
		unsigned long bit, crc;

		crcinit_direct = crcinit;
		crc = crcinit;
		for (i = 0; i < order; i++) {

			bit = crc & 1;
			if (bit) crc ^= polynom;
			crc >>= 1;
			if (bit) crc |= crchighbit;
		}
		crcinit_nondirect = crc;
	}
	crc_init = true;
}

uint16_t fpga2_crc_calc(void* buf, int len)
{
	if (crc_init == false) {
		fpga2_crc_init();
	}
	return crcbitbybitfast((unsigned char*)buf, len);
}

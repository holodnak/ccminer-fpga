/*
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

//#include "cpuminer-config.h"
#include "miner.h"
#include "fpga.h"

#include <string.h>
#include <inttypes.h>

#if defined(USE_ASM) && \
	(defined(__x86_64__) || \
	 (defined(__arm__) && defined(__APCS_32__)) || \
	 (defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)))
#define EXTERN_SHA256
#endif

static const uint32_t sha256_h[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_init(uint32_t* state)
{
	memcpy(state, sha256_h, 32);
}

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define ROTR(x, n)      ((x >> n) | (x << (32 - n)))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k) \
	do { \
		t0 = h + S1(e) + Ch(e, f, g) + k; \
		t1 = S0(a) + Maj(a, b, c); \
		d += t0; \
		h  = t0 + t1; \
	} while (0)

/* Adjusted round function for rotating state */
#define RNDr(S, W, i) \
	RND(S[(64 - i) % 8], S[(65 - i) % 8], \
	    S[(66 - i) % 8], S[(67 - i) % 8], \
	    S[(68 - i) % 8], S[(69 - i) % 8], \
	    S[(70 - i) % 8], S[(71 - i) % 8], \
	    W[i] + sha256_k[i])

#ifndef EXTERN_SHA256

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void sha256_transform(uint32_t * state, const uint32_t * block, int swap)
{
	uint32_t W[64];
	uint32_t S[8];
	uint32_t t0, t1;
	int i;

	/* 1. Prepare message schedule W. */
	if (swap) {
		for (i = 0; i < 16; i++)
			W[i] = swab32(block[i]);
	}
	else
		memcpy(W, block, 64);
	for (i = 16; i < 64; i += 2) {
		W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i + 1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
	RNDr(S, W, 0);
	RNDr(S, W, 1);
	RNDr(S, W, 2);
	RNDr(S, W, 3);
	RNDr(S, W, 4);
	RNDr(S, W, 5);
	RNDr(S, W, 6);
	RNDr(S, W, 7);
	RNDr(S, W, 8);
	RNDr(S, W, 9);
	RNDr(S, W, 10);
	RNDr(S, W, 11);
	RNDr(S, W, 12);
	RNDr(S, W, 13);
	RNDr(S, W, 14);
	RNDr(S, W, 15);
	RNDr(S, W, 16);
	RNDr(S, W, 17);
	RNDr(S, W, 18);
	RNDr(S, W, 19);
	RNDr(S, W, 20);
	RNDr(S, W, 21);
	RNDr(S, W, 22);
	RNDr(S, W, 23);
	RNDr(S, W, 24);
	RNDr(S, W, 25);
	RNDr(S, W, 26);
	RNDr(S, W, 27);
	RNDr(S, W, 28);
	RNDr(S, W, 29);
	RNDr(S, W, 30);
	RNDr(S, W, 31);
	RNDr(S, W, 32);
	RNDr(S, W, 33);
	RNDr(S, W, 34);
	RNDr(S, W, 35);
	RNDr(S, W, 36);
	RNDr(S, W, 37);
	RNDr(S, W, 38);
	RNDr(S, W, 39);
	RNDr(S, W, 40);
	RNDr(S, W, 41);
	RNDr(S, W, 42);
	RNDr(S, W, 43);
	RNDr(S, W, 44);
	RNDr(S, W, 45);
	RNDr(S, W, 46);
	RNDr(S, W, 47);
	RNDr(S, W, 48);
	RNDr(S, W, 49);
	RNDr(S, W, 50);
	RNDr(S, W, 51);
	RNDr(S, W, 52);
	RNDr(S, W, 53);
	RNDr(S, W, 54);
	RNDr(S, W, 55);
	RNDr(S, W, 56);
	RNDr(S, W, 57);
	RNDr(S, W, 58);
	RNDr(S, W, 59);
	RNDr(S, W, 60);
	RNDr(S, W, 61);
	RNDr(S, W, 62);
	RNDr(S, W, 63);

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];
}

#endif /* EXTERN_SHA256 */


static const uint32_t sha256d_hash1[16] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000100
};

static void sha256d_80_swap(uint32_t * hash, const uint32_t * data)
{
	uint32_t S[16];
	int i;

	sha256_init(S);
	sha256_transform(S, data, 0);
	sha256_transform(S, data + 16, 0);
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	sha256_init(hash);
	sha256_transform(hash, S, 0);
	for (i = 0; i < 8; i++)
		hash[i] = swab32(hash[i]);
}

static void sha256d(unsigned char* hash, const unsigned char* data, int len)
{
	uint32_t S[16], T[16];
	int i, r;

	sha256_init(S);
	for (r = len; r > -9; r -= 64) {
		if (r < 64)
			memset(T, 0, 64);
		memcpy(T, data + len - r, r > 64 ? 64 : (r < 0 ? 0 : r));
		if (r >= 0 && r < 64)
			((unsigned char*)T)[r] = 0x80;
		for (i = 0; i < 16; i++)
			T[i] = be32dec(T + i);
		if (r < 56)
			T[15] = 8 * len;
		sha256_transform(S, T, 0);
	}
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	sha256_init(T);
	sha256_transform(T, S, 0);
	for (i = 0; i < 8; i++)
		be32enc((uint32_t*)hash + i, T[i]);
}

static inline void sha256d_preextend(uint32_t * W)
{
	W[16] = s1(W[14]) + W[9] + s0(W[1]) + W[0];
	W[17] = s1(W[15]) + W[10] + s0(W[2]) + W[1];
	W[18] = s1(W[16]) + W[11] + W[2];
	W[19] = s1(W[17]) + W[12] + s0(W[4]);
	W[20] = W[13] + s0(W[5]) + W[4];
	W[21] = W[14] + s0(W[6]) + W[5];
	W[22] = W[15] + s0(W[7]) + W[6];
	W[23] = W[16] + s0(W[8]) + W[7];
	W[24] = W[17] + s0(W[9]) + W[8];
	W[25] = s0(W[10]) + W[9];
	W[26] = s0(W[11]) + W[10];
	W[27] = s0(W[12]) + W[11];
	W[28] = s0(W[13]) + W[12];
	W[29] = s0(W[14]) + W[13];
	W[30] = s0(W[15]) + W[14];
	W[31] = s0(W[16]) + W[15];
}

static inline void sha256d_prehash(uint32_t * S, const uint32_t * W)
{
	uint32_t t0, t1;
	RNDr(S, W, 0);
	RNDr(S, W, 1);
	RNDr(S, W, 2);
}

#ifdef EXTERN_SHA256

void sha256d_ms(uint32_t * hash, uint32_t * W,
	const uint32_t * midstate, const uint32_t * prehash);

#else

static inline void sha256d_ms(uint32_t * hash, uint32_t * W,
	const uint32_t * midstate, const uint32_t * prehash)
{
	uint32_t S[64];
	uint32_t t0, t1;
	int i;

	S[18] = W[18];
	S[19] = W[19];
	S[20] = W[20];
	S[22] = W[22];
	S[23] = W[23];
	S[24] = W[24];
	S[30] = W[30];
	S[31] = W[31];

	W[18] += s0(W[3]);
	W[19] += W[3];
	W[20] += s1(W[18]);
	W[21] = s1(W[19]);
	W[22] += s1(W[20]);
	W[23] += s1(W[21]);
	W[24] += s1(W[22]);
	W[25] = s1(W[23]) + W[18];
	W[26] = s1(W[24]) + W[19];
	W[27] = s1(W[25]) + W[20];
	W[28] = s1(W[26]) + W[21];
	W[29] = s1(W[27]) + W[22];
	W[30] += s1(W[28]) + W[23];
	W[31] += s1(W[29]) + W[24];
	for (i = 32; i < 64; i += 2) {
		W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i + 1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	memcpy(S, prehash, 32);

	RNDr(S, W, 3);
	RNDr(S, W, 4);
	RNDr(S, W, 5);
	RNDr(S, W, 6);
	RNDr(S, W, 7);
	RNDr(S, W, 8);
	RNDr(S, W, 9);
	RNDr(S, W, 10);
	RNDr(S, W, 11);
	RNDr(S, W, 12);
	RNDr(S, W, 13);
	RNDr(S, W, 14);
	RNDr(S, W, 15);
	RNDr(S, W, 16);
	RNDr(S, W, 17);
	RNDr(S, W, 18);
	RNDr(S, W, 19);
	RNDr(S, W, 20);
	RNDr(S, W, 21);
	RNDr(S, W, 22);
	RNDr(S, W, 23);
	RNDr(S, W, 24);
	RNDr(S, W, 25);
	RNDr(S, W, 26);
	RNDr(S, W, 27);
	RNDr(S, W, 28);
	RNDr(S, W, 29);
	RNDr(S, W, 30);
	RNDr(S, W, 31);
	RNDr(S, W, 32);
	RNDr(S, W, 33);
	RNDr(S, W, 34);
	RNDr(S, W, 35);
	RNDr(S, W, 36);
	RNDr(S, W, 37);
	RNDr(S, W, 38);
	RNDr(S, W, 39);
	RNDr(S, W, 40);
	RNDr(S, W, 41);
	RNDr(S, W, 42);
	RNDr(S, W, 43);
	RNDr(S, W, 44);
	RNDr(S, W, 45);
	RNDr(S, W, 46);
	RNDr(S, W, 47);
	RNDr(S, W, 48);
	RNDr(S, W, 49);
	RNDr(S, W, 50);
	RNDr(S, W, 51);
	RNDr(S, W, 52);
	RNDr(S, W, 53);
	RNDr(S, W, 54);
	RNDr(S, W, 55);
	RNDr(S, W, 56);
	RNDr(S, W, 57);
	RNDr(S, W, 58);
	RNDr(S, W, 59);
	RNDr(S, W, 60);
	RNDr(S, W, 61);
	RNDr(S, W, 62);
	RNDr(S, W, 63);

	for (i = 0; i < 8; i++)
		S[i] += midstate[i];

	W[18] = S[18];
	W[19] = S[19];
	W[20] = S[20];
	W[22] = S[22];
	W[23] = S[23];
	W[24] = S[24];
	W[30] = S[30];
	W[31] = S[31];

	memcpy(S + 8, sha256d_hash1 + 8, 32);
	S[16] = s1(sha256d_hash1[14]) + sha256d_hash1[9] + s0(S[1]) + S[0];
	S[17] = s1(sha256d_hash1[15]) + sha256d_hash1[10] + s0(S[2]) + S[1];
	S[18] = s1(S[16]) + sha256d_hash1[11] + s0(S[3]) + S[2];
	S[19] = s1(S[17]) + sha256d_hash1[12] + s0(S[4]) + S[3];
	S[20] = s1(S[18]) + sha256d_hash1[13] + s0(S[5]) + S[4];
	S[21] = s1(S[19]) + sha256d_hash1[14] + s0(S[6]) + S[5];
	S[22] = s1(S[20]) + sha256d_hash1[15] + s0(S[7]) + S[6];
	S[23] = s1(S[21]) + S[16] + s0(sha256d_hash1[8]) + S[7];
	S[24] = s1(S[22]) + S[17] + s0(sha256d_hash1[9]) + sha256d_hash1[8];
	S[25] = s1(S[23]) + S[18] + s0(sha256d_hash1[10]) + sha256d_hash1[9];
	S[26] = s1(S[24]) + S[19] + s0(sha256d_hash1[11]) + sha256d_hash1[10];
	S[27] = s1(S[25]) + S[20] + s0(sha256d_hash1[12]) + sha256d_hash1[11];
	S[28] = s1(S[26]) + S[21] + s0(sha256d_hash1[13]) + sha256d_hash1[12];
	S[29] = s1(S[27]) + S[22] + s0(sha256d_hash1[14]) + sha256d_hash1[13];
	S[30] = s1(S[28]) + S[23] + s0(sha256d_hash1[15]) + sha256d_hash1[14];
	S[31] = s1(S[29]) + S[24] + s0(S[16]) + sha256d_hash1[15];
	for (i = 32; i < 60; i += 2) {
		S[i] = s1(S[i - 2]) + S[i - 7] + s0(S[i - 15]) + S[i - 16];
		S[i + 1] = s1(S[i - 1]) + S[i - 6] + s0(S[i - 14]) + S[i - 15];
	}
	S[60] = s1(S[58]) + S[53] + s0(S[45]) + S[44];

	sha256_init(hash);

	RNDr(hash, S, 0);
	RNDr(hash, S, 1);
	RNDr(hash, S, 2);
	RNDr(hash, S, 3);
	RNDr(hash, S, 4);
	RNDr(hash, S, 5);
	RNDr(hash, S, 6);
	RNDr(hash, S, 7);
	RNDr(hash, S, 8);
	RNDr(hash, S, 9);
	RNDr(hash, S, 10);
	RNDr(hash, S, 11);
	RNDr(hash, S, 12);
	RNDr(hash, S, 13);
	RNDr(hash, S, 14);
	RNDr(hash, S, 15);
	RNDr(hash, S, 16);
	RNDr(hash, S, 17);
	RNDr(hash, S, 18);
	RNDr(hash, S, 19);
	RNDr(hash, S, 20);
	RNDr(hash, S, 21);
	RNDr(hash, S, 22);
	RNDr(hash, S, 23);
	RNDr(hash, S, 24);
	RNDr(hash, S, 25);
	RNDr(hash, S, 26);
	RNDr(hash, S, 27);
	RNDr(hash, S, 28);
	RNDr(hash, S, 29);
	RNDr(hash, S, 30);
	RNDr(hash, S, 31);
	RNDr(hash, S, 32);
	RNDr(hash, S, 33);
	RNDr(hash, S, 34);
	RNDr(hash, S, 35);
	RNDr(hash, S, 36);
	RNDr(hash, S, 37);
	RNDr(hash, S, 38);
	RNDr(hash, S, 39);
	RNDr(hash, S, 40);
	RNDr(hash, S, 41);
	RNDr(hash, S, 42);
	RNDr(hash, S, 43);
	RNDr(hash, S, 44);
	RNDr(hash, S, 45);
	RNDr(hash, S, 46);
	RNDr(hash, S, 47);
	RNDr(hash, S, 48);
	RNDr(hash, S, 49);
	RNDr(hash, S, 50);
	RNDr(hash, S, 51);
	RNDr(hash, S, 52);
	RNDr(hash, S, 53);
	RNDr(hash, S, 54);
	RNDr(hash, S, 55);
	RNDr(hash, S, 56);

	hash[2] += hash[6] + S1(hash[3]) + Ch(hash[3], hash[4], hash[5])
		+ S[57] + sha256_k[57];
	hash[1] += hash[5] + S1(hash[2]) + Ch(hash[2], hash[3], hash[4])
		+ S[58] + sha256_k[58];
	hash[0] += hash[4] + S1(hash[1]) + Ch(hash[1], hash[2], hash[3])
		+ S[59] + sha256_k[59];
	hash[7] += hash[3] + S1(hash[0]) + Ch(hash[0], hash[1], hash[2])
		+ S[60] + sha256_k[60]
		+ sha256_h[7];
}

#endif /* EXTERN_SHA256 */


bool fulltest_blockstamp(const uint32_t* hash, const uint32_t* target);

#include <openssl/sha.h>

static SHA256_CTX sha256q_ctx;

static void sha256d_midstate(const void* input)
{
	SHA256_Init(&sha256q_ctx);

	//printf("sha256d_midstate:\n\n");
	//printData(sha256q_ctx.h, 32);
	//printDataFPGA(sha256q_ctx.h, 32);

	SHA256_Update(&sha256q_ctx, input, 64);
}

static void sha256d_hash(void* output, const void* input)
{
	uint32_t _ALIGN(64) hash[16];
	const int midlen = 64;            // bytes
	const int tail = 80 - midlen;   // 16

	SHA256_CTX ctx;

	memcpy(&ctx, &sha256q_ctx, sizeof sha256q_ctx);

	SHA256_Update(&ctx, ((unsigned char*)input) + midlen, tail);
	SHA256_Final((unsigned char*)hash, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final((unsigned char*)hash, &ctx);

	memcpy(output, hash, 32);
}

static void sha256d_fullhash(void* output, const void* input)
{
	uint32_t _ALIGN(64) hash[16];
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, ((unsigned char*)input), 80);
	SHA256_Final((unsigned char*)hash, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final((unsigned char*)hash, &ctx);

	memcpy(output, hash, 32);
}

extern volatile int is_acc, is_rej;

int scanhash_blockstampp(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;
	uint32_t hash[8], hash2[8];
	uint32_t midstate[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	uint32_t endiandata[32];

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	sha256d_midstate(endiandata);

	//midstate is sha256q_ctx.h, needs reverse, no bswap
	//memcpy(midstate, sha256q_ctx.h, 32);
	//reverse((unsigned char*)midstate, 32);

	do {
		if (is_acc || is_rej)
			applog(LOG_INFO, " Share Found."); is_acc = 0; is_rej = 0;

		pdata[19] = ++n;
		be32enc(&endiandata[19], pdata[19]);
		sha256d_hash(hash, endiandata);

		if ((hash[7] ^ 0x80000000) <= Htarg) {
			printf("share found? hash[7] = %08X\n", swab32(hash[7]));

			sha256d_80_swap(hash2, pdata);

			printf("hash: \n");
			printData(hash, 32);
			printDataFPGA(hash, 32);
			printf("hash2: \n");
			printData(hash2, 32);
			printDataFPGA(hash2, 32);

			printf("midstate: \n");
			printData((void*)midstate, 32);
			printDataFPGA((void*)midstate, 32);

			printf("ptarget: \n");
			printData((void*)ptarget, 32);

			printf("pdata: \n");
			printData(pdata, 80);
			printDataFPGA(pdata, 80);

			//system("pause");

			if (fulltest_blockstamp(hash, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				work->nonces[0] = pdata[19];
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

extern volatile int is_acc, is_rej;
extern volatile int cur_freq;
extern volatile double thr_hashrates[16];

int translate_freq(uint8_t fr);
int GetAcc();
int GetRej();

extern uint64_t global_hashrate;
extern bool less_difficult;
extern bool more_difficult;

/*
		uint32_t hash_be[8], target_be[8];
		char* hash_str, * target_str;

		for (i = 0; i < 8; i++) {
			be32enc(hash_be + i, hash[7 - i]);
			be32enc(target_be + i, target[7 - i]);
		}
		hash_str = bin2hex((uchar*)hash_be, 32);
		target_str = bin2hex((uchar*)target_be, 32);

		applog(LOG_DEBUG, "DEBUG: %s\nHash:   %s\nTarget: %s",
			rc ? "hash <= target"
			: "hash > target (false positive)",
			hash_str,
			target_str);
*/
int scanhash_blockstamp(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;
	uint32_t hash[8], hash2[8];
	uint32_t midstate[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int info_timeout;
	uint32_t my_target[8];

	unsigned char wbuf[52];
	uint32_t endiandata[32];

	info_timeout = 10;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	memcpy(my_target, work->target, 32);

	my_target[7] = 0;
	my_target[6] = 0xFFFFFFFF;

	sha256d_midstate(endiandata);

	//midstate is sha256q_ctx.h, needs reverse, no bswap
	memcpy(midstate, sha256q_ctx.h, 32);
	reverse((unsigned char*)midstate, 32);

	memcpy(wbuf, midstate, 32);
	memcpy(wbuf + 32, &endiandata[16], 16);
	memcpy(wbuf + 48, ((unsigned char*)& my_target[7]), 4);

	//bswap target
	bswap(wbuf + 48, 4);

	//reverse and bswap data (not nonce)
	bswap(wbuf + 32, 12);
	reverse(wbuf + 32, 12);

	//clear target to 0
	memset(wbuf + 48, 0, 4);

	//	printf("wbuf: \n");
	//	printData((char*)wbuf, 52);
	//	printDataFPGA((char*)wbuf, 52);

	//printf("target[6,7]: \n");
	//printData((char*)& work->target[6], 8);
	//printDataFPGA((char*)& work->target[6], 8);

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 52);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	size_t len;
	uint8_t buf[8];

	while (!work_restart[thr_id].restart) {
		memset(buf, 0, 8);

		ret = fpga_read(thr_info[thr_id].fd, (char*)buf, 8, &len);

		cgtime(&tv_end); timersub(&tv_end, &tv_start, &elapsed);

		int n = fpga_freq_check_keys(thr_info[thr_id].fd);

		if (n > 0) {
			//printf("Frequency changed, resending work.\n");
			Sleep(50);
			//fpga_send_start(thr_info[thr_id].fd);
			//fpga_send_data(thr_info[thr_id].fd, wbuf, 284);
		}
		else if (n == -1) {
			thr_info[thr_id].hw_err = 0;
			thr_info[thr_id].solutions = 0;
			applog(LOG_ERR, "Clearing solutions/errors.");
		}

		if (ret == 0 && len != 8) {		// No Nonce Found
			if (elapsed.tv_sec > info_timeout) {
				applog(LOG_ERR, "End Scan For Nonces - Time = %d sec", elapsed.tv_sec);
				//thr->work_restart = true;
				break;
			}
			continue;
		}

		else if (ret != 0) { //(ret < SERIAL_READ_SIZE) {
			applog(LOG_ERR, "Serial Read Error (ret=%d)", ret);
			//serial_fpga_close(thr);
			//dev_error(serial_fpga, REASON_DEV_COMMS_ERROR);
			break;
		}

		double error_pct;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)thr_info[thr_id].solutions * 100.0f;

		double vint, temp;

		uint32_t vt = *(uint32_t*)(&buf[4]);

		//chop off core id
		vt >>= 8;

		uint32_t vv, tt;

		vv = ((buf[7] << 0) | ((buf[6] & 0x0F) << 8)) << 4;
		tt = ((buf[5] << 4) | ((buf[6] & 0xF0) >> 4)) << 4;

		vint = ((double)vv) / 65536.0f * 3.0f;
		temp = (((double)tt) * 509.3140064f / 65536.0f) - 280.23087870f;

		double hr = ((double)global_hashrate + thr_hashrates[thr_id]) / 1000000.0f / 2.0f;

		char fstr[64];

		memset(fstr, 0, 64);
		if (cur_freq > 0)
			sprintf(fstr, "[%dMHz] ", cur_freq);

		//		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC", thr_id, vint, temp);
		if (is_acc || is_rej) {
			applog(LOG_INFO, "%sV: %0.2fv, T: %.1fC, Err: %.2f%% " CL_CYN "%.1f MH/s" CL_GR2 " Share Found." CL_N "", fstr, vint, temp, error_pct, hr);
		}
		else
			applog(LOG_INFO, "%sV: %0.2fv, T: %.1fC, Err: %.2f%% " CL_CYN "%.1f MH/s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", fstr, vint, temp, error_pct, hr, GetAcc(), GetAcc() + GetRej(), thr_info[thr_id].solutions - thr_info[thr_id].hw_err, thr_info[thr_id].hw_err);
		is_acc = 0;
		is_rej = 0;

		uint32_t nonce;

		memcpy((char*)& nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = (uint64_t)(nonce - first_nonce) & 0xFFFFFFFFULL;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;// +0x10000;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, nonce);


		pdata[19] = nonce;
		uint32_t hash_test[32];

		for (int l = 0; l < 20; l++)
			be32enc(&endiandata[l], pdata[l]);
		//bsha3_hash(hash_test, endiandata);
//		honeycomb_hash_new(hash_test, endiandata, 0);
		sha256d_fullhash(hash_test, endiandata);
		//printDataFPGA(hash_test, 32);
		//printDataFPGA((char*)& work->target[6], 8);
		//printDataFPGA((char*)& my_target[6], 8);

		//check for bad nonce
		if (fulltest_blockstamp(hash_test, my_target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "miner[%d] Nonce Invalid - Hardware Error, Nonce = %08X", thr_id, nonce);
			return 0;
		}

		if (fulltest_blockstamp(hash_test, work->target) == 0) {
			//thr_info[thr_id].hw_err++;
			//applog(LOG_INFO, "miner[%d] Nonce Invalid - Diff not high enough, Nonce = %08X", thr_id, swab32(nonce));
			return 0;
		}
		else {
			//applog(LOG_INFO, "miner[%d] Valid Nonce Found = %08X", thr_id, swab32(nonce));
			work->nonces[0] = pdata[19];
			return 1;
		}



		return 0;
	} 

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;


}

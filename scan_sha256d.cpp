#include "miner.h"
#include "fpga.h"

#include <io.h>
#include <string.h>
#include <inttypes.h>

#include <openssl/sha.h>

static __thread SHA256_CTX sha256q_ctx;

void sha256q_midstate(const void* input)
{
	SHA256_Init(&sha256q_ctx);

	//printf("start midstate:\n\n");
	//printData(sha256q_ctx.h, 32);
	//printDataFPGA(sha256q_ctx.h, 32);

	SHA256_Update(&sha256q_ctx, input, 64);
}

void sha256q_hash(void* output, const void* input)
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

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final((unsigned char*)hash, &ctx);

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, hash, 32);
	SHA256_Final((unsigned char*)hash, &ctx);

	memcpy(output, hash, 32);
}

#ifdef WIN32
#ifndef timersub
#define timersub(a, b, result)                     \
    do {                                               \
      (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;    \
      (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
      if ((result)->tv_usec < 0) {                     \
        --(result)->tv_sec;                            \
        (result)->tv_usec += 1000000;                  \
      }                                                \
    } while (0)
#endif
#ifndef timeradd
# define timeradd(a, b, result)            \
   do {                   \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;       \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;        \
    if ((result)->tv_usec >= 1000000)           \
      {                   \
  ++(result)->tv_sec;             \
  (result)->tv_usec -= 1000000;           \
      }                   \
   } while (0)
#endif
#endif
#define EPOCHFILETIME (116444736000000000LL)

void decius_time(lldiv_t *lidiv)
{
	FILETIME ft;
	LARGE_INTEGER li;

	GetSystemTimeAsFileTime(&ft);
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	li.QuadPart -= EPOCHFILETIME;

	/* SystemTime is in decimicroseconds so divide by an unusual number */
	*lidiv = lldiv(li.QuadPart, 10000000);
}

/* This is a sgminer gettimeofday wrapper. Since we always call gettimeofday
* with tz set to NULL, and windows' default resolution is only 15ms, this
* gives us higher resolution times on windows. */
void cgtime(struct timeval *tv)
{
	lldiv_t lidiv;

	decius_time(&lidiv);
	tv->tv_sec = lidiv.quot;
	tv->tv_usec = lidiv.rem / 10;
}

void bswap(unsigned char *b, int len)
{
	if ((len & 3) != 0) {
		printf("bswap error: len not multiple of 4\n");
		return;
	}

	while (len) {
		unsigned char t[4];

		t[0] = b[0];		t[1] = b[1];		t[2] = b[2];		t[3] = b[3];
		b[0] = t[3];		b[1] = t[2];		b[2] = t[1];		b[3] = t[0];
		b += 4;
		len -= 4;
	}
}

void reverse(unsigned char *b, int len)
{
	static unsigned char bt[1024];
	int i, j;

	if (len > 128) {
		system("pause");
		exit(0);
	}
	//	bt = (unsigned char*)malloc(len + 1);

	for (i = 0, j = len; i < len;) {
		bt[i++] = b[--j];
	}

	memcpy(b, bt, len);

	//	free(bt);
}

int scanhash_sha256q(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	unsigned char hash[64];
	unsigned char wbuf[52];
	uint32_t *pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];

	if (pdata[19] < 200)
		pdata[19] = 200;

	pdata[19] += 250;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	sha256q_midstate(endiandata);

	//copy midstate
	memcpy(wbuf, sha256q_ctx.h, 32);

	//copy data
	memcpy(wbuf + 32, &endiandata[16], 16);
	memcpy(wbuf + 48, ((unsigned char*)&work->target[6]), 4);

	//swap endian of data + nonce + target
	bswap(wbuf + 32, 20);

	//unswap nonce endian
	bswap(wbuf + 44, 4);

	//reverse midstate
	reverse(wbuf, 32);

	//reverse data
	reverse(wbuf + 32, 12);

#define SERIAL_READ_SIZE 8

	struct timeval tv_start, tv_finish, elapsed, tv_end, diff;
	int ret;

	int info_timeout;
	info_timeout = 10;

	_write(thr_info[thr_id].fd, wbuf, 52);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	size_t len;
	uint32_t first_nonce;

	first_nonce = pdata[19];

	//	applog(LOG_INFO, "FPGA: Begin Scan For Nonces at (first_nonce= %08X)", first_nonce);

	while ((!work_restart[thr_id].restart)) {

		memset(buf, 0, 8);

		// Check Serial Port For 1/10 Sec For Nonce  
		ret = serial_recv(thr_info[thr_id].fd, (char*)buf, 8, &len);

		// Calculate Elapsed Time
		cgtime(&tv_end);
		timersub(&tv_end, &tv_start, &elapsed);

		if (ret == 0 && len != 8) {		// No Nonce Found
			if (elapsed.tv_sec > info_timeout) {
				//				applog(LOG_ERR, "End Scan For Nonces - Time = %d sec", elapsed.tv_sec);
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

		uint32_t nonce;

		memcpy((char *)&nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = nonce - first_nonce;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;// +0x10000;
							  //		   applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		memcpy(&work->nonces[0], &nonce, 4);

		if(opt_debug)
			applog(LOG_INFO, "Nonce Found on miner[%d] - Nonce = %08X", thr_id, swab32(nonce));

		pdata[19] = nonce;

		return 1;

		// Update Hashrate
		//		if (serial_fpga->hw_errors == curr_hw_errors)
		//			info->Hs = ((double)(elapsed.tv_sec) + ((double)(elapsed.tv_usec)) / ((double)1000000)) / (double)nonce;

	}

	pdata[19] = 0xFFFFFFFF;
	//pdata[19] = pdata[19] + 1;
	*hashes_done = pdata[19] - first_nonce;

	//	applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

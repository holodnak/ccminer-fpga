#include "miner.h"
#include "fpga.h"
#include "scanhash.h"

#include <io.h>
#include <string.h>
#include <inttypes.h>

#include <openssl/sha.h>

static __thread SHA256_CTX sha256q_ctx;

static void sha256d_midstate(const void* input)
{
	SHA256_Init(&sha256q_ctx);

	//printf("start midstate:\n\n");
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

//int scanhash_sha256d_f(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
int scanhash_sha256d(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;

	/*
	uint32_t data[64];
	uint32_t hash[8];
	uint32_t midstate[8];
	uint32_t prehash[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];

	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);

	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	*/

	/*
	uint32_t endiandata[32];

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	sha256d_midstate(endiandata);

	do {
		data[3] = ++n;
		sha256d_ms(hash, data, midstate, prehash);
		if ((swab32(hash[7]) ^ 0x80000000) <= Htarg) {
			pdata[19] = data[3];
			sha256d_80_swap(hash, pdata);
			if (fulltest(hash, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return 1;
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;*/
	return 0;
}

int scanhash_sha256d_f(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	unsigned char wbuf[52];
	uint32_t *pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];

	if (pdata[19] < 200)
		pdata[19] = 200;

	pdata[19] += 250;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	sha256d_midstate(endiandata);

	//copy midstate
	memcpy(wbuf, sha256q_ctx.h, 32);

	//copy data
	memcpy(wbuf + 32, &endiandata[16], 16);
	memcpy(wbuf + 48, ((unsigned char*)&work->target[6]), 4);

	//swap endian of data + nonce + target
	//bswap(wbuf + 32, 20);

	//unswap nonce endian
	//bswap(wbuf + 44, 4);

	//reverse midstate
	//reverse(wbuf, 32);

	//reverse data
	//reverse(wbuf + 32, 12);

#define SERIAL_READ_SIZE 8

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	int info_timeout;
	info_timeout = 10;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 52);
//	_write(thr_info[thr_id].fd, wbuf, 52);

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
		ret = fpga_read(thr_info[thr_id].fd, (char*)buf, 8, &len);

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

		double error_pct;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)thr_info[thr_id].solutions * 100.0f;

		double vint, temp;

		vint = ((double)buf[7]) + (((double)buf[6]) * 256.0f);
		vint = vint / 65536.0f * 3.0f;
		temp = ((double)buf[5]) + (((double)buf[4]) * 256.0f);
		temp = (temp * 509.3140064f / 65536.0f) - 280.23087870f;

//		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC", thr_id, vint, temp);
		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC, Errors: %.3f%%", thr_id, vint, temp, error_pct);

		uint32_t nonce;

		memcpy((char *)&nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = nonce - first_nonce;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;// +0x10000;
							  //		   applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		if(opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, swab32(nonce));

		pdata[19] = nonce;


		uint32_t hash_test[32];

		for (int k = 0; k < 20; k++)
			be32enc(&endiandata[k], pdata[k]);
		sha256d_hash(hash_test, endiandata);
		if (fulltest(hash_test, work->target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "miner[%d] Nonce Invalid - Hardware Error", thr_id, swab32(nonce));
			return 0;
		}

		return 1;

	}

	pdata[19] = 0xFFFFFFFF;
	//pdata[19] = pdata[19] + 1;
	*hashes_done = pdata[19] - first_nonce;

	//	applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

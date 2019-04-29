/**
 * Phi1612 algo Implementation (initial LUX algo)
 */

#include <memory.h>

extern "C" {
	#include "sph/sph_skein.h"
	#include "sph/sph_jh.h"
	#include "sph/sph_cubehash.h"
	#include "sph/sph_fugue.h"
	#include "sph/sph_streebog.h"
	#include "sph/sph_echo.h"
}

#include "miner.h"
#include "fpga.h"
#include "scanhash.h"

void phi1612_midstate(void* midstate, const void* input)
{
	sph_skein512_context ctx_midstate;
	uint64_t* s = (uint64_t*)midstate;

	sph_skein512_init(&ctx_midstate);
	sph_skein512(&ctx_midstate, input, 80);

	s[0] = ctx_midstate.h0;
	s[1] = ctx_midstate.h1;
	s[2] = ctx_midstate.h2;
	s[3] = ctx_midstate.h3;
	s[4] = ctx_midstate.h4;
	s[5] = ctx_midstate.h5;
	s[6] = ctx_midstate.h6;
	s[7] = ctx_midstate.h7;
}

void phi1612_hash(void* state, const void* input)
{
	sph_skein512_context        ctx_skein;
	sph_jh512_context           ctx_jh;
	sph_cubehash512_context     ctx_cubehash;
	sph_fugue512_context        ctx_fugue;
	sph_gost512_context         ctx_gost;
	sph_echo512_context         ctx_echo;

	uint8_t _ALIGN(128) hash[64];

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, (void*)hash);

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, (const void*)hash, 64);
	sph_jh512_close(&ctx_jh, (void*)hash);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, (const void*)hash, 64);
	sph_cubehash512_close(&ctx_cubehash, (void*)hash);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*)hash, 64);
	sph_fugue512_close(&ctx_fugue, (void*)hash);

	sph_gost512_init(&ctx_gost);
	sph_gost512(&ctx_gost, (const void*)hash, 64);
	sph_gost512_close(&ctx_gost, (void*)hash);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*)hash, 64);
	sph_echo512_close(&ctx_echo, (void*)hash);

	memcpy(state, hash, 32);
}

void phi1612_hash_noisey(void* state, const void* input)
{
	sph_skein512_context        ctx_skein;
	sph_jh512_context           ctx_jh;
	sph_cubehash512_context     ctx_cubehash;
	sph_fugue512_context        ctx_fugue;
	sph_gost512_context         ctx_gost;
	sph_echo512_context         ctx_echo;

	uint8_t _ALIGN(128) hash[64];

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, (void*)hash);

	printf("skein512 hash:\n\n");
	printDataFPGA(hash, 64);

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, (const void*)hash, 64);
	sph_jh512_close(&ctx_jh, (void*)hash);

	printf("jh512 hash:\n\n");
	printDataFPGA(hash, 64);

	sph_cubehash512_init(&ctx_cubehash);
	sph_cubehash512(&ctx_cubehash, (const void*)hash, 64);
	sph_cubehash512_close(&ctx_cubehash, (void*)hash);

	printf("cube512 hash:\n\n");
	printDataFPGA(hash, 64);

	sph_fugue512_init(&ctx_fugue);
	sph_fugue512(&ctx_fugue, (const void*)hash, 64);
	sph_fugue512_close(&ctx_fugue, (void*)hash);

	printf("fugue512 hash:\n\n");
	printDataFPGA(hash, 64);

	sph_gost512_init(&ctx_gost);
	sph_gost512(&ctx_gost, (const void*)hash, 64);
	sph_gost512_close(&ctx_gost, (void*)hash);

	printf("gost512 hash:\n\n");
	printDataFPGA(hash, 64);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, (const void*)hash, 64);
	sph_echo512_close(&ctx_echo, (void*)hash);

	printf("echo512 hash:\n\n");
	printDataFPGA(hash, 64);

	memcpy(state, hash, 32);
}

int scanhash_phi1612_c(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;
	uint64_t midstate[8];

	/*
		uint32_t newdata[20] = {
			0x00000003, 0xD1309985, 0xD1577A21, 0xCB059779,
			0x772857F2, 0x9716EC56, 0xE43EBDCA, 0x010FB4D1,
			0x00000000, 0x8F66C7B9, 0xCC209869, 0x90FF7085,
			0xEFD0ED70, 0xB9C38BFC, 0xB31F0989, 0xDE168655,
			0xE72511AB, 0x5C7DD9C2, 0x1C0603CA, 0x5DC50900
		};

		uint32_t newdata_swap[20];

		for (int i = 0; i < 20; i++) {
			newdata_swap[i] = bswap_32(newdata[i]);
		}

		pdata = newdata_swap;
		*/

	if(opt_benchmark)
	{
		ptarget[7] = 0x00ff0;
	}

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t n = first_nonce;

	for (int i = 0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], n);

		phi1612_hash(hash, endiandata);

		if (hash[7] < Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;

			phi1612_midstate(midstate, endiandata);
			phi1612_hash_noisey(hash, endiandata);

			printf("\n\nfound ptarget:\n\n");
			printData(&ptarget[6], 8);

			printf("found midstate:\n\n");
			printData(midstate, 64);
			printDataFPGA(midstate, 64);

			printf("found hash:\n\n");
			printData(hash, 32);

			printf("found endian data:\n\n");
			printData(endiandata, 80);
			printDataFPGA(endiandata, 80);
			printf("\n\n");

			printf("found pdata:\n\n");
			printData(pdata, 80);
			printDataFPGA(pdata, 80);
			printf("\n\n");

			system("pause");

			return 1;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

int scanhash_phi1612(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	unsigned char wbuf[84];
	uint32_t* pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];
	uint32_t hash_test[64];
	uint32_t midstate[32];



	
/*	uint32_t newdata[20] = {
		0x00000003, 0xD1309985, 0xD1577A21, 0xCB059779,
		0x772857F2, 0x9716EC56, 0xE43EBDCA, 0x010FB4D1,
		0x00000000, 0x8F66C7B9, 0xCC209869, 0x90FF7085,
		0xEFD0ED70, 0xB9C38BFC, 0xB31F0989, 0xDE168655,
		0xE72511AB, 0x5C7DD9C2, 0x1C0603CA, 0x5DC50900
	};

	uint32_t newdata_swap[20];

	for (int i = 0; i < 20; i++) {
		newdata_swap[i] = bswap_32(newdata[i]);
	}

	pdata = newdata_swap;
	*/


	//kludge to keep nonce higher
	//if (pdata[19] < 1000)
	//	pdata[19] = 1000;

	//pdata[19] += 250;

	//////////////////////////////////////////////////////////////////
	//prepare data

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	phi1612_midstate(midstate, endiandata);

	//copy midstate
	memcpy(wbuf, midstate, 64);
	//reverse(wbuf, 64);
	bswap64(wbuf, 64);

	//copy data
	memcpy(wbuf + 64, &endiandata[16], 16);
	reverse(wbuf + 64, 12);
	//Bswap(wbuf + 64, 12);

	//copy target
	wbuf[80] = ((unsigned char*)work->target)[0x1F - 0];
	wbuf[81] = ((unsigned char*)work->target)[0x1E - 0];
	wbuf[82] = ((unsigned char*)work->target)[0x1D - 0];
	wbuf[83] = ((unsigned char*)work->target)[0x1C - 0];
/*
	printf("\n\nfound ptarget:\n\n");
	printData(&(((unsigned char*)work->target)[6*4]), 8);

	printData(wbuf, 84);
	printDataFPGA(wbuf, 84);
	system("pause");*/

	////////////////////////////////////////////////////////////////////
	//find nonce

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	int info_timeout;
	info_timeout = 10;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 84);

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

		double error_pct, vint, temp;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)thr_info[thr_id].solutions * 100.0f;

		vint = ((double)buf[7]) + (((double)buf[6]) * 256.0f);	vint = vint / 65536.0f * 3.0f;
		temp = ((double)buf[5]) + (((double)buf[4]) * 256.0f);	temp = (temp * 509.3140064f / 65536.0f) - 280.23087870f;

		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC, Errors: %.3f%%", thr_id, vint, temp, error_pct);

		uint32_t nonce;

		memcpy((char*)& nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = nonce - first_nonce;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;
			applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, swab32(nonce));

		pdata[19] = nonce;

		for (int k = 0; k < 20; k++)
			be32enc(&endiandata[k], pdata[k]);
		phi1612_hash(hash_test, endiandata);
		if (fulltest(hash_test, work->target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "miner[%d] Nonce Invalid - Hardware Error (%08X)", thr_id, swab32(nonce));
			return 0;
		}
		else applog(LOG_INFO, "miner[%d] Valid Nonce Found = %08X", thr_id, swab32(nonce));

		return 1;

	}

	pdata[19] = 0xFFFFFFFF;
	//pdata[19] = pdata[19] + 1;
	*hashes_done = pdata[19] - first_nonce;

	applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

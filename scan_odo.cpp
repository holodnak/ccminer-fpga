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

#include "odo/odocrypt.h"
extern "C" {
#include "odo/KeccakP-800-SnP.h"
}

static void odo_hash(void* output, const void* input, uint32_t key)
{
	char cipher[KeccakP800_stateSizeInBytes] = {};

	size_t len = 80;// (pend - pbegin) * sizeof(pbegin[0]);
	memcpy(cipher, input, len);
	cipher[len] = 1;

	OdoCrypt(key).Encrypt(cipher, cipher);
	KeccakP800_Permute_12rounds(cipher);
	memcpy(output, cipher, 32);

}

extern volatile int is_acc, is_rej;
extern volatile int cur_freq;
extern volatile double thr_hashrates[16];

int translate_freq(uint8_t fr);
int GetAcc();
int GetRej();

extern uint64_t odocrypt_current_key;
extern uint64_t global_hashrate;
extern bool less_difficult;
extern bool more_difficult;
extern bool detect_sqrl;

static char* make_coreid(int n)
{
	static char buf[32];

	int n1, n2;

	n2 = n & 0x3f;
	n1 = n >> 6;

	sprintf(buf, "%d:%d", n1, n2);

	return buf;
}

extern char active_dna[];

/*

hash7 = 0000FCB3
edata = 111200001B02DAB65D3729FE5680B51E7ED3A01D9509A74541423EBA4E1F0E753AD74A61E8574CE376F7FD7B0000000000000003650DE45BBED33E6A0FCCA528D81B5AEF8D835AECAE1AC30C20000E02
020E0020 0CC31AAE - EC5A838D EF5A1BD8
28A5CC0F 6A3ED3BE - 5BE40D65 03000000
00000000 7BFDF776 - E34C57E8 614AD73A
750E1F4E BA3E4241 - 45A70995 1DA0D37E
1EB58056 FE29375D - B6DA021B 00001211

pdata = 00001211B6DA021BFE29375D1EB580561DA0D37E45A70995BA3E4241750E1F4E614AD73AE34C57E87BFDF77600000000030000005BE40D656A3ED3BE28A5CC0FEF5A1BD8EC5A838D0CC31AAE020E0020
20000E02 AE1AC30C - 8D835AEC D81B5AEF
0FCCA528 BED33E6A - 650DE45B 00000003
00000000 76F7FD7B - E8574CE3 3AD74A61
4E1F0E75 41423EBA - 9509A745 7ED3A01D
5680B51E 5D3729FE - 1B02DAB6 11120000

*/


int scanhash_odoc(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
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

	uint32_t my_data[20] = {
		0x20000E02, 0xAE1AC30C, 0x8D835AEC, 0xD81B5AEF,
		0x0FCCA528, 0xBED33E6A, 0x650DE45B, 0x00000003,
		0x00000000, 0x76F7FD7B, 0xE8574CE3, 0x3AD74A61,
		0x4E1F0E75, 0x41423EBA, 0x9509A745, 0x7ED3A01D,
		0x5680B51E, 0x5D3729FE, 0x1B02DAB6, 0x11120000
	};

	unsigned char wbuf[84];
	uint32_t endiandata[32];

	info_timeout = 60;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], bswap_32(my_data[k]));

	while (!work_restart[thr_id].restart) {

		odo_hash(hash2, endiandata, odocrypt_current_key);


		if (hash2[7] < 0x0000ffff) {
			printf("hash7 = %08X\n", hash2[7]);
			printf("edata = "); printDataFPGA(endiandata, 80); printData(endiandata, 80);
			printf("pdata = "); printDataFPGA(my_data, 80); printData(my_data, 80);
			system("pause");
			return 1;
		}

		pdata[19]++;
		be32enc(&endiandata[19], pdata[19]);

	}

	return 0;
}

class Thing {
private:
	int *arr;
	int pos;
	int count;
	int max;
public:
	Thing(int maxcount) {
		pos = 0;
		count = 0;
		max = maxcount;
		arr = new int[max];
	}
	~Thing() {
		delete[] arr;
	}
	void Add(int n) {
		arr[pos++] = n;
		if (pos == max)
			pos = 0;
		if (count < max) {
			count++;
		}
	}
	void Clear() {
		pos = 0;
		count = 0;
	}
	__int64 GetSum() {
		__int64 n, i;

		for (n = 0, i = 0; i < count; i++) {
			n += (__int64)arr[i];
		}
		return(n);
	}
	int GetAvg() {
		return(count <= 0 ? -1 : GetSum() / count);
	}
};

class Hashrate {
private:
	Thing hr;
public:
	Hashrate(int avg_count):hr(avg_count) {
	}
	void Add(int n) {
		if (n > 20000)	//cutoff, 20GH is too the limit
			n = 20000 / 4;
		hr.Add(n);
	}
	void Clear() {
		hr.Clear();
	}
	int Get() {
		return hr.GetAvg();
	}
};

extern bool opt_discover_key;

int scanhash_odo(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
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
	static int megahashes = 1;
	static Hashrate hashrate(25);

	unsigned char wbuf[84];
	uint32_t endiandata[32];

	info_timeout = 60;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	less_difficult = true;
	memcpy(my_target, work->target, 32);
	my_target[7] = 0;
	my_target[6] = 0x7FFFFFFF;
	if (less_difficult)
		my_target[6] = 0xFFFFFFFF;
	else if (more_difficult)
		my_target[6] = 0x3FFFFFFF;

	memcpy(wbuf, endiandata, 80);
	memcpy(wbuf + 80, ((unsigned char*)& my_target[6]), 4);

	//bswap target
	bswap(wbuf + 80, 4);

	//reverse and bswap data (not nonce)
	//bswap(wbuf, 76);
	reverse(wbuf, 76);

	//bswap nonce
	bswap(wbuf + 76, 4);


	struct timeval tv_start, elapsed, tv_end;
	int ret;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 84);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	//size_t len;
	uint8_t buf[10];

	//applog(LOG_INFO, "Starting nonce = %08X", swab32(first_nonce));
	//printf("wbuf: "); printDataFPGA(wbuf, 84);

#define GC(xx,yy) (((xx) << 6) | (yy))
#define CSOLS(xx,yy) ( thr_info[thr_id].cid_sols[ GC(xx,yy) ] )
#define CERRS(xx,yy) ( thr_info[thr_id].cid_errs[ GC(xx,yy) ] )
#define CSOLSs(xx,yy) (CSOLS(xx,yy) + CERRS(xx,yy))

	uint32_t fivecores = CSOLSs(0, 4) + CSOLSs(1, 4) + CSOLSs(1, 4);
	uint32_t fourcores = CSOLSs(0, 3) + CSOLSs(1, 3) + CSOLSs(1, 3) + fivecores;
	uint32_t threecores = CSOLSs(0, 2) + CSOLSs(1, 2) + CSOLSs(1, 2) + fourcores;
	uint32_t twocores = CSOLSs(0, 1) + CSOLSs(1, 1) + CSOLSs(1, 1) + threecores;
	uint32_t onecore2 = CSOLSs(2, 0) + twocores;
	uint32_t onecore1 = CSOLSs(1, 0) + onecore2;

	while (!work_restart[thr_id].restart) {

		//////////////////////////////////////////////////

		int r2 = fpga_freq_check_keys(thr_info[thr_id].fd);

		if (r2) {
			r2 = tolower(r2);
			switch (r2) {
			case 'r':
				applog(LOG_INFO, "==< Device Info >==================================================");
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Device DNA: %s", active_dna);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Bitstream Version: %02X.%02X", thr_info[thr_id].fpga_info.version, thr_info[thr_id].fpga_info.userbyte);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "==< Share Info >===================================================");
				applog(LOG_INFO, "");
				applog(LOG_INFO, "     Accepted: %14d             Solutions: %14d", GetAcc(), thr_info[thr_id].solutions);
				applog(LOG_INFO, "     Rejected: %14d             Errors   : %14d", GetRej(), thr_info[thr_id].hw_err);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Group 0:  Core 0: %8d (errors: %d)", CSOLS(0, 0), CERRS(0, 0));
				if (twocores)applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(0, 1), CERRS(0, 1));
				if (threecores)applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(0, 2), CERRS(0, 2));
				if (fourcores)applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(0, 3), CERRS(0, 3));
				if (fivecores)applog(LOG_INFO, "             Core 4: %8d (errors: %d)", CSOLS(0, 3), CERRS(0, 3));
				if (onecore1)applog(LOG_INFO, "");
				if (onecore1)applog(LOG_INFO, "   Group 1:  Core 0: %8d (errors: %d)", CSOLS(1, 0), CERRS(1, 0));
				if (twocores)applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(1, 1), CERRS(1, 1));
				if (threecores)applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(1, 2), CERRS(1, 2));
				if (fourcores)applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(1, 3), CERRS(1, 3));
				if (fivecores)applog(LOG_INFO, "             Core 4: %8d (errors: %d)", CSOLS(1, 3), CERRS(1, 3));
				if (onecore2)applog(LOG_INFO, "");
				if (onecore2)applog(LOG_INFO, "   Group 2:  Core 0: %8d (errors: %d)", CSOLS(2, 0), CERRS(2, 0));
				if (twocores)applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(2, 1), CERRS(2, 1));
				if (threecores)applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(2, 2), CERRS(2, 2));
				if (fourcores)applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(2, 3), CERRS(2, 3));
				if (fivecores)applog(LOG_INFO, "             Core 4: %8d (errors: %d)", CSOLS(2, 3), CERRS(2, 3));
				applog(LOG_INFO, "");
				applog(LOG_INFO, "===================================================================");
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   There has been %d serial CRC errors in data received from the FPGA.", thr_info[thr_id].crc_err);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "===================================================================");
				break;
			case 'c':
				thr_info[thr_id].hw_err = 0;
				thr_info[thr_id].solutions = 0;
				thr_hashrates[thr_id] = 0;
				applog(LOG_INFO, "Clearing solutions/errors.");
				break;
			}
		}

		//////////////////////////////////////////////////

		memset(buf, 0, 8);

		//read response from fpga
		ret = fpga2_recv_response(thr_info[thr_id].fd, buf);

		cgtime(&tv_end); timersub(&tv_end, &tv_start, &elapsed);

		if (ret == 0) {		// No Nonce Found
			if (elapsed.tv_sec > info_timeout) {
				applog(LOG_ERR, "End Scan For Nonces - Time = %d sec", elapsed.tv_sec);
				//thr->work_restart = true;
				break;
			}
			continue;
		}

		else if (ret == -1) {
			applog(LOG_ERR, "Serial Read Error (ret=%d), need to exit.", ret);
			Sleep(2000);
			//serial_fpga_close(thr);
			//dev_error(serial_fpga, REASON_DEV_COMMS_ERROR);
			break;
		}

		else if (ret == -2) {
			size_t len2 = 0;
			applog(LOG_ERR, "Serial CRC Error.");
			thr_info[thr_id].crc_err++;
			char buf2[1024];
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			Sleep(1000);
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			Sleep(1000);
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			break;
		}

		double error_pct;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)(thr_info[thr_id].solutions + thr_info[thr_id].hw_err) * 100.0f;

		double vint, temp;

		uint32_t vt = *(uint32_t*)(&buf[4]);
		uint8_t cid = vt & 0xFF; //top 3 bits are SLR, lower are core number

		//chop off core id
		vt >>= 8;

		uint32_t vv, tt;

		vv = ((buf[7] << 0) | ((buf[6] & 0x0F) << 8)) << 4;
		tt = ((buf[5] << 4) | ((buf[6] & 0xF0) >> 4)) << 4;

		vint = ((double)vv) / 65536.0f * 3.0f;
		temp = (((double)tt) * 509.3140064f / 65536.0f) - 280.23087870f;

		double hr = ((double)thr_hashrates[thr_id]) / 1000000.0f;
		char hr_unit = 'M';

		hashrate.Add((int)hr);

		hr = (double)hashrate.Get();

		if (hr > 1000.0f || megahashes == 0) {
			megahashes = 0;
			hr /= 1000.0f;
			hr_unit = 'G';
		}

		char fstr[128];

		memset(fstr, 0, 128);

		if (cur_freq > 0)
			sprintf(fstr, "[%s: %dMHz %0.2fv %dc] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, cur_freq, vint, (int)temp, hr, hr_unit, error_pct);
		else
			sprintf(fstr, "[%s: %0.2fv %dc] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, vint, (int)temp, hr, hr_unit, error_pct);

		if (is_acc || is_rej) {
			if (is_rej)
				applog(LOG_INFO, "%s" CL_LRD " Share %s." CL_N "", fstr, "Rejected");
			else
				applog(LOG_INFO, "%s" CL_GR2 " Share %s." CL_N "", fstr, "Accepted");
		}

		is_acc = 0;
		is_rej = 0;

		uint32_t nonce;

		memcpy((char*)& nonce, buf, 4);

		//version 2
		nonce = (nonce << 16) | (nonce >> 16);

		//nonce = swab32(nonce);// -89;

		if (swab32(nonce) > swab32(first_nonce))
			* hashes_done = (uint64_t)(swab32(nonce) - swab32(first_nonce)) & 0xFFFFFFFFULL;

		//???
		else
			*hashes_done = (uint64_t)(swab32(first_nonce) - swab32(nonce)) & 0xFFFFFFFFULL;

		//applog(LOG_INFO, CL_LGR "Nonce = %08X (first_nonce = %08x, hashes_done = %lld", swab32(nonce), swab32(first_nonce), *hashes_done);

		if (nonce == 0xFFFFFFFF) {
			applog(LOG_INFO, "%s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", fstr, GetAcc(), GetRej(), thr_info[thr_id].solutions, thr_info[thr_id].hw_err);
			pdata[19] = nonce;// +0x10000;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, nonce);

		uint32_t hash_test[32];

		pdata[19] = nonce;//not swapped!!

		for (int l = 0; l < 20; l++)
			be32enc(&endiandata[l], pdata[l]);

		odo_hash(hash_test, endiandata, odocrypt_current_key);

		//check for bad nonce
		if (fulltest(hash_test, my_target) == 0) {
			thr_info[thr_id].hw_err++;
			thr_info[thr_id].cid_errs[cid]++;
			//applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Hardware Error, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));

			if (detect_sqrl && ((rand() & 0x7) == 0)) {
				double fah = temp * 9.0f / 5.0f + 32;
				//applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Squirrel Detected, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
				applog(LOG_INFO, "%s" CL_LRD " Squirrel Detected, core %s" CL_N "", fstr, make_coreid(cid));
			}
			else {
				applog(LOG_INFO, "%s" CL_LRD " Hardware Error, core %s" CL_N "", fstr, make_coreid(cid));
			}

			return 0;
		}

		thr_info[thr_id].solutions++;
		thr_info[thr_id].cid_sols[cid]++;

		if (fulltest(hash_test, work->target) == 0) {
			applog(LOG_INFO, "%s" CL_YL2 " Solution Found, core %s" CL_N "", fstr, make_coreid(cid));
			return 0;
		}
		else {
			applog(LOG_INFO, "%s" CL_LBL " Share Found, core %s" CL_N "", fstr, make_coreid(cid));
			work->nonces[0] = pdata[19];
			return 1;
		}

		return 0;
	}

	*hashes_done = 0;
	pdata[19] = n;
	return 0;

}



int scanhash_odo2(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
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
	static int megahashes = 1;
	static Hashrate hashrate(25);

	unsigned char wbuf[84];
	uint32_t endiandata[32];

	info_timeout = 60;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	less_difficult = true;
	memcpy(my_target, work->target, 32);
	my_target[7] = 0x0000000F;
	my_target[6] = 0x7FFFFFFF;
	if (less_difficult)
		my_target[6] = 0xFFFFFFFF;
	else if (more_difficult)
		my_target[6] = 0x3FFFFFFF;

	memcpy(wbuf, endiandata, 80);
	memcpy(wbuf + 80, ((unsigned char*)& my_target[7]), 4);

	//bswap target
	bswap(wbuf + 80, 4);

	//reverse and bswap data (not nonce)
	//bswap(wbuf, 76);
	reverse(wbuf, 76);

	//bswap nonce
	bswap(wbuf + 76, 4);

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 84);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	//size_t len;
	uint8_t buf[10];

	//applog(LOG_INFO, "Starting nonce = %08X", swab32(*((uint32_t*)(wbuf + 76))));
	//printf("wbuf: "); printDataFPGA(wbuf, 84);

#define GC(xx,yy) (((xx) << 6) | (yy))
#define CSOLS(xx,yy) ( thr_info[thr_id].cid_sols[ GC(xx,yy) ] )
#define CERRS(xx,yy) ( thr_info[thr_id].cid_errs[ GC(xx,yy) ] )
#define CSOLSs(xx,yy) (CSOLS(xx,yy) + CERRS(xx,yy))

	uint32_t fivecores = CSOLSs(0, 4) + CSOLSs(1, 4) + CSOLSs(1, 4);
	uint32_t fourcores = CSOLSs(0, 3) + CSOLSs(1, 3) + CSOLSs(1, 3) + fivecores;
	uint32_t threecores = CSOLSs(0, 2) + CSOLSs(1, 2) + CSOLSs(1, 2) + fourcores;
	uint32_t twocores = CSOLSs(0, 1) + CSOLSs(1, 1) + CSOLSs(1, 1) + threecores;
	uint32_t onecore2 = CSOLSs(2, 0) + twocores;
	uint32_t onecore1 = CSOLSs(1, 0) + onecore2;

	int start = time(0) - 3;

	static char str_health[128];
	static double vint = 0, temp = 0;

	sprintf(str_health, "[%s: %dMHz %.0fC %.2fV]", active_dna, cur_freq, temp, vint);

	while (!work_restart[thr_id].restart) {

		int now = time(0);

		int r2 = fpga_freq_check_keys(thr_info[thr_id].fd);

		memset(buf, 0, 8);

		//read response from fpga
		ret = fpga2_recv_response(thr_info[thr_id].fd, buf);

		cgtime(&tv_end); timersub(&tv_end, &tv_start, &elapsed);

		if (ret == 0) {		// No Nonce Found
			if ((now - start) >= 3) {
				//LOG_INFO("updating temp/vint. (now=%d, start=%d, diff=%d)", now, start, now - start);
				uint8_t cmd = 0x01;

				//check = now;
				//fpga_get_health(fd, &temp, &vint);

				/* the following is a nasty kludge due to not having a
				   packet ID in the data returned from the FPGA.  the packet
				   could be a valid nonce, or the response of the "get health"
				   command.  to work around this, the first 40 bits of the
				   "get health" response are currently zero, so we check for that.
				*/

				//write "get health" command
				fpga_write(thr_info[thr_id].fd, &cmd, 1);

				//consumeJob();
				start = time(0);
				//break;
			}

			if (elapsed.tv_sec > info_timeout) {
				applog(LOG_ERR, "End Scan For Nonces - Time = %d sec", elapsed.tv_sec);
				//thr->work_restart = true;
				break;
			}

			continue;
		}

		else if (ret == -1) {
			applog(LOG_ERR, "Serial Read Error (ret=%d), need to exit.", ret);
			Sleep(2000);
			//serial_fpga_close(thr);
			//dev_error(serial_fpga, REASON_DEV_COMMS_ERROR);
			break;
		}

		else if (ret == -2) {
			size_t len2 = 0;
			applog(LOG_ERR, "Serial CRC Error.");
			thr_info[thr_id].crc_err++;
			char buf2[1024];
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			Sleep(1000);
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			Sleep(1000);
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			break;
		}


		bool is_health = (buf[0] == 0) && (buf[1] == 0) && (buf[2] == 0) && (buf[3] == 0) && (buf[4] == 0);

		double hr = ((double)thr_hashrates[thr_id]) / 1000000.0f;
		char hr_unit = 'M';

		hashrate.Add((int)hr);

		hr = (double)hashrate.Get();

		if (hr > 1000.0f || megahashes == 0) {
			megahashes = 0;
			hr /= 1000.0f;
			hr_unit = 'G';
		}

		if (is_health) {
			uint32_t vv, tt;

			vv = ((buf[7] << 0) | ((buf[6] & 0x0F) << 8)) << 4;
			tt = ((buf[5] << 4) | ((buf[6] & 0xF0) >> 4)) << 4;
			vint = ((double)vv) / 65536.0f * 3.0f;
			temp = (((double)tt) * 509.3140064f / 65536.0f) - 280.23087870f;

			{
				//double hr_gh = Workers::GetHr10() / 1000000000.0f;

				sprintf(str_health, "[%s: %dMHz %.0fC %.2fV]", active_dna, cur_freq, temp, vint);
				//if (strlen(str_hashrate) > 0)
				//applog(LOG_INFO, "%s " CL_CYN "%3.1f %cH/s " CL_LCY " Acc/Rej: %d/%d  Sol/Err: %d/%d", str_health, hr, hr_unit, GetAcc(), GetRej(), thr_info[thr_id].solutions, thr_info[thr_id].hw_err);
			}

			//sprintf(str_health, "[%s: %dMHz %.0fC %.2fV]", dna, cur_freq, temp, vint);
			//if (strlen(str_hashrate) > 0)
			//	applog(LOG_INFO, "%s %s" CL_LCY " Acc/Rej: %d/%d  Sol/Err: %d/%d", str_health, str_hashrate, accepted, rejected, solutions, errors);
			continue;
		}

		//printf("recv: "); printDataFPGA(buf, 8);

		double error_pct;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)(thr_info[thr_id].solutions + thr_info[thr_id].hw_err) * 100.0f;


		if (is_acc || is_rej) {
			if (is_rej)
				applog(LOG_INFO, "%s" CL_LRD " Share %s." CL_N "", str_health, "Rejected");
			else
				applog(LOG_INFO, "%s" CL_GR2 " Share %s." CL_N "", str_health, "Accepted");
		}

		is_acc = 0;
		is_rej = 0;

		uint32_t nonce;

		memcpy((char*)& nonce, buf+4, 4);

		//version 2
		//nonce = (nonce << 16) | (nonce >> 16);

		//nonce = swab32(nonce);// -89;

		if (swab32(nonce) > swab32(first_nonce))
			* hashes_done = (uint64_t)(swab32(nonce) - swab32(first_nonce)) & 0xFFFFFFFFULL;

		//???
		else
			*hashes_done = (uint64_t)(swab32(first_nonce) - swab32(nonce)) & 0xFFFFFFFFULL;

		//applog(LOG_INFO, CL_LGR "Nonce = %08X (first_nonce = %08x, hashes_done = %lld", swab32(nonce), swab32(first_nonce), *hashes_done);

		if (nonce == 0xFFFFFFFF) {
			applog(LOG_INFO, "%s " CL_CYN "%3.1f %cH/s "  CL_N "Err: %.1f%% " CL_LCY " Acc/Rej: %d/%d  Sol/Err: %d/%d", str_health, hr, hr_unit, error_pct, GetAcc(), GetRej(), thr_info[thr_id].solutions, thr_info[thr_id].hw_err);
			//applog(LOG_INFO, "%s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", str_health, GetAcc(), GetRej(), thr_info[thr_id].solutions, thr_info[thr_id].hw_err);
			pdata[19] = nonce;// +0x10000;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, nonce);

		uint32_t hash_test[32];

		pdata[19] = nonce;//not swapped!!

		for (int l = 0; l < 20; l++)
			be32enc(&endiandata[l], pdata[l]);

		odo_hash(hash_test, endiandata, odocrypt_current_key);
		//printf("hash: "); printDataFPGA(hash_test, 32);

		//check for bad nonce
		if (fulltest(hash_test, my_target) == 0) {
			thr_info[thr_id].hw_err++;
			//applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Hardware Error, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));

			if (detect_sqrl && ((rand() & 0x7) == 0)) {
				double fah = temp * 9.0f / 5.0f + 32;
				//applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Squirrel Detected, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
				applog(LOG_INFO, "%s" CL_LRD " Squirrel Detected" CL_N "", str_health);
			}
			else {
				applog(LOG_INFO, "%s" CL_LRD " Hardware Error" CL_N "", str_health);
			}

			return 0;
		}

		thr_info[thr_id].solutions++;

		if (fulltest(hash_test, work->target) == 0) {
			applog(LOG_INFO, "%s" CL_YL2 " Solution Found" CL_N "", str_health);
			return 0;
		}
		else {
			//applog(LOG_INFO, "%s" CL_LBL " Share Found" CL_N "", str_health);
			work->nonces[0] = pdata[19];
			return 1;
		}

		return 0;
	}

	*hashes_done = 0;
	pdata[19] = n;
	return 0;

}

/*


int scanhash_odo2(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;
	uint32_t hash[8], hash2[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int info_timeout;
	uint32_t my_target[8];
	static int megahashes = 1;
	static Hashrate hashrate(25);
	unsigned char wbuf[84];
	uint32_t endiandata[32];

	unsigned char midstate[64];

	info_timeout = 60;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);
	memcpy(&endiandata, pdata, 32);


	///////////////////////////////////////////////

	unsigned int data[] = {

	0xd5a74fba,
	0x920ad0d3,
	0x5ec5726f,
	0x26327547,

	0xcbc82180,
	0xe356e5cc,
	0xf6cf2e6b,
	0xd75f8a66,

	0x00c904bd,
	0x00000000,
	0x00000000,
	0x00114026,

	0x0000FFFF

	};

	bswap((unsigned char*)data, 12 * 4);

	//memcpy(&endiandata, data, 32);



	///////////////////////////////////////////



	less_difficult = true;
	memcpy(my_target, work->target, 32);
	reverse((unsigned char*)my_target, 32);
	my_target[7] = 0;
	my_target[0] = 0;
	my_target[6] = 0x7FFFFFFF;
	if (less_difficult)
		my_target[6] = 0xFFFFFFFF;
	else if (more_difficult)
		my_target[6] = 0x3FFFFFFF;


	unsigned char mid[64];

	memcpy(wbuf, endiandata, 32);
	//reverse(wbuf, 32);
	EaglesongHash_Mid(mid, (unsigned char*)wbuf, 32);

	//printf("mids: "); printDataFPGA(mid, 64);
	//printDataFPGA(endiandata, 32);
	//printDataFPGA(my_target, 32);

	uint8_t cmd = 0x01;
	fpga_write(thr_info[thr_id].fd, &cmd, 1);

	reverse(mid, 64);

	memset(wbuf, 0, 84);
	memcpy(wbuf, mid, 64);
	memcpy(wbuf + 64, ((uint8_t*)endiandata) + 32, 16);
	memcpy(wbuf + 80, &my_target[7], 4);

	wbuf[67] = work->xnonce2[3];
	wbuf[66] = work->xnonce2[2];
	wbuf[65] = work->xnonce2[1];
	wbuf[64] = work->xnonce2[0];

	wbuf[71] = (char)rand();
	wbuf[70] = (char)rand();
	wbuf[69] = (char)rand();
	wbuf[68] = (char)rand();


	struct timeval tv_start, elapsed, tv_end;
	int ret;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 84);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	//size_t len;
	uint8_t buf[10];

	//applog(LOG_INFO, "Starting nonce = %08X", swab32(first_nonce));
	//printf("wbuf: "); printDataFPGA(wbuf, 84);
	//printf("tart: "); printDataFPGA(work->target, 32);

#define GC(xx,yy) (((xx) << 6) | (yy))
#define CSOLS(xx,yy) ( thr_info[thr_id].cid_sols[ GC(xx,yy) ] )
#define CERRS(xx,yy) ( thr_info[thr_id].cid_errs[ GC(xx,yy) ] )
#define CSOLSs(xx,yy) (CSOLS(xx,yy) + CERRS(xx,yy))

	uint32_t fivecores = CSOLSs(0, 4) + CSOLSs(1, 4) + CSOLSs(1, 4);
	uint32_t fourcores = CSOLSs(0, 3) + CSOLSs(1, 3) + CSOLSs(1, 3) + fivecores;
	uint32_t threecores = CSOLSs(0, 2) + CSOLSs(1, 2) + CSOLSs(1, 2) + fourcores;
	uint32_t twocores = CSOLSs(0, 1) + CSOLSs(1, 1) + CSOLSs(1, 1) + threecores;
	uint32_t onecore2 = CSOLSs(2, 0) + twocores;
	uint32_t onecore1 = CSOLSs(1, 0) + onecore2;

	while (!work_restart[thr_id].restart) {

		//////////////////////////////////////////////////

		int r2 = fpga_freq_check_keys(thr_info[thr_id].fd);

		if (r2) {
			r2 = tolower(r2);
			switch (r2) {
			case 'c':
				thr_info[thr_id].hw_err = 0;
				thr_info[thr_id].solutions = 0;
				thr_hashrates[thr_id] = 0;
				applog(LOG_INFO, "Clearing solutions/errors.");
				break;
			}
		}

		//////////////////////////////////////////////////

		memset(buf, 0, 8);

		//read response from fpga
		ret = fpga2_recv_response(thr_info[thr_id].fd, buf);

		cgtime(&tv_end); timersub(&tv_end, &tv_start, &elapsed);

		//if(elapsed.tv_sec > 4)
		//	fpga_write(fd, &cmd, 1);

		if (elapsed.tv_sec > info_timeout) {
			applog(LOG_ERR, "End Scan For Nonces - Time = %d sec", elapsed.tv_sec);
			//thr->work_restart = true;
			break;
		}

		if (ret == 0) {		// No Nonce Found
			continue;
		}

		else if (ret == -1) {
			applog(LOG_ERR, "Serial Read Error (ret=%d), need to exit.", ret);
			Sleep(2000);
			//serial_fpga_close(thr);
			//dev_error(serial_fpga, REASON_DEV_COMMS_ERROR);
			break;
		}

		else if (ret == -2) {
			size_t len2 = 0;
			applog(LOG_ERR, "Serial CRC Error.");
			thr_info[thr_id].crc_err++;
			char buf2[1024];
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			Sleep(1000);
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			//Sleep(1000);
			//fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			break;
		}

		bool is_health = (buf[0] == 0) && (buf[1] == 0) && (buf[2] == 0) && (buf[3] == 0) && (buf[4] == 0);

		//printData(buf, 8);

		double error_pct;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)thr_info[thr_id].solutions * 100.0f;

		static double vint = 0, temp = 0;

		double hr = ((double)thr_hashrates[thr_id]) / 1000000.0f;
		char hr_unit = 'M';

		hashrate.Add((int)hr);

		hr = (double)hashrate.Get();

		if (hr > 1000.0f || megahashes == 0) {
			megahashes = 0;
			hr /= 1000.0f;
			hr_unit = 'G';
		}

		char fstr[128];

		memset(fstr, 0, 128);

		if (cur_freq > 0)
			sprintf(fstr, "[%s: %dMHz %dc %0.2fV] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, cur_freq, (int)temp, vint, hr, hr_unit, error_pct);
		else
			sprintf(fstr, "[%s: %0.2fv %dc] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, vint, (int)temp, hr, hr_unit, error_pct);

		if (is_acc || is_rej) {
			if (is_rej)
				applog(LOG_INFO, "%s" CL_LRD " Share %s." CL_N "", fstr, "Rejected");
			else
				applog(LOG_INFO, "%s" CL_GR2 " Share %s." CL_N "", fstr, "Accepted");
			is_acc = 0;
			is_rej = 0;
		}

		if (is_health) {
			uint32_t vv, tt;

			vv = ((buf[7] << 0) | ((buf[6] & 0x0F) << 8)) << 4;
			tt = ((buf[5] << 4) | ((buf[6] & 0xF0) >> 4)) << 4;
			vint = ((double)vv) / 65536.0f * 3.0f;
			temp = (((double)tt) * 509.3140064f / 65536.0f) - 280.23087870f;

			char str_health[128];

			sprintf(str_health, "[%s: %dMHz %.0fC %.2fV]", active_dna, cur_freq, temp, vint);
			//if (strlen(str_hashrate) > 0)
			applog(LOG_INFO, "%s " CL_CYN "%3.1f %cH/s " CL_LCY " Acc/Rej: %d/%d  Sol/Err: %d/%d", str_health, hr, hr_unit, GetAcc(), GetRej(), thr_info[thr_id].solutions, thr_info[thr_id].hw_err);
			continue;
		}



		uint64_t nonce;

		memcpy((char*)& nonce, buf, 8);

		//nonce -= 18;


		memcpy(&work->nonces[0], &nonce, 4);
		memcpy(&work->nonces2[0], ((uint8_t*)& nonce) + 4, 4);
		memcpy(&work->nonces[1], ((unsigned char*)wbuf) + 68, 4);
		//reverse((unsigned char*)& nonce, 8);

		memcpy(wbuf, endiandata, 32);
		memcpy(wbuf + 40, &nonce, 8);

		wbuf[35] = work->xnonce2[3];
		wbuf[34] = work->xnonce2[2];
		wbuf[33] = work->xnonce2[1];
		wbuf[32] = work->xnonce2[0];

		wbuf[39] = wbuf[71];
		wbuf[38] = wbuf[70];
		wbuf[37] = wbuf[69];
		wbuf[36] = wbuf[68];

		if (nonce == 0xFFFFFFFFFFFFFFFFLL) {
			//applog(LOG_INFO, "%s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", fstr, GetAcc(), GetRej(), thr_info[thr_id].solutions, thr_info[thr_id].hw_err);
			//pdata[19] = nonce;// +0x10000;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			*hashes_done = 0xFFFFFFFFLL * 6LL;  //
			return 0;
		}


		if (!validate_eagle_hash((unsigned char*)wbuf, 48, my_target)) {
			//hashes += (unsigned int)(nonce & 0xFFFFFFFFLL);
			//valid = 1;
			*hashes_done = nonce;
			thr_info[thr_id].hw_err++;
			applog(LOG_WARNING, "hardware error");
			printData(buf, 8);
			//return 1;
		}

		else {

			thr_info[thr_id].solutions++;
			memcpy(my_target, work->target, 32);
			reverse((unsigned char*)my_target, 32);

			//if (validate_eagle((uint8_t*)wbuf, (uint32_t*)& nonce, (uint8_t*)my_target)) {
			if (validate_eagle_hash((unsigned char*)wbuf, 48, my_target)) {
				*hashes_done = nonce;
				//applog(LOG_INFO, "its valid!!");
				return 1;
			}
			//else
			//	applog(LOG_WARNING, "share found");
		}

		return 0;
	}

	*hashes_done = 0;
	pdata[19] = n;
	return 0;

}
*/
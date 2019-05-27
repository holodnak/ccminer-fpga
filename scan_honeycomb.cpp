#include "miner.h"
#include "fpga.h"
#include "scanhash.h"

extern "C" {
#include "sph/sph_keccak.h"
#include "sph/sph_jh.h"
#include "sph/sph_shabal.h"
#include "sph/sph_shavite.h"
#include "sph/sph_simd.h"
#include "sph/sph_echo.h"
}


extern "C" int noise;

extern int smaller_diff;

void HoneyBee2(const unsigned char* in, unsigned int sz, unsigned char* out) {
	memcpy(&out[0], &in[0], 36);
	memcpy(&out[36], &in[sz - 28], 28);
}

void xor64(unsigned char* a, unsigned char* b, unsigned char* c, unsigned char* out) {
	for (int i = 0; i < 64; i++) {
		out[i] = a[i] ^ b[i] ^ c[i];
	}
}

void honeycomb_hash_new(void* state, void* input)
{
	uint32_t _ALIGN(64) buffer1[16], buffer2[16], buffer3[16], buffer4[16], hash1[16], hash2[16], hash3[16], hash4[16], hash5[16], hash6[16], hash7[16], hash8[16];
	sph_keccak_context ctx_keccak;
	sph_shavite_big_context ctx_shavite;
	sph_simd_big_context ctx_simd;
	sph_echo_big_context ctx_echo;
	sph_jh_context ctx_jh;
	sph_shabal_context ctx_shabal;

	//noise = 1;
	unsigned char bee[64];
	int len = 80;

	printf("\ninput len = %d bytes, contents:\n\n", len);
	printData((char*)input, len);

	///////////////////////////////////////////////////////////

	memset(input, 0, len);
	//memset(input, 0x55, len);

	printf("\nbefore simd512:\n\n");
	printData(input, len);
	printDataFPGA(input, len);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, input, len);
	sph_simd512_close(&ctx_simd, (void*)buffer3);

	printf("\nafter simd512:\n\n");
	printData(buffer3, 64);
	printDataFPGA(buffer3, 64);

	uint32_t res[] = {
		//hashing result of all 0's
		0x7783C699, 0x19B2645C, 0xAA5297D7, 0x3D828397,
		0x9D3571DE, 0x2ABA17DB, 0x474A9796, 0xC97CC588,
		0x8CC91145, 0x31E50B51, 0xC610F227, 0xEC6E15F9,
		0x00A51165, 0x2C5D3E37, 0x1FC11E31, 0x450416FC,

		//hashing result of all $55's
		0xDF77F2E0, 0x1A762173, 0xA5B5A63F, 0x213A582E,
		0x1D844E10, 0x7FA378D1, 0x99615276, 0xCB737EA4,
		0x95E38BBF, 0x9083251B, 0xD97792D8, 0x14BD97B7,
		0x21DA2203, 0x326A025D, 0x7798C4E5, 0xD2E9CCFC
	};

	for(int k=0;k<32;k++)
		res[k] = bswap_32(res[k]);

	if (memcmp(buffer3, res, 64) == 0) {
		printf("\n !! empty string to hash: success\n\n");
	}
	if (memcmp(buffer3, res+16, 64) == 0) {
		printf("\n !! string of $55 to hash: success\n\n");
	}

	system("pause");
	exit(0);

	///////////////////////////////////////////////////////////


	HoneyBee2((unsigned char*)input, len, bee);

	printf("\nafter HoneyBee:\n\n");
	printData(bee, len);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, input, len);
	sph_keccak512_close(&ctx_keccak, (void*)buffer1);

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, input, len);
	sph_shavite512_close(&ctx_shavite, (void*)buffer2);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, input, len);
	sph_echo512_close(&ctx_echo, (void*)buffer4);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, input, len);
	sph_simd512_close(&ctx_simd, (void*)buffer3);

	printf("hash1 (keccak):\n\n"); printData(buffer1, 64);
	printf("hash2 (shavite):\n\n"); printData(buffer2, 64);
	printf("hash4 (simd):\n\n"); printData(buffer3, 64);
	printf("hash6 (echo):\n\n"); printData(buffer4, 64);

	xor64((unsigned char*)bee, (unsigned char*)buffer1, (unsigned char*)buffer2, (unsigned char*)hash2);

	printf("\nbuffer1^buffer2^bee: \n\n");
	printData(hash2, 64);

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, hash2, 64);
	sph_jh512_close(&ctx_jh, (void*)hash3);

	printf("hash3 (jh):\n\n"); printData(hash3, 64);

	xor64((unsigned char*)bee, (unsigned char*)buffer3, (unsigned char*)hash3, (unsigned char*)hash5);

	printf("\nbuffer3^buffer4^bee: \n\n");
	printData(hash5, 64);

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hash5, 64);
	sph_shabal512_close(&ctx_shabal, (void*)hash6);

	printf("hash5 (shabal):\n\n"); printData(hash6, 64);

	xor64((unsigned char*)bee, (unsigned char*)buffer4, (unsigned char*)hash6, (unsigned char*)hash8);

	printf("\noutput: \n\n");
	printData(hash8, 64);

	memcpy(state, hash8, 32);
}

extern "C" void honeycomb_hash(const char* input, int len, char* output);

int scanhash_honeycomb(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t _ALIGN(128) hash32[8], hash32_new[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;

	ptarget[7] = 0x0000fff;
	ptarget[6] = 0xffffffff;

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	const uint32_t Htarg = ptarget[7];
	do {

		pdata[19] = ++n;
		be32enc(&endiandata[19], n);
		honeycomb_hash((char*)endiandata, 80, (char*)hash32);

		honeycomb_hash_new(hash32_new, endiandata);

		printf("found hash:\n\n");
		printData(hash32, 32);

		printf("found hash (new):\n\n");
		printData(hash32_new, 32);

		system("pause");

		if (hash32[7] <= Htarg && fulltest(hash32, ptarget))
		{

			printf("\n\nfound ptarget:\n\n");
			printData(&ptarget[6], 8);

			printf("found hash:\n\n");
			printData(hash32, 32);

			printf("found endian data:\n\n");
			printData(endiandata, 80);
			printDataFPGA(endiandata, 80);
			printf("\n\n");

			printf("found pdata:\n\n");
			printData(pdata, 80);
			printDataFPGA(pdata, 80);
			printf("\n\n");

			system("pause");




			work_set_target_ratio(work, hash32);
			pdata[19] = n;
			*hashes_done = pdata[19] - first_nonce;
			return true;
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce;
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

int scanhash_honeycomb_f(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	unsigned char wbuf[84];
	uint32_t* pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];
	uint32_t hash_test[64];
	uint32_t target1, my_target[8];

	if (pdata[19] < 200)
		pdata[19] = 200;

	//	pdata[19] += 250;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	for (int i = 0; i < 8; i++)
		my_target[i] = work->target[i];

	if (smaller_diff)
		my_target[6] <<= 1;

	target1 = my_target[6];

	//copy data
	memcpy(wbuf, endiandata, 80);

	//copy target
/*
	wbuf[80] = ((unsigned char*)work->target)[0x1F - 4];
	wbuf[81] = ((unsigned char*)work->target)[0x1E - 4];
	wbuf[82] = ((unsigned char*)work->target)[0x1D - 4];
	wbuf[83] = ((unsigned char*)work->target)[0x1C - 4];
	*/
	wbuf[80] = ((unsigned char*)& target1)[3];
	wbuf[81] = ((unsigned char*)& target1)[2];
	wbuf[82] = ((unsigned char*)& target1)[1];
	wbuf[83] = ((unsigned char*)& target1)[0];


#define SERIAL_READ_SIZE 8

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	int info_timeout;
	info_timeout = 10;

	//	printf("data out:\n");
	//	printData(wbuf, 84);
	//	printDataFPGA(wbuf, 84);
	//	system("pause");
	fpga_send_data(thr_info[thr_id].fd, wbuf, 84);
	//	_write(thr_info[thr_id].fd, wbuf, 52);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	size_t len;
	uint32_t first_nonce;

	first_nonce = pdata[19];

	//applog(LOG_INFO, "FPGA: Begin Scan For Nonces at (first_nonce= %08X, target[6:7]= %08X %08X)", first_nonce, work->target[6], work->target[7]);

	while ((!work_restart[thr_id].restart)) {

		memset(buf, 0, 8);

		// Check Serial Port For 1/10 Sec For Nonce  
		ret = fpga_read(thr_info[thr_id].fd, (char*)buf, 8, &len);

		// Calculate Elapsed Time
		cgtime(&tv_end);
		timersub(&tv_end, &tv_start, &elapsed);

		int n = fpga_freq_check_keys(thr_info[thr_id].fd);

		if (n > 0) {
			//printf("frequency changed, resending work.\n");
			Sleep(50);
			fpga_send_data(thr_info[thr_id].fd, wbuf, 84);
		}
		else if (n == -1) {
			thr_info[thr_id].hw_err = 0;
			thr_info[thr_id].solutions = 0;
			applog(LOG_ERR, "Clearing solutions/errors.");
		}


		if (ret == 0 && len != 8) {		// No Nonce Found
			if (elapsed.tv_sec > info_timeout) {
				//applog(LOG_ERR, "End Scan For Nonces - Time = %d sec", elapsed.tv_sec);
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

		double hr = ((double)global_hashrate + thr_hashrates[thr_id]) / 1000000.0f / 2.0f;

		//		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC", thr_id, vint, temp);
		if (is_acc || is_rej) {
			applog(LOG_INFO, "[%dMHz] VInt: %0.2fv, Temp: %.1fC, Errors: %.2f%% " CL_CYN "%.1f MH/s" CL_GR2 " Share Found." CL_N "", (cur_freq), vint, temp, error_pct, hr);

		}
		else
			applog(LOG_INFO, "[%dMHz] VInt: %0.2fv, Temp: %.1fC, Errors: %.2f%% " CL_CYN "%.1f MH/s" CL_WHT " Acc/Rej: %d/%d  Sol: %d  Err: %d", (cur_freq), vint, temp, error_pct, hr, GetAcc(), GetAcc() + GetRej(), thr_info[thr_id].solutions, thr_info[thr_id].hw_err);
		is_acc = 0;
		is_rej = 0;

		uint32_t nonce;

		memcpy((char*)& nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = nonce - first_nonce;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;// +0x10000;
							  //		   applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, swab32(nonce));


		pdata[19] = nonce;

		for (int l = 0; l < 20; l++)
			be32enc(&endiandata[l], pdata[l]);
		honeycomb_hash_new(hash_test, endiandata);
		//printData32(hash_test, 32);

		//check for bad nonce
		if (fulltest(hash_test, my_target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "miner[%d] Nonce Invalid - Hardware Error, Nonce = %08X", thr_id, swab32(nonce));
			return 0;
		}

		if (fulltest(hash_test, work->target) == 0) {
			//thr_info[thr_id].hw_err++;
			//applog(LOG_INFO, "miner[%d] Nonce Invalid - Diff not high enough, Nonce = %08X", thr_id, swab32(nonce));
			return 0;
		}
		else {
			//applog(LOG_INFO, "miner[%d] Valid Nonce Found = %08X", thr_id, swab32(nonce));
			return 1;
		}

		return 0;
	}

	pdata[19] = 0xFFFFFFFF;
	//pdata[19] = pdata[19] + 1;
	*hashes_done = pdata[19] - first_nonce;

	//	applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

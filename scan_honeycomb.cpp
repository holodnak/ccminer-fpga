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

void honeycomb_hash_new(void* state, void* input, bool noisey)
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

	if (noisey) printf("\ninput len = %d bytes, contents: ", len);
	if (noisey) printDataFPGA((char*)input, len);

	///////////////////////////////////////////////////////////

	//memset(input, 0, len);
	//memset(input, 0x55, len);


	HoneyBee2((unsigned char*)input, len, bee);

	if (noisey) printf("after HoneyBee:       ");
	if (noisey) printDataFPGA(bee, 64);

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, input, len);
	sph_keccak512_close(&ctx_keccak, (void*)buffer1);

	//system("pause");

	sph_shavite512_init(&ctx_shavite);
	sph_shavite512(&ctx_shavite, input, len);
	sph_shavite512_close(&ctx_shavite, (void*)buffer2);

	sph_echo512_init(&ctx_echo);
	sph_echo512(&ctx_echo, input, len);
	sph_echo512_close(&ctx_echo, (void*)buffer4);

	sph_simd512_init(&ctx_simd);
	sph_simd512(&ctx_simd, input, len);
	sph_simd512_close(&ctx_simd, (void*)buffer3);

	if (noisey){ printf("hash1 (keccak):       "); printDataFPGA(buffer1, 64);}
	if (noisey){ printf("hash2 (shavite):      "); printDataFPGA(buffer2, 64);}
	if (noisey){ printf("hash3 (simd):         "); printDataFPGA(buffer3, 64);}
	if (noisey){ printf("hash4 (echo):         "); printDataFPGA(buffer4, 64);}

	xor64((unsigned char*)bee, (unsigned char*)buffer1, (unsigned char*)buffer2, (unsigned char*)hash2);

	if (noisey) printf("buffer1^buffer2^bee:  ");
	if (noisey) printDataFPGA(hash2, 64);

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, hash2, 64);
	sph_jh512_close(&ctx_jh, (void*)hash3);

	if (noisey) printf("hash3 (jh):           "); 
	if (noisey) printDataFPGA(hash3, 64);

	xor64((unsigned char*)bee, (unsigned char*)buffer3, (unsigned char*)hash3, (unsigned char*)hash5);

	if (noisey) printf("buffer3^buffer4^bee:  ");
	if (noisey) printDataFPGA(hash5, 64);

	sph_shabal512_init(&ctx_shabal);
	sph_shabal512(&ctx_shabal, hash5, 64);
	sph_shabal512_close(&ctx_shabal, (void*)hash6);

	if (noisey) { printf("hash5 (shabal):       "); printDataFPGA(hash6, 64); }

	xor64((unsigned char*)bee, (unsigned char*)buffer4, (unsigned char*)hash6, (unsigned char*)hash8);

	if (noisey) printf("output:               ");
	if (noisey) printDataFPGA(hash8, 64);

	memcpy(state, hash8, 32);
}

extern "C" void honeycomb_hash(const char* input, int len, char* output);

int scanhash_honeycomb_cpu(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t _ALIGN(128) hash32[8], hash32_new[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;

	ptarget[7] = 0x0000ffff;
	ptarget[6] = 0xffffffff;

	uint32_t aaa[20] = {
		0x00000020, 0xE0CFE519, 0x7DC0CC6E, 0x2C74451B,
		0x3481B15F, 0xBC69F269, 0xD7669944, 0xD9B30600,
		0x00000000, 0x007E36B9, 0xACD262AD, 0xB2F7A041,
		0xAECB8E97, 0x91C720AB, 0xBB2618CD, 0x94182A20,
		0xA90A355B, 0xFE04F35C, 0x99BD111B, 0x00016D57
	};

	memcpy(work->data, aaa, 80);

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	const uint32_t Htarg = ptarget[7];
	do {

		pdata[19] = ++n;
		be32enc(&endiandata[19], n);

		//memset(endiandata, 0, 80);
		//memset(endiandata, 0x55, 80);

		//honeycomb_hash((char*)endiandata, 80, (char*)hash32);

		honeycomb_hash_new(hash32, endiandata, 0);

		//printf("found hash:\n\n");
		//printData(hash32, 32);

		//printf("found hash (new):\n\n");
		//printData(hash32_new, 32);

		//if (memcmp(hash32, hash32_new, 32) == 0)
		//	printf("\n  !! hashes match!!  success!!\n\n");

		//printf("\n\nfound ptarget:\n\n");
		//printData(&ptarget[6], 8);
		//system("pause");

		if (hash32[7] <= Htarg && fulltest(hash32, ptarget))
		{
			honeycomb_hash_new(hash32, endiandata, 1);

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
extern bool more_difficult;

int scanhash_honeycomb(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	unsigned char wbuf[84];
	uint32_t* pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];
	uint32_t hash_test[64];
	uint32_t target0, target1, my_target[8];
	int info_timeout;

	info_timeout = 10;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	double my_diff = work->targetdiff * 65536.0f;

	if (more_difficult == false) {
		if (my_diff < 4096.0f)		my_diff = 4096.0f;
		//if (my_diff < 2048.0f)		my_diff = 2048.0f;
		//if (my_diff < 1024.0f)	my_diff = 1024.0f;

		if (my_diff > 16384.0f)	my_diff = 16384.0f;
		//if (my_diff > 8192.0f)		my_diff = 8192.0f;
		//if (my_diff > 2048.0f)	my_diff = 2048.0f;
	}

	else {
		if (my_diff < 16384.0f)		my_diff = 16384.0f;
		if (my_diff > 65536.0f)		my_diff = 65536.0f;
		info_timeout = 30;
	}

	diff_to_target(my_target, my_diff / 65536.0f);

	//printf("my_target: "); printData(&my_target[6], 8);
	//printf("w->target: "); printData(&work->target[6], 8);

	//system("pause");

	//if (smaller_diff) my_target[6] <<= 1;
	//if (smaller_diff) my_target[6] <<= 4;
	//my_target[6] = 0xFFFFFFFF;

	//memcpy(work->target, my_target, 8 * 4);

	target1 = my_target[6];
	target0 = my_target[7];

	//copy data
	memcpy(wbuf, endiandata, 80);

	//copy target
	wbuf[80] = ((unsigned char*)& target0)[3];
	wbuf[81] = ((unsigned char*)& target0)[2];
	wbuf[82] = ((unsigned char*)& target0)[1];
	wbuf[83] = ((unsigned char*)& target0)[0];


#define SERIAL_READ_SIZE 8

	struct timeval tv_start, elapsed, tv_end;
	int ret;


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
			printf("Frequency changed, resending work.\n");
			Sleep(100);
			fpga_send_start(thr_info[thr_id].fd);
			fpga_send_data(thr_info[thr_id].fd, wbuf, 284);
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

		*hashes_done = nonce - first_nonce;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;// +0x10000;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, swab32(nonce));


		pdata[19] = nonce;

		for (int l = 0; l < 20; l++)
			be32enc(&endiandata[l], pdata[l]);
		//bsha3_hash(hash_test, endiandata);
		honeycomb_hash_new(hash_test, endiandata, 0);
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

	//applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

void gen_keccak_midstate(unsigned char *out, unsigned char *buf, int len)
{
	sph_keccak_context ctx_keccak;

	sph_keccak512_init(&ctx_keccak);
	sph_keccak512(&ctx_keccak, buf, 72);

	ctx_keccak.u.wide[1] = ~ctx_keccak.u.wide[1];
	ctx_keccak.u.wide[2] = ~ctx_keccak.u.wide[2];
	ctx_keccak.u.wide[8] = ~ctx_keccak.u.wide[8];
	ctx_keccak.u.wide[12] = ~ctx_keccak.u.wide[12];
	ctx_keccak.u.wide[17] = ~ctx_keccak.u.wide[17];
	ctx_keccak.u.wide[20] = ~ctx_keccak.u.wide[20];

	memcpy(out, &ctx_keccak.u.wide[0], 200);

	bswap64(out, 200);
	/*
	printf("keccak midstate:\n");
	printData(out, 200);
	printf("\n");

	reverse(out, 200);

	printDataFPGA(out, 200);
	printf("\n");

	system("pause");
	*/
//	sph_keccak512_close(&ctx_keccak, (void*)buffer1);
}


int scanhash_honeycomb_v2(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	unsigned char wbuf[84 + 200], mids[200];
	uint32_t* pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];
	uint32_t hash_test[64];
	uint32_t target0, my_target[8];
	int info_timeout;
	struct timeval tv_start, elapsed, tv_end;
	int ret;
	size_t len;
	uint32_t first_nonce;

/*	uint32_t aaa[20] = {
		0x00000020, 0xE0CFE519, 0x7DC0CC6E, 0x2C74451B,
		0x3481B15F, 0xBC69F269, 0xD7669944, 0xD9B30600,
		0x00000000, 0x007E36B9, 0xACD262AD, 0xB2F7A041,
		0xAECB8E97, 0x91C720AB, 0xBB2618CD, 0x94182A20,
		0xA90A355B, 0xFE04F35C, 0x99BD111B, 0x00016D57
	};

	memcpy(work->data, aaa, 80);*/

	info_timeout = 10;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	double my_diff = work->targetdiff * 65536.0f;

	if (more_difficult == false) {
		if (my_diff < 4096.0f)		my_diff = 4096.0f;
		if (my_diff > 16384.0f)		my_diff = 16384.0f;
	}

	else {
		if (my_diff < 16384.0f)		my_diff = 16384.0f;
		if (my_diff > 65536.0f)		my_diff = 65536.0f;
		info_timeout = 30;
	}

	diff_to_target(my_target, my_diff / 65536.0f);

	target0 = my_target[7];

	//generate midstate for keccak
	gen_keccak_midstate(mids, (unsigned char*)endiandata, 80);

	//copy data
	memcpy(wbuf,     mids,       200);
	memcpy(wbuf+200, endiandata, 80);

	//copy target
	wbuf[280] = ((unsigned char*)& target0)[3];
	wbuf[281] = ((unsigned char*)& target0)[2];
	wbuf[282] = ((unsigned char*)& target0)[1];
	wbuf[283] = ((unsigned char*)& target0)[0];

	fpga_send_data(thr_info[thr_id].fd, wbuf, 284);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

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
			printf("Frequency changed, resending work.\n");
			Sleep(100);
			cgtime(&tv_start);
			fpga_send_start(thr_info[thr_id].fd);
			fpga_send_data(thr_info[thr_id].fd, wbuf, 284);
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

		char fstr[64];

		memset(fstr, 0, 64);
		if (cur_freq > 0)
			sprintf(fstr, "[%dMHz] ", cur_freq);

		if (is_acc || is_rej)
			applog(LOG_INFO, "%sV: %0.2fv, T: %.1fC, Err: %.2f%% " CL_CYN "%.1f MH/s" CL_GR2 " Share Found." CL_N "", fstr, vint, temp, error_pct, hr);
		else
			applog(LOG_INFO, "%sV: %0.2fv, T: %.1fC, Err: %.2f%% " CL_CYN "%.1f MH/s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", fstr, vint, temp, error_pct, hr, GetAcc(), GetAcc() + GetRej(), thr_info[thr_id].solutions - thr_info[thr_id].hw_err, thr_info[thr_id].hw_err);
		is_acc = 0;
		is_rej = 0;

		uint32_t nonce;

		memcpy((char*)& nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = nonce - first_nonce;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;// +0x10000;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, swab32(nonce));


		pdata[19] = nonce;

		for (int l = 0; l < 20; l++)
			be32enc(&endiandata[l], pdata[l]);
		//bsha3_hash(hash_test, endiandata);
		honeycomb_hash_new(hash_test, endiandata, 0);
		//printData32(hash_test, 32);

		//check for bad nonce
		if (fulltest(hash_test, my_target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "miner[%d] Nonce Invalid - Hardware Error, Nonce = %08X", thr_id, swab32(nonce));
			return 0;
		}

		if (fulltest(hash_test, work->target) == 0) {
			//applog(LOG_INFO, "miner[%d] Nonce Invalid - Diff not high enough, Nonce = %08X", thr_id, swab32(nonce));
			return 0;
		}

		//applog(LOG_INFO, "miner[%d] Valid Nonce Found = %08X", thr_id, swab32(nonce));
		return 1;
	}

	pdata[19] = 0xFFFFFFFF;
	* hashes_done = pdata[19] - first_nonce;

	//applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

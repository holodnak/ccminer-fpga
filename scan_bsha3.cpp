#include "miner.h"
#include "fpga.h"
#include "scanhash.h"

extern "C" {
#include "sph/sph_keccak.h"
}
extern "C" int noise;
void bsha3_hash(void* state, const void* input)
{
	uint32_t _ALIGN(64) buffer[16], hash[16];
	sph_keccak_context ctx_keccak;

	//noise = 1;

	sph_keccak256_init(&ctx_keccak);
	sph_keccak256(&ctx_keccak, input, 80);
	sph_keccak256_close(&ctx_keccak, (void*)buffer);

	//printf("keccak hash1:\n\n");printData(buffer, 32);

	sph_keccak256_init(&ctx_keccak);
	sph_keccak256(&ctx_keccak, buffer, 32);
	sph_keccak256_close(&ctx_keccak, (void*)hash);

	//noise = 0;

	//printf("keccak hash2:\n\n");printData(hash, 32);

	memcpy(state, hash, 32);
}

int scanhash_bsha3p(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t _ALIGN(128) hash32[8];
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
		bsha3_hash(hash32, endiandata);

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

int scanhash_bsha3(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	unsigned char wbuf[84];
	uint32_t* pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];
	uint32_t hash_test[64];

	if (pdata[19] < 200)
		pdata[19] = 200;

//	pdata[19] += 250;
	
	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	//copy data
	memcpy(wbuf, endiandata, 80);

	//copy target
	wbuf[80] = ((unsigned char*)work->target)[0x1F - 4];
	wbuf[81] = ((unsigned char*)work->target)[0x1E - 4];
	wbuf[82] = ((unsigned char*)work->target)[0x1D - 4];
	wbuf[83] = ((unsigned char*)work->target)[0x1C - 4];
 

	//	printData(work->target, 32);
	//	printData(pdata, 80);
	//	printDataC(endiandata, 80);
	//	printDataFPGA(pdata, 80);
	//	printDataFPGA(endiandata, 80);

	//	bmw512_hash(hash_test, endiandata);
	//	printData(hash_test, 64);


		//swap endian of data + nonce + target
		//bswap(wbuf, 76);

		//unswap nonce endian
		//bswap(wbuf + 44, 4);

	//	bswap(wbuf, 76);
	//	bswap(wbuf, 80);
	//	reverse(wbuf, 76);

		//reverse data
		//reverse(wbuf + 32, 12);

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
			applog(LOG_INFO, "[%dMHz] VInt: %0.2fv, Temp: %.1fC, Errors: %.2f%% " CL_CYN "%.1f MH/s" CL_WHT " Acc/Rej: %d/%d", (cur_freq), vint, temp, error_pct, hr, GetAcc(), GetAcc() + GetRej());
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
		bsha3_hash(hash_test, endiandata);
		//printData32(hash_test, 32);
		if (fulltest(hash_test, work->target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "miner[%d] Nonce Invalid - Hardware Error, Nonce = %08X", thr_id, swab32(nonce));
			return 0;
		}
		else {
			//applog(LOG_INFO, "miner[%d] Valid Nonce Found = %08X", thr_id, swab32(nonce));
		}

		return 1;

	}

	pdata[19] = 0xFFFFFFFF;
	//pdata[19] = pdata[19] + 1;
	*hashes_done = pdata[19] - first_nonce;

	//	applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

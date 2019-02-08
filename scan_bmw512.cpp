#include "miner.h"
#include "fpga.h"
#include "scanhash.h"

extern "C" {
#include "sph/sph_bmw.h"
}

void bmw512_hash(void *state, const void *input)
{
	uint32_t _ALIGN(128) hash[16];
	uint32_t *inp = (uint32_t*)input;
	sph_bmw512_context       ctx_bmw;

	sph_bmw512_init(&ctx_bmw);
	sph_bmw512(&ctx_bmw, inp, 80);
	sph_bmw512_close(&ctx_bmw, hash);

	memcpy(state, hash, 64);
}

int scanhash_bmw512(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	unsigned char wbuf[84];
	uint32_t *pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];
	uint32_t hash_test[64];

	if (pdata[19] < 200)
		pdata[19] = 200;

	pdata[19] += 250;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	//	sha256q_midstate(endiandata);

	//copy midstate
	//	memcpy(wbuf, sha256q_ctx.h, 32);

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
	reverse(wbuf, 76);

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

		for (int k = 0; k < 20; k++)
			be32enc(&endiandata[k], pdata[k]);
		bmw512_hash(hash_test, endiandata);
//		printData(hash_test, 64);
		if (fulltest(hash_test, work->target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "miner[%d] Nonce Invalid - Hardware Error", thr_id, swab32(nonce));
			return 0;
		}
//		else applog(LOG_INFO, "miner[%d] Valid Nonce Found = %08X", thr_id, swab32(nonce));

		return 1;

	}

	pdata[19] = 0xFFFFFFFF;
	//pdata[19] = pdata[19] + 1;
	*hashes_done = pdata[19] - first_nonce;

//	applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

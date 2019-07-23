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

int scanhash_bmw512_old(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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
//		nonce = swab32(nonce);

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

extern volatile int is_acc, is_rej;
extern volatile int cur_freq;
extern volatile double thr_hashrates[16];

int translate_freq(uint8_t fr);
int GetAcc();
int GetRej();

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

typedef void (*hashfunc_t)(void*, void*);

int fpga2_recv_nonce(int thr_id, struct work* work, uint8_t* buf, int timeout, hashfunc_t hashfunc);
int fpga2_send_mining_data(int fd, uint8_t* buf, int len);

int scanhash_bmw512m(int thr_id, struct work* work,	uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;

	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];

	ptarget[7] = 0x0000ffff;
	ptarget[6] = 0xFFFFFFFF;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		if (n < 60000) {
			be32enc(&endiandata[19], n);
			bmw512_hash(hash64, endiandata);
			if (hash64[7] < Htarg && fulltest(hash64, ptarget))
			{

				printf("\nhash64:\n");
				printData(hash64, 32);
				printDataFPGA(hash64, 32);

				printf("\nendiandata:\n");
				printData(endiandata, 80);
				printDataFPGA(endiandata, 80);

				pdata[19] = n;
				printf("\npdata:\n");
				printData(pdata, 80);
				printDataFPGA(pdata, 80);

				system("pause");

				*hashes_done = n - first_nonce + 1;
				pdata[19] = n;
				return true;
			}
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}

extern char active_dna[];

//v2
int scanhash_bmw512aaaa(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
/*	uint32_t mydata[20] = {
	0x00000020, 0x87446760, 0xD9D25BA4, 0x0CCA738B,
	0x6C06430F, 0x421BB024, 0xF7FCA0B8, 0x5B56D566,
	0xF40FA247, 0xB972D714, 0xE5FBA852, 0x0F260CAC,
	0xF0091F6B, 0x0A6788D0, 0xC7B5BC5B, 0xA048B96B,
	0x86D0C670, 0x1A0A215D, 0xAD25031B, 0,//0x00000238
	};

	for (int k = 0; k < 20; k++)
		be32enc(&work->data[k], mydata[k]);
		*/

	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;
	uint32_t hash[8], hash2[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int info_timeout;
	uint32_t my_target[8];

	*hashes_done = 0;

	unsigned char wbuf[88];
	uint32_t endiandata[32];

	info_timeout = 60;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	///////////////////////////////

	less_difficult = true;
	memcpy(my_target, work->target, 32);
	my_target[7] = 0;
	my_target[6] = 0x7FFFFFFF;
	if (less_difficult)
		my_target[6] = 0xFFFFFFFF;
	else if (more_difficult)
		my_target[6] = 0x3FFFFFFF;

	double my_diff = work->targetdiff * 256.0f;

#ifdef NEW_DIFF_OFFSETS
	//starting initial values
	double start_min = 4096.0f;
	double start_max = 16384.0f;

	if (more_difficult) {
		start_min *= 4.0f;
		start_max *= 4.0f;
		info_timeout = 30;
	}
	if (less_difficult) {
		start_min /= 4.0f;
		start_max /= 4.0f;
	}
	if (my_diff < start_min)	my_diff = start_min;
	if (my_diff > start_max)	my_diff = start_max;
#else
	if (more_difficult == false) {
		if (my_diff < 16.0f)	my_diff = 16.0f;
		if (my_diff > 64.0f)	my_diff = 64.0f;
	}

	else {
		if (my_diff < 64.0f)		my_diff = 64.0f;
		if (my_diff > 256.0f)		my_diff = 256.0f;
		info_timeout = 30;
	}
#endif

	//my_diff
	diff_to_target(my_target, my_diff / 256.0f);

	//fake target
	my_target[7] = 0x00000000;
	my_target[6] = 0xFFFFFFFF;

	//memcpy(my_target, work->target, 32);

	//printf("my_target: "); printData(&my_target[6], 8);
	//printf("w->target: "); printData(&work->target[6], 8);

	////////////////////////////////

	//copy data
	memcpy(wbuf, endiandata, 80);

	//copy target
	memcpy(wbuf + 80, ((unsigned char*)& my_target[6]), 4);

	//bswap(wbuf, 80);
	//reverse(wbuf, 76);
	//reverse(wbuf + 76, 4);

	//wbuf[77]++;
	//wbuf[78]++;

	//printf("wbuf: \n"); printData(wbuf, 84); printDataFPGA(wbuf, 84);

	/////////////////////////////////

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 84);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	//size_t len;
	uint8_t buf[10];

	//applog(LOG_INFO, "Starting nonce = %08X",first_nonce);

	while (!work_restart[thr_id].restart) {

		//////////////////////////////////////////////////

		int r2 = fpga_freq_check_keys(thr_info[thr_id].fd);

#define GC(xx,yy) (((xx) << 6) | (yy))
#define CSOLS(xx,yy) ( thr_info[thr_id].cid_sols[ GC(xx,yy) ] )
#define CERRS(xx,yy) ( thr_info[thr_id].cid_errs[ GC(xx,yy) ] )
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
				applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(0, 1), CERRS(0, 1));
				applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(0, 2), CERRS(0, 2));
				applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(0, 3), CERRS(0, 3));
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Group 1:  Core 0: %8d (errors: %d)", CSOLS(1, 0), CERRS(1, 0));
				applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(1, 1), CERRS(1, 1));
				applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(1, 2), CERRS(1, 2));
				applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(1, 3), CERRS(1, 3));
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Group 2:  Core 0: %8d (errors: %d)", CSOLS(2, 0), CERRS(2, 0));
				applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(2, 1), CERRS(2, 1));
				applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(2, 2), CERRS(2, 2));
				applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(2, 3), CERRS(2, 3));
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

		//ret = fpga_read(thr_info[thr_id].fd, (char*)buf, 10, &len);

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
			applog(LOG_ERR, "Serial Read Error (ret=%d)", ret);
			//serial_fpga_close(thr);
			//dev_error(serial_fpga, REASON_DEV_COMMS_ERROR);
			break;
		}

		else if (ret == -2) {
			size_t len2 = 0;
			applog(LOG_ERR, "Serial CRC Error.");
			thr_info[thr_id].crc_err++;
			char buf2[1024];
			Sleep(3000);
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			break;
		}

		double error_pct;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)thr_info[thr_id].solutions * 100.0f;

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

		double hr = ((double)thr_hashrates[thr_id]) / 1000000.0f / 1000.0f;

		char fstr[64];

		memset(fstr, 0, 64);
		if (cur_freq > 0)
			sprintf(fstr, "[%dMHz] ", cur_freq);

		//		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC", thr_id, vint, temp);
		if (is_acc || is_rej) {
			if (is_rej)
				applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Share %s." CL_N "", fstr, vint, (int)temp, error_pct, hr, "Rejected");
			else
				applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_GR2 " Share %s." CL_N "", fstr, vint, (int)temp, error_pct, hr, "Accepted");
		}

		is_acc = 0;
		is_rej = 0;

		uint32_t nonce;

		memcpy((char*)& nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = (uint64_t)(swab32(nonce) - first_nonce) & 0xFFFFFFFFULL;

		if (nonce == 0xFFFFFFFF) {
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", fstr, vint, (int)temp, error_pct, hr, GetAcc(), GetRej(), thr_info[thr_id].solutions - thr_info[thr_id].hw_err, thr_info[thr_id].hw_err);
			pdata[19] = nonce;// +0x10000;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, nonce);

		//TODO: fix the 'waiting' flag in the bitstream!
		pdata[19] = nonce;

		uint32_t hash_test[32];

		for (int k = 0; k < 20; k++)
			be32enc(&endiandata[k], pdata[k]);

		bmw512_hash(hash_test, endiandata);

		printDataFPGA(hash_test, 32);
		printDataFPGA((char*)pdata, 80);

		//printDataFPGA((char*)& work->target[6], 8);
		//printDataFPGA((char*)& my_target[6], 8);

		//printf("Nonce = %08X\n", nonce);

		pdata[19] = nonce;

		//check for bad nonce
		if (fulltest(hash_test, my_target) == 0) {
			thr_info[thr_id].hw_err++;
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_RD2 " Hardware Error, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
			return 0;
		}

		if (fulltest(hash_test, work->target) == 0) {
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_YL2 " Solution Found, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
			return 0;
		}
		else {
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LBL " Share Found, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
			work->nonces[0] = pdata[19];
			return 1;
		}

		return 0;
	}

	return 0;

}

static struct timeval tv_start, elapsed;

int fpga2_send_mining_data(int fd, uint8_t* buf, int len)
{
	int ret;

	//initialize counters
	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	return fpga_send_data(fd, buf, len);
}

int fpga2_recv_nonce(int thr_id, struct work* work, uint8_t* buf, int timeout, hashfunc_t hashfunc)
{
	struct timeval tv_end;
	int ret;
	int fd = thr_info[thr_id].fd;

	switch (fpga_freq_check_keys(fd)) {
	default:
		break;
	case -2:
		applog(LOG_ERR, "There has been %d serial CRC errors.", thr_info[thr_id].crc_err);
		break;
	case -1:
		thr_info[thr_id].hw_err = 0;
		thr_info[thr_id].solutions = 0;
		thr_hashrates[thr_id] = 0;
		applog(LOG_ERR, "Clearing solutions/errors.");
		break;
	}

	//clear response buffer
	memset(buf, 0, 8);

	//read response from fpga
	ret = fpga2_recv_response(fd, buf);

	//update counters
	cgtime(&tv_end);
	timersub(&tv_end, &tv_start, &elapsed);

	if (ret == 0) {		// No Nonce Found
		if (elapsed.tv_sec > timeout) {
			applog(LOG_ERR, "End Scan For Nonces - Time = %d sec", elapsed.tv_sec);
			//thr->work_restart = true;

			//stop loop
			return -1;//break;
		}

		//continue mining loop
		return -1;//continue;
	}

	else if (ret == -1) {
		applog(LOG_ERR, "Serial Read Error (ret=%d)", ret);
		//serial_fpga_close(thr);
		//dev_error(serial_fpga, REASON_DEV_COMMS_ERROR);

		//stop loop
		return 0;//break;
	}

	else if (ret == -2) {
		size_t len2 = 0;
		applog(LOG_ERR, "Serial CRC Error.");
		thr_info[thr_id].crc_err++;
		char buf2[1024];
		Sleep(3000);
		fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);

		//stop loop
		return 0;//break;
	}

	double error_pct;

	if (thr_info[thr_id].solutions == 0)
		error_pct = 0;
	else
		error_pct = (double)thr_info[thr_id].hw_err / (double)thr_info[thr_id].solutions * 100.0f;

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

	double hr = ((double)thr_hashrates[thr_id]) / 1000000.0f / 1000.0f;

	char fstr[64];

	memset(fstr, 0, 64);
	if (cur_freq > 0)
		sprintf(fstr, "[%dMHz] ", cur_freq);

	//		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC", thr_id, vint, temp);
	if (is_acc || is_rej) {
		if (is_rej)
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Share %s." CL_N "", fstr, vint, (int)temp, error_pct, hr, "Rejected");
		else
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_GR2 " Share %s." CL_N "", fstr, vint, (int)temp, error_pct, hr, "Accepted");
	}

	is_acc = 0;
	is_rej = 0;

	uint32_t nonce;

	memcpy((char*)& nonce, buf, 4);

	nonce = swab32(nonce);

	//*hashes_done = (uint64_t)(nonce - first_nonce) & 0xFFFFFFFFULL;

	if (nonce == 0xFFFFFFFF) {
		applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", fstr, vint, (int)temp, error_pct, hr, GetAcc(), GetRej(), thr_info[thr_id].solutions - thr_info[thr_id].hw_err, thr_info[thr_id].hw_err);
		work->data[19] = nonce;// +0x10000;
		//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
		return 0;
	}

	thr_info[thr_id].solutions++;

	memcpy(&work->nonces[0], &nonce, 4);

	if (opt_debug)
		applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, nonce);

	work->data[19] = nonce;

	uint32_t hash_test[32];
	uint32_t endiandata[20];

	for (int l = 0; l < 20; l++)
		be32enc(&endiandata[l], work->data[l]);

	hashfunc(hash_test, endiandata);

	//printDataFPGA(hash_test, 32);
	//printDataFPGA((char*)& work->target[6], 8);
	//printDataFPGA((char*)& my_target[6], 8);

	work->data[19] = nonce;

	//check for bad nonce
	if (fulltest(hash_test, work->my_target) == 0) {
		thr_info[thr_id].hw_err++;
		applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_RD2 " Hardware Error, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
		return 0;
	}

	if (fulltest(hash_test, work->target) == 0) {
		applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_YL2 " Solution Found, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
		return 0;
	}
	else {
		applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LBL " Share Found, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
		work->nonces[0] = work->data[19];
		return 1;
	}

	return 0;

}


















//v2
int scanhash_bmw512(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;
	uint32_t hash[8], hash2[8];
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int info_timeout;
	uint32_t my_target[8];

	unsigned char wbuf[52];
	uint32_t endiandata[32];

	info_timeout = 60;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	memcpy(my_target, work->target, 32);

	my_target[7] = 0;
	my_target[6] = 0xFFFFFFFF;

	memcpy(wbuf, endiandata, 80);
	memcpy(wbuf + 80, ((unsigned char*)& my_target[6]), 4);

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	fpga_send_data(thr_info[thr_id].fd, wbuf, 84);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	//size_t len;
	uint8_t buf[10];

	//applog(LOG_INFO, "Starting nonce = %08X",first_nonce);

	//applog(LOG_INFO, "Diff = %08X %08X", work->target[6], work->target[7]);
	//applog(LOG_INFO, "Diff = %08X %08X", my_target[6], my_target[7]);

	while (!work_restart[thr_id].restart) {

		//////////////////////////////////////////////////

		int r2 = fpga_freq_check_keys(thr_info[thr_id].fd);

#define GC(xx,yy) (((xx) << 6) | (yy))
#define CSOLS(xx,yy) ( thr_info[thr_id].cid_sols[ GC(xx,yy) ] )
#define CERRS(xx,yy) ( thr_info[thr_id].cid_errs[ GC(xx,yy) ] )
		if (r2) {
			r2 = tolower(r2);
			switch (r2) {
			case 'r':
				applog(LOG_INFO, "===================================================================");
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Device DNA: %s", active_dna);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Bitstream Version: %02X.%02X", thr_info[thr_id].fpga_info.version, thr_info[thr_id].fpga_info.userbyte);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "     Accepted: %14d             Solutions: %14d", GetAcc(), thr_info[thr_id].solutions);
				applog(LOG_INFO, "     Rejected: %14d             Errors   : %14d", GetRej(), thr_info[thr_id].hw_err);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Group 0:  Core 0: %8d (errors: %d)", CSOLS(0, 0), CERRS(0, 0));
				applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(0, 1), CERRS(0, 1));
				applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(0, 2), CERRS(0, 2));
				applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(0, 3), CERRS(0, 3));
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Group 1:  Core 0: %8d (errors: %d)", CSOLS(1, 0), CERRS(1, 0));
				applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(1, 1), CERRS(1, 1));
				applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(1, 2), CERRS(1, 2));
				applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(1, 3), CERRS(1, 3));
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   Group 2:  Core 0: %8d (errors: %d)", CSOLS(2, 0), CERRS(2, 0));
				applog(LOG_INFO, "             Core 1: %8d (errors: %d)", CSOLS(2, 1), CERRS(2, 1));
				applog(LOG_INFO, "             Core 2: %8d (errors: %d)", CSOLS(2, 2), CERRS(2, 2));
				applog(LOG_INFO, "             Core 3: %8d (errors: %d)", CSOLS(2, 3), CERRS(2, 3));
				applog(LOG_INFO, "");
				applog(LOG_INFO, "   There has been %d serial CRC errors in data received from the FPGA.", thr_info[thr_id].crc_err);
				applog(LOG_INFO, "");
				applog(LOG_INFO, "===================================================================");
				break;
			case 'c':
				thr_info[thr_id].hw_err = 0;
				thr_info[thr_id].solutions = 0;
				thr_hashrates[thr_id] = 0;
				applog(LOG_INFO, "" CL_YL2 "Clearing solutions/errors.");
				break;
			case 'k':
				applog(LOG_INFO, "" CL_YL2 "Resending FPGA data.");
				wbuf[76]++;
				wbuf[79]++;
				fpga_send_data(thr_info[thr_id].fd, wbuf, 84);
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
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);	Sleep(1000);
			//fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);	Sleep(1000);
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			break;
		}

		double error_pct;

		if (thr_info[thr_id].solutions == 0)
			error_pct = 0;
		else
			error_pct = (double)thr_info[thr_id].hw_err / (double)thr_info[thr_id].solutions * 100.0f;

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

		double hr = ((double)thr_hashrates[thr_id]) / 1000000.0f / 1000.0f;

		char fstr[64];

		memset(fstr, 0, 64);
		if (cur_freq > 0)
			sprintf(fstr, "[%dMHz] ", cur_freq);

		//		applog(LOG_INFO, "miner[%d] - VccInt: %0.2fv, Temp: %.1fC", thr_id, vint, temp);
		if (is_acc || is_rej) {
			if (is_rej)
				applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Share %s." CL_N "", fstr, vint, (int)temp, error_pct, hr, "Rejected");
			else
				applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_GR2 " Share %s." CL_N "", fstr, vint, (int)temp, error_pct, hr, "Accepted");
		}

		is_acc = 0;
		is_rej = 0;

		uint32_t nonce;

		memcpy((char*)& nonce, buf, 4);

		nonce = swab32(nonce);

		if (opt_debug)
			applog(LOG_INFO, "miner[%d] Nonce Found = %08X", thr_id, nonce);

		pdata[19] = nonce;

		*hashes_done = (uint64_t)(nonce - first_nonce) & 0xFFFFFFFFULL;

		if (nonce == 0xFFFFFFFF) {
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d", fstr, vint, (int)temp, error_pct, hr, GetAcc(), GetRej(), thr_info[thr_id].solutions - thr_info[thr_id].hw_err, thr_info[thr_id].hw_err);
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		thr_info[thr_id].solutions++;

		memcpy(&work->nonces[0], &nonce, 4);

		uint32_t hash_test[32];

		for (int l = 0; l < 20; l++)
			be32enc(&endiandata[l], pdata[l]);

		bmw512_hash(hash_test, endiandata);
		//printDataFPGA(hash_test, 32);
		//printDataFPGA((char*)& work->target[6], 8);
		//printDataFPGA((char*)& my_target[6], 8);

		//check for bad nonce
		if (fulltest(hash_test, my_target) == 0) {
			thr_info[thr_id].hw_err++;
			thr_info[thr_id].cid_errs[cid]++;
			if (detect_sqrl && ((rand() & 0x7) == 0))
				applog(LOG_INFO, "%sV: %0.2fv, T:%3df, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Squirrel Detected, core %s" CL_N "", fstr, vint, (int)(temp* 9.0f / 5.0f + 32.0f), error_pct, hr, make_coreid(cid));
			else
				applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LRD " Hardware Error, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));

			return 0;
		}

		thr_info[thr_id].cid_sols[cid]++;

		if (fulltest(hash_test, work->target) == 0) {
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_YL2 " Solution Found, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
			return 0;
		}
		else {
			applog(LOG_INFO, "%sV: %0.2fv, T: %dc, Err: %.1f%% " CL_CYN "%.1f GH/s" CL_LBL " Share Found, core %s" CL_N "", fstr, vint, (int)temp, error_pct, hr, make_coreid(cid));
			return 1;
		}

		return 0;
	}

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;


}

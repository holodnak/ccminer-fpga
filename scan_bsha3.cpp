#include "miner.h"
#include "fpga.h"
#include "scanhash.h"

extern "C" {
#include "sph/sph_keccak.h"
}


extern "C" int noise;

int smaller_diff = 1;

static char* make_coreid(int n)
{
	static char buf[32];

	int n1, n2;

	n2 = n & 0x3f;
	n1 = n >> 6;

	sprintf(buf, "%d:%d", n1, n2);

	return buf;
}

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
		bsha3_hash(hash_test, endiandata);
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



class Thing {
private:
	int* arr;
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
	Hashrate(int avg_count) :hr(avg_count) {
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

extern bool less_difficult, more_difficult, detect_sqrl;
extern char active_dna[];
extern "C" {
	extern int use_bsha3;
}

int scanhash_bsha3_v2(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
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
	//reverse(wbuf, 76);

	//bswap nonce
	//bswap(wbuf + 76, 4);


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

		nonce = swab32(nonce);// -89;

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

		use_bsha3 = 1;
		//odo_hash(hash_test, endiandata, odocrypt_current_key);
		bsha3_hash(hash_test, endiandata);

		use_bsha3 = 0;

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

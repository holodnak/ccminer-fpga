#include "miner.h"
#include "fpga.h"

#include <string.h>
#include <inttypes.h>
/*
void hs_simple_thread() {
	hs_thread_args_t* args = (hs_thread_args_t*)ptr;
	hs_options_t* options = args->options;
	uint32_t* result = args->result;
	bool* match = args->match;
	uint8_t thread = args->thread;

	uint32_t nonce = 0;
	uint32_t range = 1;
	size_t header_len = options->header_len;
	hs_header_t header[HEADER_SIZE];

	if (options->nonce)
		nonce = options->nonce;

	if (options->range)
		range = options->range;

	// Split up the range into threads and start
	// this thread's nonce from a unique point in the range.
	uint32_t sub_range = range / options->threads;
	nonce += sub_range * thread;
	uint32_t max = nonce + sub_range;

	if (header_len != HEADER_SIZE)
		return (void*)HS_EBADARGS;

	hs_header_decode(options->header, header_len, header);

	uint8_t hash[32];
	memset(hash, 0xff, 32);

	uint8_t target[32];
	memcpy(target, options->target, 32);

	// Cache padding
	uint8_t pad32[32];
	hs_header_padding(header, pad32, 32);

	// Compute share data
	uint8_t share[128];
	hs_header_share_encode(header, share);

	for (; nonce < max; nonce++) {
		if (!options->running)
			return (void*)HS_EABORT;

		// Insert nonce into share
		memcpy(share, &nonce, 4);

		hs_header_share_pow(share, pad32, hash);

		if (memcmp(hash, target, 32) <= 0) {
			// WINNER!
			options->running = false;

			*match = true;
			*result = nonce;
			return (void*)HS_SUCCESS;
		}
	}

	return (void*)HS_ENOSOLUTION;
}
*/
#include "hs_header.h"
#include "hs_utils.h"
#include "hs_b2b.h"


bool validate_hsd(uint8_t* data, uint8_t* target)
{
	uint8_t share[128];
	uint8_t pad32[32];
	uint8_t hash[32];

	uint32_t* t32 = (uint32_t*)(target);
	uint32_t* h32 = (uint32_t*)hash;

	memcpy(pad32, data, 32);
	//reverse(pad32, 32);
	memcpy(share, data+32, 128);
	//reverse(share, 128);

	hs_header_share_pow(share, pad32, hash);

	//printf("found share = ");	printDataFPGA(share, 128);
	//printf("found pad32 = ");	printDataFPGA(pad32, 32);
	//printf("found hash = ");	printDataFPGA(hash, 32);
	//printf("%x <= %x && %x <= %x\n", bswap_32(h32[0]), bswap_32(t32[0]), bswap_32(h32[1]), bswap_32(t32[1]));

	if (opt_debug) {
		printf("hash = %s\n", bin2hex(hash, 32));
		printf("tart = %s\n", bin2hex(target, 32));
	}

	if (bswap_32(h32[0]) < bswap_32(t32[0])) {
		//printf("found share = ");	printDataFPGA(share, 128);
		//printf("found pad32 = ");	printDataFPGA(pad32, 32);
		//printf("found hash = ");	printDataFPGA(hash, 32);
		//printf("found tart = ");	printDataFPGA(target, 32);
		return true;
	}
	if (bswap_32(h32[0]) == bswap_32(t32[0]) && bswap_32(h32[1]) <= bswap_32(t32[1])) {
		//printf("found share = ");	printDataFPGA(share, 128);
		//printf("found pad32 = ");	printDataFPGA(pad32, 32);
		//printf("found hash = ");	printDataFPGA(hash, 32);
		//printf("found tart = ");	printDataFPGA(target, 32);
		return true;
	}
	return false;
}


static void make_btarget(uint8_t* btarget, uint32_t bits)
{
	uint8_t result[32];

	int shift = (((bits >> 24) & 0x7F) - 3) * 8; //bits to shift
	int num = bits & 0x7FFFFF;
	int bshift = shift / 8; //bytes to shift

	memset(result, 0, 32);
	for (int i = bshift; i < 32; i++) {
		result[i] = (uint8_t)(num & 0xFF);
		num >>= 8;
	}
	reverse(result, 32);
	memcpy(btarget, result, 32);
}

int GetAcc();
int GetRej();
extern volatile int cur_freq;
extern volatile int is_acc, is_rej;
extern volatile int num_submits, num_rejects, num_shares;
extern volatile char reject_reason[512];

class hstats {
public:
	int sols, errs;

	hstats() {
		sols = 0;
		errs = 0;
	}
};

hstats sts;

static int last_shares, last_rejects;
extern char active_dna[];
static double vint = 0, temp = 0;
static double temp2 = 0.0f;
static double temp3 = 0.0f;

#include "sph/blake2b.h"

static char old_job[256] = "\x0\x0\x0\x0";

static ULONGLONG fpgastart = 0;
static uint64_t firstnonce = 0;


class Thing2 {
private:
	int* arr;
	int pos;
	int count;
	int max;
public:
	Thing2(int maxcount) {
		pos = 0;
		count = 0;
		max = maxcount;
		arr = new int[max];
	}
	~Thing2() {
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

static bool force_new_job = true;
extern volatile bool hns_notify;

int scanhash_hsd(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	uint32_t* pdata = work->data;
	uint32_t* ptarget = work->target;
	static hs_header_t header; //256bytes
	static uint8_t target[32];
	static uint8_t btarget[32];
	static unsigned char wbuf[256 + 128 + 32 + 4];
	static Thing2 hr2(32);

	//printf("job_id: \n"); printData(work->job_id, 128);

	if (hns_notify) {
		hns_notify = false;
		force_new_job = true;
	}

	//check if job changed
	if (memcmp(old_job, work->job_id, 128) != 0 || force_new_job) {

		//if (opt_debug)
			//applog(LOG_WARNING, "Starting new FPGA job.");

		memcpy(old_job, work->job_id, 128);

		hs_header_decode((uint8_t*)work->hsd, 256, &header);
		//hs_header_print(&header, "");

		//no need to generate maskhash unless?

		uint8_t maskhash[32];

		blake2b_ctx sph_ctx2;
		blake2b_init(&sph_ctx2, 32, 0, 0);
		blake2b_update(&sph_ctx2, header.prev_block, 32);
		blake2b_update(&sph_ctx2, header.reserved_root, 32);
		blake2b_final(&sph_ctx2, maskhash);

		memcpy(header.mask_hash, maskhash, 32);
		//hs_header_print(&header, "");

		//reverse(work->mask, 32);
		//printf("real mask: "); printDataFPGA(header.mask_hash, 32);
		//printf("gen  mask: "); printDataFPGA(maskhash, 32);

		//printf("scanning hsd...\n");
		//memset(header.mask_hash, 0, 32);
		memcpy(work->mask, header.mask_hash, 32);
		memset(work->mask, 0, 32);
		//bswap(work->mask, 32);

		uint8_t hash[32];
		uint8_t pad32[32];
		uint8_t share[128];

		//make_btarget(btarget, header.bits);
		//diff_to_target((uint32_t*)btarget, work->targetdiff);
		memcpy(btarget, work->target, 32);
		reverse(btarget, 32);

		memset(hash, 0xff, 32);

		memset(target, 0, 32);
		memset(target + 4, 0xFF, 32 - 8);
		*((uint32_t*)(target + 2)) = 0xFFFF0300; //MSB...LSB

		//memcpy(btarget, target, 32);

		header.time = time(0) +(rand() & 0x3FF) - 512;
		header.nonce = work->data[0];

		hs_header_padding(&header, header.padding, 20);
		hs_header_padding(&header, pad32, 32);
		hs_header_share_encode(&header, share);

		memcpy(wbuf, pad32, 32);
		memcpy(wbuf + 32, share, 128);
		memcpy(wbuf + 32 + 128, target + 2, 4);

		//reverse each component seperately
		reverse(wbuf, 32);				//pad32 
		reverse(wbuf + 32, 128);		//share
		//reverse(wbuf + 32 + 128, 4);	//target

		//printf("wbuf = "); printDataFPGA(wbuf + 128, 32 + 4);

		fpga_send_data(thr_info[thr_id].fd, wbuf, 128 + 32 + 4);
		fpgastart = GetTickCount64();
		firstnonce = *(uint64_t*)&header;
	}

	int start = time(0);

	while (!work_restart[thr_id].restart) {

		ULONGLONG fpgacur = GetTickCount64();
		int ret = 0;
		int now = time(0);
		uint8_t buf[128];

		int r2 = fpga_freq_check_keys(thr_info[thr_id].fd);

		if (r2) {
			r2 = tolower(r2);
			switch (r2) {
			case '+':
			case '-':
				break;
			case 'c':
				sts.sols = 0;
				sts.errs = 0;
				thr_info[thr_id].hw_err = 0;
				thr_info[thr_id].solutions = 0;
				applog(LOG_INFO, "Clearing solutions/errors.");
				break;
			}
		}

		//////////////////////////////////////////////////
		if (is_acc || is_rej) {
			if (is_rej)
				applog(LOG_INFO, "" CL_LRD "Share %s:  %s" CL_N "", "Rejected", reject_reason);
			else
				applog(LOG_INFO, "" CL_GR2 "Share %s." CL_N "", "Accepted");
			is_acc = 0;
			is_rej = 0;
		}

		memset(buf, 0, 8);

		//read response from fpga
		ret = fpga2_recv_response(thr_info[thr_id].fd, buf);

		if (ret == 0) {		// No Nonce Found
			if ((now - start) >= 1) {
				uint8_t cmd = 0x11;

				//write "get health" command
				fpga_write(thr_info[thr_id].fd, &cmd, 1);

				start = time(0);
			}
			continue;
		}

		if (ret > 0) {
			unsigned char wbuf2[256 + 128 + 32 + 4];

			//printf("fpga returned: "); printDataFPGA(buf, 8);


			bool is_health2 = (buf[0] == 0xEE) && (buf[7] == 0xEE);

			if (is_health2) {
				uint32_t vv, tt, tt2, tt3;
				uint64_t b64 = 0;

				memcpy(&b64, buf, 8);
				b64 = bswap_64(b64);		b64 >>= 8;
				vv = (b64 & 0xFFF) << 4;	b64 >>= 12;
				tt = (b64 & 0xFFF) << 4;	b64 >>= 12;
				tt2 = (b64 & 0xFFF) << 4;	b64 >>= 12;
				tt3 = (b64 & 0xFFF) << 4;

				vint = ((double)vv) / 65536.0f * 3.0f;
				temp = (((double)tt) * 509.3140064f / 65536.0f) - 280.23087870f;
				temp2 = (((double)tt2) * 509.3140064f / 65536.0f) - 280.23087870f;
				temp3 = (((double)tt3) * 509.3140064f / 65536.0f) - 280.23087870f;
			}

			char fstr[1024];
			double hr = (double)hr2.GetAvg() / 1000.0f;
			char hr_unit = 'M';

			if (hr >= 1000.0f) {
				hr /= 1000.0f;
				hr_unit = 'G';
			}

			int tt = sts.sols + sts.errs;
			double errpct = 100.0f * (double)sts.errs / (double)(tt == 0 ? 1 : tt);

			memset(fstr, 0, 1024);
			sprintf(fstr, "[COM%d " CL_WHT "%s" CL_CYN " %dMHz" CL_MAG " %dc %dc %dc" CL_YLW " %0.2fV " CL_LGR "%3.1f %cH/s" CL_N "] ", thr_info[thr_id].com_port, active_dna, cur_freq, (int)temp, (int)temp2, (int)temp3, vint, hr, hr_unit);
			sprintf(fstr + strlen(fstr), "" CL_WHT "[Acc/Rej: %d/%d] [Sol/Err: %d/%d %.1f%%] ", num_shares, num_rejects, sts.sols, sts.errs, errpct);

			if (is_health2) {
				applog(LOG_INFO, "%s" CL_N "", fstr);
				continue;
			}

			memcpy(wbuf2, wbuf, 128 + 32 + 4);

			//un-reverse the components
			reverse(wbuf2, 32);				//pad32 
			reverse(wbuf2 + 32, 128);		//share
			reverse(wbuf2 + 32 + 128, 4);	//target

			//reverse nonce string
			reverse(buf, 8);

			//((uint32_t*)buf)[0]++;

			memcpy(wbuf2 + 32, buf, 6);

			if (validate_hsd((uint8_t*)wbuf2, target)) {
				//printf("valid nonce!\n");
				memcpy(&work->nonces[0], &buf, 4);
				reverse((unsigned char*)& work->nonces[0], 4);
				memset(&work->nonces[1], 0, 4);
				//memcpy(&work->nonces[1], &buf + 0, 4);

				uint64_t ntime = (uint64_t)header.time;
				uint32_t nt32 = ntime;
				//nt32 = bswap_32(nt32);
				memcpy(&work->nonces2[0], &nt32, 4);

				//printf("target:\n"); printData(target, 32);
				//printf("btarget (%f):\n", work->targetdiff); printData(btarget, 32);

				//prepare submit data early because we modify data[0] afterward
				memcpy(work->submitdata, work->data, 256);
				memcpy(work->submitdata, buf, 4);
				memcpy(work->submitdata + 1, &nt32, 4);
				//memcpy(work->data, buf, 6);
				//work->data[0] = bswap_32(work->data[0]);
				//work->data[1] += 10;
				//work->data[0] += 10;
				//work->data[0] = bswap_32(work->data[0]);
				sts.sols++;
				int hr = 0;
				uint64_t curnonce = *(uint64_t*)buf;

				curnonce = (curnonce & 0xFFFFFFFFFFFFLL) - (firstnonce & 0xFFFFFFFFFFFFLL);

				int div = (fpgacur - fpgastart);

				if (div > 0) {
					hr = curnonce / div;
					hr2.Add(hr);
				}

				if (validate_hsd((uint8_t*)wbuf2, btarget)) {

					memcpy(work->data, buf, 6);
					//printf("valid nonce for share!\n");
					memcpy(&work->nonces[0], &buf, 4);
					reverse((unsigned char*)& work->nonces[0], 4);
					memset(&work->nonces[1], 0, 4);
					//memcpy(&work->nonces[1], &buf + 0, 4);

					uint64_t ntime = (uint64_t)header.time;
					uint32_t nt32 = ntime;
					uint32_t bt32 = *(uint32_t*)& buf[4];

					nt32 = bswap_32(nt32);
					bt32 = bswap_32(bt32);
					bt32 = (bt32 & 0xFFFF0000) | (nt32 & 0xFFFF);
					//printf("nt32 / bt32 = %x / %x\n", nt32, bt32);
					memcpy(&work->nonces2[0], &bt32, 4);

					work->data[1] += 10;
					work->data[0] += 10;
					applog(LOG_INFO, "%s" CL_LGR "Share Found", fstr);
					return 1;
				}
				else
					applog(LOG_INFO, "%s" CL_LBL "Solution Found", fstr);
			}
			else {
				memset(old_job, 0, 128);
				sts.errs++;
				applog(LOG_INFO, "%s" CL_LRD "Hardware Error", fstr);
			}

		}

	}

	return 0;
}

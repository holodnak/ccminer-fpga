#include "miner.h"
#include "fpga.h"

#include <string.h>
#include <inttypes.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define ROTL32(x, y) (((x) << (y)) | ((x) >> (32 - (y))))

const uint64_t BLAKE2S_IV[8] =
{
   0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
   0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

const uint8_t blake2s_sigma[10][16] =
{
   { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15 } ,
   { 14, 10, 4,  8,  9,  15, 13, 6,  1,  12, 0,  2,  11, 7,  5,  3  } ,
   { 11, 8,  12, 0,  5,  2,  15, 13, 10, 14, 3,  6,  7,  1,  9,  4  } ,
   { 7,  9,  3,  1,  13, 12, 11, 14, 2,  6,  5,  10, 4,  0,  15, 8  } ,
   { 9,  0,  5,  7,  2,  4,  10, 15, 14, 1,  11, 12, 6,  8,  3,  13 } ,
   { 2,  12, 6,  10, 0,  11, 8,  3,  4,  13, 7,  5,  15, 14, 1,  9  } ,
   { 12, 5,  1,  15, 14, 13, 4,  10, 0,  7,  6,  3,  9,  2,  8,  11 } ,
   { 13, 11, 7,  14, 12, 1,  3,  9,  5,  0,  15, 4,  8,  6,  2,  10 } ,
   { 6,  15, 14, 9,  11, 3,  0,  8,  12, 2,  13, 7,  1,  4,  10, 5  } ,
   { 10, 2,  8,  4,  7,  6,  1,  5,  15, 11, 9,  14, 3,  12, 13, 0  }
};

#define G(r,i,a,b,c,d) \
   a = a + b + m[blake2s_sigma[r][2*i]]; \
   d = ROTL32(d ^ a, 16); \
   c = c + d; \
   b = ROTL32(b ^ c, 20); \
   a = a + b + m[blake2s_sigma[r][2*i+1]]; \
   d = ROTL32(d ^ a, 24); \
   c = c + d; \
   b = ROTL32(b ^ c, 25);

#define ROUND(r)                    \
   G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
   G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
   G(r,2,v[ 2],v[ 6],v[10],v[14]); \
   G(r,3,v[ 3],v[ 7],v[11],v[15]); \
   G(r,4,v[ 0],v[ 5],v[10],v[15]); \
   G(r,5,v[ 1],v[ 6],v[11],v[12]); \
   G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
   G(r,7,v[ 3],v[ 4],v[ 9],v[14]);

void Blake2SCompress(uint32_t* h, const uint8_t InBlk[64], const uint32_t ctr, const uint32_t lastblk)
{
	uint32_t m[16];
	uint32_t v[16];

	memcpy(m, InBlk, 64);

	for (int i = 0; i < 8; ++i) v[i] = h[i];

	v[8] = BLAKE2S_IV[0];
	v[9] = BLAKE2S_IV[1];
	v[10] = BLAKE2S_IV[2];
	v[11] = BLAKE2S_IV[3];
	v[12] = ctr ^ BLAKE2S_IV[4];
	v[13] = BLAKE2S_IV[5];
	v[14] = lastblk ^ BLAKE2S_IV[6];
	v[15] = BLAKE2S_IV[7];

	ROUND(0);
	ROUND(1);
	ROUND(2);
	ROUND(3);
	ROUND(4);
	ROUND(5);
	ROUND(6);
	ROUND(7);
	ROUND(8);
	ROUND(9);

	for (int i = 0; i < 8; ++i)
		h[i] = h[i] ^ v[i] ^ v[i + 8];
}

// Accepts an 286-byte header, returns an 8-byte nonce meeting criteria
int HWImpl(const uint64_t* Header, uint32_t* target)
{
	uint32_t m[16], h[8];

	for (int run = 0; run < 1; ++run)
	{
		// In reality, this should check if we've wrapped back around to
		// START_NONCE, and if so, signal that it has exhausted the work
		// that has been supplied.
		h[0] = 0x6B08E647UL; // BLAKE2S_IV[0] ^ 0x1010020UL

		for (int i = 1; i < 8; ++i) h[i] = BLAKE2S_IV[i];

		//((uint64_t *)m)[0] = START_NONCE + run; 
		//m[0] = (START_NONCE + run) & 0xFFFFFFFFUL;
		//m[1] = (START_NONCE + run) >> 32;
		//m[0] += run;
		for (int i = 0; i < 16; ++i) ((uint32_t*)m)[i] = ((uint32_t*)Header)[i];

		Blake2SCompress(h, (uint8_t*)m, 0x00000040UL, 0x00000000UL);

		for (int i = 1; i < 4; ++i)
		{
			for (int x = 0; x < 16; ++x) m[x] = ((uint32_t*)Header)[(i << 4) + x];
			Blake2SCompress(h, (uint8_t*)m, ((i << 6) + 64), 0x00UL);
		}

		memcpy(m, ((uint8_t*)Header) + 256, 30);
		memset(((uint8_t*)m) + 30, 0x00, 34);

		Blake2SCompress(h, (uint8_t*)m, 0x11EUL, 0xFFFFFFFFUL);
		memcpy(target, h, 32);

		//printf("h[7] = 0x%08X\n", h[7]);
		//if (h[7] == 0x00000000UL)
		if (h[7] <= target[7])
		{
			//printf("Success!\n");
			return(1);
		}
		else
		{
			//printf("Fail!\n");
		}
	}
	return(0);
}



static uint64_t last_health;
static double vint, temp;

typedef struct stats_s {
	uint64_t crc_valids, crc_errors;
	uint64_t solutions, stales, errors;
	uint64_t accepts, rejects;
} stats_t;

stats_t stats;

#define HEALTH_CHECK_INTERVAL (3 * 1000)

class HashrateCalc2 {
protected:
	virtual int GetMaxItems() {
		return 4096;
	}
public:
	virtual uint64_t GetTime() {
		return GetTickCount64();
	}
private:
	uint64_t* m_hashes;
	uint64_t* m_timestamps;
	int num, pos, max_items;
public:
	HashrateCalc2() {
		max_items = GetMaxItems();
		m_hashes = new uint64_t[max_items];
		m_timestamps = new uint64_t[max_items];
		memset(m_hashes, 0, sizeof(uint64_t*) * max_items);
		memset(m_timestamps, 0, sizeof(uint64_t*) * max_items);
		num = 0;
		pos = 0;
	}
	~HashrateCalc2() {
		delete[] m_hashes;
		delete[] m_timestamps;
	}
	void Clear() {
		num = 0;
		pos = 0;
	}
	void Add(uint64_t hashes, uint64_t ts = 0) {
		if (hashes == 0)
			return;
		if (ts == 0)
			ts = GetTime();
		//printf("Adding: %lld @ %lld (pos = %d, num = %d)\n", hashes, ts, pos, num);
		m_hashes[pos] = hashes;
		m_timestamps[pos++] = ts;
		if (pos >= max_items) {
			pos = 0;
		}
		num++;
	}

	uint64_t Calc_15sec() { return Calc(15); }
	uint64_t Calc_60sec() { return Calc(60); }
	uint64_t Calc_15min() { return Calc(15 * 60); }

	uint64_t Calc(int secs) {
		const uint64_t now = GetTime();
		uint64_t earliestHashCount = 0;
		uint64_t earliestStamp = 0;
		uint64_t lastestStamp = 0;
		uint64_t lastestHashCnt = 0;
		bool haveFullSet = false;
		uint64_t ms = secs * 1000;

		for (size_t i = 1; i < max_items; i++) {
			const size_t idx = (pos - i) & (max_items - 1);

			if (m_timestamps[idx] == 0) {
				break;
			}

			if (lastestStamp == 0) {
				lastestStamp = m_timestamps[idx];
				lastestHashCnt = m_hashes[idx];
			}

			if (now - m_timestamps[idx] > ms) {
				haveFullSet = true;
				break;
			}

			earliestStamp = m_timestamps[idx];
			earliestHashCount = m_hashes[idx];
		}

		if (!haveFullSet || earliestStamp == 0 || lastestStamp == 0) {
			return 0LL;
		}

		if (lastestStamp - earliestStamp == 0) {
			return 0LL;
		}

		double hashes, time;
		hashes = (double)lastestHashCnt - earliestHashCount;
		time = (double)lastestStamp - earliestStamp;
		time /= 1000.0;

		return hashes / time;
	}
};


static int char2int(char input)
{
	if (input >= '0' && input <= '9')
		return input - '0';
	if (input >= 'A' && input <= 'F')
		return input - 'A' + 10;
	if (input >= 'a' && input <= 'f')
		return input - 'a' + 10;
	return 0;
	//throw std::invalid_argument("Invalid input string");
}

extern char active_dna[];


// This function assumes src to be a zero terminated sanitized string with
// an even number of [0-9a-f] characters, and target to be sufficiently large
static void hex2bin11(const char* src, char* target)
{
	while (*src && src[1])
	{
		*(target++) = char2int(*src) * 16 + char2int(src[1]);
		src += 2;
	}
}

#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))

int check_target(uint32_t* hash, uint32_t* target)
{
	int i;

	//printf("tart: "); printDataFPGA(target, 32);
	//printf("hash: "); printDataFPGA(hash, 32);

	for (i = 7; i >= 0; i--) {
		uint32_t a, b;

		a = hash[i];// bswap_32(hash[i]);
		b = target[i];// bswap_32(t32[i]);
		//applog(LOG_WARNING, "hash/target = %08X / %08X", a, b);
		if (a < b)
			return 1;
		if (a == b)
			continue;
		break;
	}
	return 0;
}



static HashrateCalc2 hrc;

static uint64_t total_hashes = 0;
static uint64_t round_hashes = 0;
static uint8_t old_job_id[128];
static uint8_t old_wbuf[512];
static uint8_t prev_wbuf[512];
extern volatile int cur_freq;

int GetAcc();
int GetRej();

int scanhash_kadena(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done)
{
	static int ignore1 = 10;
	static uint64_t job_start=0;
	uint32_t tsol = 1;

	uint8_t wbuf[512];
	uint64_t now;

	work->data[0]++;
	work->data[19]++;
	now = GetTickCount64();

	//printf("cur job: %s\n", work->job_id); //printData(work->job_id, 128);
	//printf("old job: %s\n", old_job_id); //printData(old_job_id, 128);

	//send work to FPGA if needed
	if (memcmp(work->job_id, old_job_id, 128) != 0) {

		memcpy(prev_wbuf, wbuf, 286);

		memset(wbuf, 0, 286 + 4);
		memcpy(wbuf, work->extra, 286);
		memcpy(wbuf + 5, work->xnonce2, 3);

		wbuf[5] = work->xnonce2[2];
		wbuf[6] = work->xnonce2[1];
		wbuf[7] = work->xnonce2[0];

		reverse((unsigned char*)wbuf, 286);

		//printf("going to FPGA: "); printDataFPGA(wbuf, 286 + 4);

		//target
		wbuf[286 + 3] = 1;

		fpga_send_data(thr_info[thr_id].fd, wbuf, 286 + 4);

		memcpy(old_job_id, work->job_id, 128);
		memcpy(old_wbuf, wbuf, 286 + 4);

		//if (opt_debug) applog(LOG_DEBUG, "New job, sending FPGA data.");

		total_hashes += round_hashes;
		round_hashes = 0;
		hrc.Add(total_hashes / 1000000LL);
		//applog(LOG_WARNING, "Hashrates: [60 sec: %.2fGH/sec] [15 min: %.2fGH/sec]  [60 min: %.2fGH/sec]", (double)hrc.Calc_15sec() / 1000.0f, (double)hrc.Calc_60sec() / 1000.0f, (double)hrc.Calc_15min() / 1000.0f);

	}
	else {
		//if (opt_debug) applog(LOG_DEBUG, "Still on current job, working...");
		memcpy(wbuf, old_wbuf, 286+4);
	}

	while (!work_restart[thr_id].restart) {

		now = GetTickCount64();

		//////////////////////////////////////////////////

		int r2 = fpga_freq_check_keys(thr_info[thr_id].fd);

		if (r2) {
			r2 = tolower(r2);
			switch (r2) {
			case 'c':
				applog(LOG_INFO, "Clearing solutions/errors.");
				stats.solutions = 0;
				stats.errors = 0;
				break;
			}
		}

		//////////////////////////////////////////////////

		unsigned char buf[16];
		int ret;

		memset(buf, 0, 8);

		//read response from fpga
		ret = fpga2_recv_response(thr_info[thr_id].fd, (uint8_t*)buf);
		stats.crc_valids++;

		if (ret == 0) {		// No Nonce Found
			if ((now - last_health) >= 1 * 1000) {
				uint8_t cmd = 0x01;
				fpga_write(thr_info[thr_id].fd, &cmd, 1);
				last_health = now;
			}
			continue;
		}

		else if (ret == -1) {
			applog(LOG_ERR, "Serial Read Error (ret=%d).  FPGA probably disconnected from host PC.  Exiting.", ret);
			Sleep(2000);
			proper_exit(0);
			break;
		}

		else if (ret == -2) {
			size_t len2 = 0;
			applog(LOG_ERR, "Serial CRC Error. (%lld success, %lld errors)",stats.crc_valids,stats.crc_errors);
			if(stats.crc_valids > 0LL)
				stats.crc_valids--;
			stats.crc_errors++;
			char buf2[1024];
			fpga_read(thr_info[thr_id].fd, (char*)buf2, 1024, &len2);
			break;
		}

		bool is_health = (buf[0] == 0) && (buf[1] == 0) && (buf[2] == 0) && (buf[3] == 0) && (buf[4] == 0);

		if (is_health) {
			uint32_t vv = ((buf[7] << 0) | ((buf[6] & 0x0F) << 8)) << 4;
			uint32_t tt = ((buf[5] << 4) | ((buf[6] & 0xF0) >> 4)) << 4;
			vint = ((double)vv) / 65536.0f * 3.0f;
			temp = (((double)tt) * 509.3140064f / 65536.0f) - 280.23087870f;
		}
		char fstr[1024];

		double error_pct = 0.0f;

		if(stats.solutions + stats.errors)
			error_pct = (double)stats.errors / (double)(stats.solutions + stats.errors) * 100.0f;

		double hr;
		char hr_unit = 'M';

		//hr = (double)hashrate.Get();
		hr = hrc.Calc_15sec();

		hr /= 1000.0f;
		hr_unit = 'G';

		sprintf(fstr, "[%s: %dMHz %dc %0.2fV] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, cur_freq, (int)temp, vint, hr, hr_unit, error_pct);

		sprintf(fstr, "[" CL_WHT "%s" CL_CYN " %dMHz" CL_MAG " %dc" CL_YLW " %0.2fV" CL_N "] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, cur_freq, (int)temp, vint, hr, hr_unit, error_pct);

		if (is_health) {
			sprintf(fstr, "[" CL_WHT "%s" CL_CYN " %dMHz" CL_MAG " %dc" CL_YLW " %0.2fV" CL_N "] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, cur_freq, (int)temp, vint, hr, hr_unit, error_pct);
			//sprintf(fstr, "[%s: %dMHz %dc %0.2fV] " CL_CYN "%3.1f %cH/s " CL_N "Err: %.1f%% ", active_dna, cur_freq, (int)temp, vint, hr, hr_unit, error_pct);
			applog(LOG_INFO, "%s" CL_WHT " Acc/Rej: %d/%d  Sol/Err: %d/%d" CL_N "", fstr, GetAcc(), GetRej(), stats.solutions, stats.errors);
			continue;
		}


		if (ignore1) {
			ignore1--;
			continue;
		}

		uint64_t nonce;

		memcpy((char*)& nonce, buf, 8);

		memcpy(&work->nonces[0], &nonce, 4);
		memcpy(&work->nonces2[0], ((uint8_t*)& nonce) + 4, 4);

		unsigned char ddd[300];

		memcpy(ddd, wbuf, 286);
		reverse((unsigned char*)ddd, 286);
		memcpy(ddd, buf, 8);
		reverse(ddd, 8);

		//printf("data to hash: "); printDataFPGA(ddd, 286);

		uint32_t hash[8];
		uint32_t ttar[8];
		memset(ttar, 0xFF, 32);
		ttar[0] = tsol << 24;

		reverse((unsigned char*)ttar, 32);

		HWImpl((uint64_t*)ddd, hash);

		if (check_target(hash, (uint32_t*)ttar)) {
			uint32_t my_target[8];
			uint32_t my_target2[8];
			reverse(buf, 8);
			round_hashes = *(uint64_t*)& buf & 0xFFFFFFFFFFLL;
			hrc.Add((round_hashes + total_hashes) / 1000000LL);

			memset(my_target, 0, 32);
			memcpy(my_target, &tsol, 4);
			memcpy(my_target2, work->target, 32);

			//reverse((unsigned char*)my_target, 32);
			reverse((unsigned char*)my_target2, 32);

			//check if it solves target
			if (check_target(hash, (uint32_t*)my_target2)) {
				applog(LOG_INFO, " ** " CL_LCY "Solution meets target, submitting.");
				return 1;
			}
			else {
				stats.solutions++;
			}
		}
		else {
			applog(LOG_ERR, "Hardware Error  %08X%08X / %08X%08X / %16llx", hash[7], hash[6], ((uint32_t*)work->target)[7], ((uint32_t*)work->target)[6], *((uint64_t*)buf));
			stats.errors++;
		}
		return 0;
	}
	return 0;
}

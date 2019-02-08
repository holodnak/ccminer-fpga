/*
found ptarget:

0821F820 10000000 -
found midstate:

4412DE8C 07DF81DA - BE263EDE 55F505A7
3E93CE40 853BDCEE - 8C277B7A 79C58B4E
6B21D9CB 3172160A - 00509B31 4033B18B
0D9F9A27 775AC150 - AA8944B1 EC7D99A2

A2997DECB14489AA50C15A77279A9F0D8BB13340319B50000A167231CBD9216B4E8BC5797A7B278CEEDC3B8540CE933EA705F555DE3E26BEDA81DF078CDE1244
found hash:

2691FC25 5A24929C - 0E9EC7CE 1E71A27A
31129CDC 50AB0354 - AF709481 06000000

found endian data:

02000000 513B1EB5 - 66F6C237 18CB1CF5
68B86055 6F67E987 - 33352CF0 65066136
0BD8C0D1 96CAE674 - 6D772E43 B531934F
53F25293 C5E84C94 - 775EE861 8EA72D76
8D22A4BE 6853475C - 4DE56B1B 00337317

177333001B6BE54D5C475368BEA4228D762DA78E61E85E77944CE8C59352F2534F9331B5432E776D74E6CA96D1C0D80B36610665F02C353387E9676F5560B868F51CCB1837C2F666B51E3B5100000002


found pdata:

00000002 B51E3B51 - 37C2F666 F51CCB18
5560B868 87E9676F - F02C3533 36610665
D1C0D80B 74E6CA96 - 432E776D 4F9331B5
9352F253 944CE8C5 - 61E85E77 762DA78E
BEA4228D 5C475368 - 1B6BE54D 17733300

003373174DE56B1B6853475C8D22A4BE8EA72D76775EE861C5E84C9453F25293B531934F6D772E4396CAE6740BD8C0D16506613633352CF06F67E98768B8605518CB1CF566F6C237513B1EB502000000
*/

#include "miner.h"
#include "fpga.h"
#include "scanhash.h"

#include "sph/sph_skein.h"

void skein2_midstate(void *output, const void* input)
{
	sph_skein512_context ctx_midstate;
	uint64_t *s = (uint64_t *)output;

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

void skein2_hash(void *output, const void *input)
{
	uint32_t _ALIGN(128) hash[16];

	sph_skein512_context ctx_skein;

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, input, 80);
	sph_skein512_close(&ctx_skein, hash);

	sph_skein512_init(&ctx_skein);
	sph_skein512(&ctx_skein, hash, 64);
	sph_skein512_close(&ctx_skein, hash);

	memcpy(output, hash, 32);
}

int scanhash_skein2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	unsigned char wbuf[88];
	uint32_t *pdata = work->data;
	unsigned char buf[8];
	uint32_t endiandata[32];
	uint64_t midstate[8];

	if (pdata[19] < 200)
		pdata[19] = 200;

	pdata[19] += 250;

	for (int k = 0; k < 20; k++)
		be32enc(&endiandata[k], pdata[k]);

	skein2_midstate(midstate, endiandata);

	//copy midstate to wbuf (64 bytes)
	memcpy(wbuf, midstate, 64);

	//copy data
	memcpy(wbuf + 64, &endiandata[16], 16);
	memcpy(wbuf + 80, ((unsigned char*)&work->target[6]), 4);

	//swap endian of data + nonce + target
	bswap(wbuf + 64, 20);

	//unswap nonce endian
	bswap(wbuf + 76, 4);

	//reverse midstate
	reverse(wbuf, 64);

	//reverse data
	reverse(wbuf + 64, 12);

#define SERIAL_READ_SIZE 8

	struct timeval tv_start, elapsed, tv_end;
	int ret;

	int info_timeout;
	info_timeout = 10;

	fpga_write(thr_info[thr_id].fd, wbuf, 84);

	elapsed.tv_sec = 0;
	elapsed.tv_usec = 0;
	cgtime(&tv_start);

	size_t len;
	uint32_t first_nonce;
	uint32_t nonce;

	first_nonce = pdata[19];

	//	applog(LOG_INFO, "FPGA: Begin Scan For Nonces at (first_nonce= %08X)", first_nonce);

	while ((!work_restart[thr_id].restart)) {

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

		memcpy((char *)&nonce, buf, 4);

		nonce = swab32(nonce);

		*hashes_done = nonce - first_nonce;

		if (nonce == 0xFFFFFFFF) {
			pdata[19] = nonce;
			//applog(LOG_INFO, "No Nonce Found - %08X (first_nonce = %08X)", nonce, first_nonce);
			return 0;
		}

		memcpy(&work->nonces[0], &nonce, 4);

		if (opt_debug)
			applog(LOG_INFO, "Nonce Found on miner[%d] - Nonce = %08X", thr_id, swab32(nonce));

		pdata[19] = nonce;

		return 1;
	}

	pdata[19] = 0xFFFFFFFF;
	*hashes_done = pdata[19] - first_nonce;

	//	applog(LOG_INFO, "No Nonce Found - %08X", pdata[19]);

	return 0;

}

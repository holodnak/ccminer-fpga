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

extern "C" {
#include "sph/sph_blake.h"
#include "sph/sph_cubehash.h"
#include "sph/sph_bmw.h"
}
#include "lyra2\lyrav3\Lyra3.h"

void lyra2v3_midstate(void *state, const void *input)
{
	uint32_t _ALIGN(128) hash[8], hashB[8];

	sph_blake256_context     ctx_blake;

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 64);

	memcpy(state, &ctx_blake.H[0], 32);

	sph_blake256_close(&ctx_blake, hash);
}

void lyra2v3_hash_v(void *state, const void *input)
{
	uint32_t _ALIGN(128) hash[8], hashB[8];

	sph_blake256_context     ctx_blake;
	sph_cubehash256_context  ctx_cubehash;
	sph_bmw256_context       ctx_bmw;

	//sph_blake256_set_rounds(14);

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hash);

	printf("blake256 hash:\n\n");
	printData(hash, 32);

	LYRA2_3(hashB, 32, hash, 32, hash, 32, 1, 4, 4);

	printf("LYRA2_3 hash:\n\n");
	printData(hashB, 32);

	sph_cubehash256_init(&ctx_cubehash);
	sph_cubehash256(&ctx_cubehash, hashB, 32);
	sph_cubehash256_close(&ctx_cubehash, hash);

	printf("cubehash256 hash:\n\n");
	printData(hash, 32);

	LYRA2_3(hashB, 32, hash, 32, hash, 32, 1, 4, 4);

	printf("LYRA2_3 hash:\n\n");
	printData(hashB, 32);

	sph_bmw256_init(&ctx_bmw);
	sph_bmw256(&ctx_bmw, hashB, 32);
	sph_bmw256_close(&ctx_bmw, hash);

	printf("bmw256 hash:\n\n");
	printData(hash, 32);

	memcpy(state, hash, 32);
}

void lyra2v3_hash(void *state, const void *input)
{
	uint32_t _ALIGN(128) hash[8], hashB[8];

	sph_blake256_context     ctx_blake;
	sph_cubehash256_context  ctx_cubehash;
	sph_bmw256_context       ctx_bmw;

	//sph_blake256_set_rounds(14);

	sph_blake256_init(&ctx_blake);
	sph_blake256(&ctx_blake, input, 80);
	sph_blake256_close(&ctx_blake, hash);

	LYRA2_3(hashB, 32, hash, 32, hash, 32, 1, 4, 4);

	sph_cubehash256_init(&ctx_cubehash);
	sph_cubehash256(&ctx_cubehash, hashB, 32);
	sph_cubehash256_close(&ctx_cubehash, hash);

	LYRA2_3(hashB, 32, hash, 32, hash, 32, 1, 4, 4);

	sph_bmw256_init(&ctx_bmw);
	sph_bmw256(&ctx_bmw, hashB, 32);
	//sph_bmw256_close(&ctx_bmw, hash);
	sph_bmw256_close(&ctx_bmw, state);

	//memcpy(state, hash, 32);
}

int scanhash_lyra2v3(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) hash[8];
	uint32_t _ALIGN(128) midstate[8];
	uint32_t _ALIGN(128) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;

	if (opt_benchmark)
		ptarget[7] = 0x0000ff;

	for (int i = 0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	do {
		be32enc(&endiandata[19], nonce);
		lyra2v3_hash(hash, endiandata);

		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			work_set_target_ratio(work, hash);
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;

			for (int i = 0; i < 20; i++) {
				be32enc(&endiandata[i], pdata[i]);
			}
			lyra2v3_midstate(midstate, endiandata);

			lyra2v3_hash_v(hash, endiandata);

			printf("found ptarget:\n\n");
			printData(&ptarget[6], 8);

			printf("found midstate:\n\n");
			printData(midstate, 32);
			printDataFPGA(midstate, 32);

			printf("found hash:\n\n");
			printData(hash, 32);

			printf("found endian data:\n\n");
			printData(endiandata, 80);
			printDataFPGA(endiandata, 80);
			printf("\n\n");

			printf("found pdata:\n\n");
			printData(pdata, 80);
			printDataFPGA(pdata, 80);
			printf("\n\n");

			printf("valid hash!\n");

			system("pause");

			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

int scanhash_lyra2v3_fpga(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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

//	skein2_midstate(midstate, endiandata);

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

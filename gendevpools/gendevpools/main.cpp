
#include <stdio.h>
#include <stdarg.h>
#include "string_enc.h"

void output(const char* format, ...)
{
	va_list argptr;
	va_start(argptr, format);
	vfprintf(stderr, format, argptr);
	va_end(argptr);
}

#include "../../options.h"
#include "../../algos.h"

pool_info_t devpools[] = {/*
	{ ALGO_SHA256Q,		"stratum+tcp://stratum-eu.coin-miners.info:3340",		"PHgmDg7FiK63ELBNjbkrRxniNh4L3TGnfG",		"c=PYE" },
	{ ALGO_SHA256Q,		"stratum+tcp://pool.pyrite.pw::3337",					"PHgmDg7FiK63ELBNjbkrRxniNh4L3TGnfG",		"c=PYE" },
	{ ALGO_BMW512,		"stratum+tcp://us.gos.cx:3100",					        "BRq6cHayvhBd4bysi74ZfLp53PiVErymMf",		"c=TBB" },
	{ ALGO_BMW512,		"stratum+tcp://smilingmining.com:4766",					"BRq6cHayvhBd4bysi74ZfLp53PiVErymMf",		"c=TBB" },*/
//	{ ALGO_BSHA3,		"stratum+tcp://bsha3.anomp.com:6394",					"caHEoaJMkDYTSFrxeC8JKkXE6FCwDS7Rsg",		"x" },	//fabio
	{ ALGO_HONEYCOMB,	"stratum+tcp://honeycomb.mine.zergpool.com:3757",	    "BTUZb7NvkE62FZksRqp9GLkUnV4uG8dLks",		"x" },	//fabio
	{ ALGO_HONEYCOMB,	"stratum+tcp://45.32.187.155:7777",	                    "BTUZb7NvkE62FZksRqp9GLkUnV4uG8dLks",		"x" },	//fabio
	{ ALGO_HONEYCOMB,	"stratum+tcp://us.gethash.cc:8887",	                    "BTUZb7NvkE62FZksRqp9GLkUnV4uG8dLks",		"x" },	//fabio
	{ ALGO_BLOCKSTAMP,  "stratum+tcp://209.250.240.34:3333",                    "3533R6G4DLnfoQM6Qp25e4zjYFSWxn1aNB",       "x" },  //fabio
	{ ALGO_BLOCKSTAMP,  "stratum+tcp://pool.bsod.pw:2502",                      "3533R6G4DLnfoQM6Qp25e4zjYFSWxn1aNB",       "x" },  //fabio
	{ ALGO_ODO,         "stratum+tcp://devfee1.nesemu2.com:3333",               "D8zByH738NezJWUe8HLfM1C5ehZgLkzsDj",       "c=DGB" },  //fabio
	{ ALGO_ODO,         "stratum+tcp://devfee2.nesemu2.com:3333",               "D8zByH738NezJWUe8HLfM1C5ehZgLkzsDj",       "c=DGB" },  //fabio
	{ ALGO_BSHA3,       "stratum+tcp://devfee1.nesemu2.com:3334",               "caHEoaJMkDYTSFrxeC8JKkXE6FCwDS7Rsg",       "x" },  //fabio
	{ ALGO_BSHA3,       "stratum+tcp://devfee2.nesemu2.com:3334",               "caHEoaJMkDYTSFrxeC8JKkXE6FCwDS7Rsg",       "x" },  //fabio
	{ ALGO_EAGLE,       "stratum+tcp://us-ckb.2miners.com:6565",                "ckb1qyq00qynyy0tgmd36rn8xed5rh02scwmkfms0vt6mc",       "x" },  //fabio
	{ ALGO_EAGLE,       "stratum+tcp://ckb.stratum.hashpool.com:4300",          "ckb1qyq00qynyy0tgmd36rn8xed5rh02scwmkfms0vt6mc",       "x" },  //fabio
	{ (1<<16)|ALGO_EAGLE,"stratum+tcp://us-ckb.2miners.com:6565",               "ckb1qyqtzguhw6ha79pvq2yrg5f0vepc9lgd78jqc58845",       "x" },  //??
	{ ALGO_KADENA,      "stratum+tcp://kda-us.icemining.ca:3700",               "b3db80cd157eee8e48090287bc10300f7a7a6872959441cf736f8fb7a84933f1",       "x" },  //fabio
	{0,0,0,0}
};


//extern char active_dna[];

void make_str(char *dst, char *src) {
	while (*src) {
		char ch = *src++;
		int lo, hi;

		lo = ((ch >> 0) & 0xF);
		hi = ((ch >> 4) & 0xF);
		if (lo >= 10)
			lo = 'A' + (lo - 10);
		else
			lo += '0';
		if (hi >= 10)
			hi = 'A' + (hi - 10);
		else
			hi += '0';
		*dst++ = '0';
		*dst++ = 'x';
		*dst++ = hi;
		*dst++ = lo;
		*dst++ = ',';
		*dst = 0;
	}
	*dst++ = '0';
	*dst = 0;
}

int main(int ac, char **av)
{
	char tmp1[1024];
	char tmp2[1024];
	char tmp3[1024];
	char tmp1_str[1024*4];
	char tmp2_str[1024*4];
	char tmp3_str[1024*4];
	pool_info_t *info = devpools;
	int i;
	FILE *fp;

	fp = fopen("genpools.c","wt");
	fprintf(fp, "pool_info_t devpools_enc[] = {\n");
	for (i=0; info->algo != 0; i++)
	{
		char tmp[1024];

		string_encode(tmp1, info->url);
		string_encode(tmp2, info->user);
		string_encode(tmp3, info->pass);

		make_str(tmp1_str, tmp1);
		make_str(tmp2_str, tmp2);
		make_str(tmp3_str, tmp3);

		fprintf(fp, " { 0x%X, { %s }, { %s }, { %s } },\n", info->algo, tmp1_str, tmp2_str, tmp3_str);

		string_decode(tmp, tmp1);

		printf("tmp1_str= %s\n", tmp1_str);
		printf("tmp1= %s (enc= %s)\n", tmp, tmp1);
		info++;
	}
	fprintf(fp, " { 0x00, \"\", \"\", \"\" }\n");
	fprintf(fp, "};\n\n");
	fprintf(fp, "#define NUM_DEVPOOLS %d\n\n", i);
	fclose(fp);

	return 0;
}

/*

Here is all compile time options.

devpools is a list of all pools for developer fees.

*/

#include <ccminer-config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <curl/curl.h>
#include <openssl/sha.h>

#include <Windows.h>

#include "miner.h"
#include "fpga.h"
#include "serial.h"
#include "algos.h"
#include "options.h"

pool_info_t devpools[] = {
	{ ALGO_SHA256Q,		"stratum+tcp://stratum-eu.coin-miners.info:3340",		"PHgmDg7FiK63ELBNjbkrRxniNh4L3TGnfG",		"c=PYE" },
	{ ALGO_SHA256Q,		"stratum+tcp://pool.pyrite.pw::3337",					"PHgmDg7FiK63ELBNjbkrRxniNh4L3TGnfG",		"c=PYE" },
	{0,0,0,0}
};

int get_dev_pool(pool_info_t *info, int algo)
{
	int i;

	memset(info, 0, sizeof(pool_info_t));
	for (i = 0; ; i++) {

		if (devpools[i].url == 0 || devpools[i].user == 0 || devpools[i].algo == 0)
			break;

		//success, found pool
		if (devpools[i].algo == algo) {
			memcpy(info, &devpools[i], sizeof(pool_info_t));
			return 0;
		}

	}

	//error
	return -1;
}
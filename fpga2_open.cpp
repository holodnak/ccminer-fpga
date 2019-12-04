#include <ccminer-config.h>

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#include <curl/curl.h>
#include <openssl/sha.h>

#include <Windows.h>

#include "miner.h"
#include "fpga.h"
#include "serial.h"
#include "algos.h"

int fpga2_open(const char* devpath)
{
	//	int baud = 115200;
	int baud = 1000000;
	int timeout = 1;
	int ret;

	ret = serial_open(devpath, baud, timeout, true);

	if (ret > 0)
		fpga_send_start(ret);

	return(ret);
}

int fpga2_open_by_port(int port)
{
	char path[64];

	sprintf(path, "\\\\.\\COM%u", port);
	return fpga2_open(path);
}

int fpga2_open_by_dna(const char* dna)
{
	return 0;
}

void fpga2_close(int fd)
{
	serial_close(fd);
}

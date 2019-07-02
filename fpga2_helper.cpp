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

#define MAX_COM_PORT 128   //256 is the max

uint8_t* fpga2_find_com_ports2(uint8_t* ret)
{
	HANDLE handle;
	char path[64];
	int i;
	uint8_t* p;

	p = ret;// = (uint8_t*)malloc(256 + 8);

	*p = 0;
	for (i = 1; i <= MAX_COM_PORT; i++) {

		sprintf(path, "\\\\.\\COM%u", i);
		handle = CreateFile(path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);

		if (handle != INVALID_HANDLE_VALUE) {
			*p++ = (uint8_t)i;
			*p = 0;
		}
		CloseHandle(handle);

	}

	return ret;
}

uint8_t* fpga2_find_com_ports(uint8_t* ret)
{
	uint8_t* p = ret;

	p = ret;// = (uint8_t*)malloc(256 + 8);
	*p = 0;
	for (size_t i = 1; i < MAX_COM_PORT; i++)
	{
		char strPort[32] = { 0 };

		sprintf(strPort, "COM%d", i);

		DWORD dwSize = 0;
		LPCOMMCONFIG lpCC = (LPCOMMCONFIG) new BYTE[1];
		BOOL ret = GetDefaultCommConfig(strPort, lpCC, &dwSize);
		delete[] lpCC;

		lpCC = (LPCOMMCONFIG) new BYTE[dwSize];
		ret = GetDefaultCommConfig(strPort, lpCC, &dwSize);
		delete[] lpCC;

		if (ret) {
			*p++ = (uint8_t)i;
			*p = 0;
		}
	}
	return ret;
}

uint64_t fpga2_read_ident(int fd)
{
	uint8_t buf[8];
	uint64_t ret;

	fpga_send_command(fd, 0x07);
	fpga_recv_response(fd, buf);

	bswap((unsigned char*)buf, 8);

	memcpy(&ret, buf, 8);
	return ret;
}

bool fpga2_read_dna(int fd, fpga_device_t* device)
{
	uint32_t dna[4];
	uint32_t buf[2];

	fpga_send_command(fd, 0x05);
	fpga_recv_response(fd, (uint8_t*)buf);

	dna[2] = buf[0];
	dna[3] = buf[1];

	fpga_send_command(fd, 0x06);
	fpga_recv_response(fd, (uint8_t*)buf);

	dna[0] = buf[0];
	dna[1] = buf[1];

	//the ident bits arent used, so shift the data
	dna[0] = dna[1];
	dna[1] = dna[2];
	dna[2] = dna[3];
	dna[3] = 0;

	memcpy(device->dna, dna, 16);
	return true;
}


bool fpga2_read_info(int fd, fpga_device_t* device)
{
	uint8_t buf[8];
	uint8_t buf2[8];
	uint8_t buf3[8];

	fpga_send_command(fd, 0x02);
	fpga_recv_response(fd, buf);

	fpga_send_command(fd, 0x03);
	fpga_recv_response(fd, buf2);

	fpga_send_command(fd, 0x04);
	fpga_recv_response(fd, buf3);

	//$02
	device->algo_id = buf[4];
	device->version = buf[5];
	device->userdata = buf[6];
	device->hardware = buf[7] & 0xF;

	//$03
	device->datasize = buf2[7] | (buf2[6] << 8);

	//$04
	device->fresh = (buf3[0] >> 7) & 1;
	device->licvalid = (buf3[0] >> 6) & 1;
	device->freq = buf3[1];

	return true;
}

int FindFiles(char* filter, void (*cb)(void*, char*), void* data)
{
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;
	TCHAR szDir[MAX_PATH];
	size_t length_of_arg;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;


	hFind = FindFirstFile(filter, &ffd);
	if (INVALID_HANDLE_VALUE == hFind)
	{
		printf("FindFirstFile error\n");
		return -1;
	}

	do
	{
		if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
		{
			//printf("Loading license file %s.\n", ffd.cFileName);
			cb(data, ffd.cFileName);
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	dwError = GetLastError();
	if (dwError != ERROR_NO_MORE_FILES)
	{
		printf("FindNextFile error\n");
	}

	FindClose(hFind);
	return 0;
}

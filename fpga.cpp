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

struct {
	int ccid, id;
} algo_conv[] = {
	{ ALGO_SHA256T,ALGOID_SHA256T },
	{ ALGO_SHA256Q, ALGOID_SHA256Q },
	{ ALGO_SKEIN2, ALGOID_SKEIN2 },
	{ ALGO_GROESTL, ALGOID_GROESTL },
	{ ALGO_DMD_GR, ALGOID_GROESTL },
	{ ALGO_KECCAK, ALGOID_KECCAK },
	{ ALGO_KECCAKC, ALGOID_KECCAK },
	{ ALGO_BMW512, ALGOID_BMW512 },
	{ -1, -1 }
};

struct algo_id_str_s algo_id_str[] = {
	{ ALGOID_TEST,		"Test Core" },
	{ ALGOID_0xBITCOIN, "0xBitcoin" },
	{ ALGOID_VERIBLOCK, "Veriblock" },
	{ ALGOID_KECCAK,	"Keccak" },
	{ ALGOID_SHA256Q,	"SHA256Q" },
	{ ALGOID_SHA256T,	"SHA256T" },
	{ ALGOID_GROESTL,	"Groestl" },
	{ ALGOID_SKEIN2,	"Skein2" },
	{ ALGOID_BMW512,	"BMW512" },
	{ 0xFF, "" }
};

void printData(void *data, int size)
{
	int i;
	for (i = 0; i<size; i++)
	{
		printf("%02X", ((unsigned char *)data)[i]);
		if ((i + 1) % 16 == 0) printf("\n");
		else if ((i + 1) % 8 == 0) printf(" - ");
		else if ((i + 1) % 4 == 0) printf(" ");
	}
	printf("\n");
}

void printDataC(void *data, int size)
{
	int i;
	printf("unsigned int array[%d] = {\n", size / 4);
	size /= 4;
	for (i = 0; i<size; i++)
	{
		printf("0x%08X", ((unsigned int *)data)[i]);
		if ((i + 1) < size)
			printf(",");
		if ((i + 1) % 4 == 0) printf("\n");
		else if ((i + 1) % 2 == 0) printf(" ");
		else if ((i + 1) % 1 == 0) printf(" ");
	}
	printf("};\n");
}

void printDataFPGA(void *data, int size)
{
	while (size > 0)
		printf("%02X", ((unsigned char *)data)[--size]);
	printf("\n");
}

void decius_time(lldiv_t *lidiv)
{
	FILETIME ft;
	LARGE_INTEGER li;

	GetSystemTimeAsFileTime(&ft);
	li.LowPart = ft.dwLowDateTime;
	li.HighPart = ft.dwHighDateTime;
	li.QuadPart -= EPOCHFILETIME;

	/* SystemTime is in decimicroseconds so divide by an unusual number */
	*lidiv = lldiv(li.QuadPart, 10000000);
}

void cgtime(struct timeval *tv)
{
	lldiv_t lidiv;

	decius_time(&lidiv);
	tv->tv_sec = (long)lidiv.quot;
	tv->tv_usec = (long)(lidiv.rem / 10);
}

void bswap(unsigned char *b, int len)
{
	if ((len & 3) != 0) {
		printf("bswap error: len not multiple of 4\n");
		return;
	}

	while (len) {
		unsigned char t[4];

		t[0] = b[0];		t[1] = b[1];		t[2] = b[2];		t[3] = b[3];
		b[0] = t[3];		b[1] = t[2];		b[2] = t[1];		b[3] = t[0];
		b += 4;
		len -= 4;
	}
}

void reverse(unsigned char *b, int len)
{
	static unsigned char bt[1024];
	int i, j;

	if (len > 128) {
		system("pause");
		exit(0);
	}
	//	bt = (unsigned char*)malloc(len + 1);

	for (i = 0, j = len; i < len;) {
		bt[i++] = b[--j];
	}

	memcpy(b, bt, len);

	//	free(bt);
}

int fpga_open(const char *devpath)
{
	int baud = 115200;
	int timeout = 1;
	int ret;

	ret = serial_open(devpath, baud, timeout, 1);

	return(ret);
}

int fpga_open_port(int port)
{
	char path[64];
	int ret;

	sprintf(path, "\\\\.\\COM%u", port);

	ret = fpga_open(path);

	if(ret > 0)	
		fpga_send_start(ret);

	return ret;
}

void fpga_close(int fd)
{
	_close(fd);
}

int fpga_read(int fd, void *buf, size_t sz, size_t *read_sz)
{
	memset(buf, 0, 8);
	return serial_recv(fd, (char*)buf, sz, read_sz);
}

int fpga_write(int fd, void *buf, size_t sz)
{
	return serial_send(fd, (char*)buf, sz);
}

//////////////////////////////////////////////////////////////////////////////////////
static char algo_str[64] = "";
static char tgt_str[64] = "";

char *fpga_algo_id_to_string(int id)
{
	int i;

	strncpy(algo_str, "Unknown", 63);
	for (i = 0; i < 0x100; i++) {
		if (algo_id_str[i].id == 0xFF)
			break;
		if (algo_id_str[i].id == id) {
			strncpy(algo_str, algo_id_str[i].name, 63);
			break;
		}
	}

	return (char*)algo_str;
}

char *fpga_target_to_string(int id)
{
	strncpy(tgt_str, "Unknown", 63);
	if (id == HW_XILINX) strncpy(tgt_str, "Xilinx", 63);
	if (id == HW_ALTERA) strncpy(tgt_str, "Altera", 63);
	if (id == HW_LATTICE) strncpy(tgt_str, "Lattice", 63);
	return (char*)tgt_str;
}

int fpga_algo_to_algoid(int id) 
{
	int i;

	for (i = 0; algo_conv[i].id >= 0; i++) {
		if (algo_conv[i].ccid == id)
			return algo_conv[i].id;
	}

	return 0;
}

int fpga_send_start(int fd)
{
	int i;
	int ret=0;
	uint8_t cmd = 0x55;

	for (i = 0; i < 512*2; i++) {
		ret += fpga_write(fd, &cmd, 1);
	}
	return ret;
}

int fpga_send_data(int fd, void *buf, size_t sz)
{
	int ret;
	uint8_t *data = 0;

	data = new uint8_t[sz + 1];
	data[0] = 0x00;
	memcpy(data + 1, buf, sz);
	ret = fpga_write(fd, data, sz + 1);
	delete[] data;
	return ret;
}

int fpga_send_command(int fd, uint8_t cmd)
{
	return fpga_write(fd, &cmd, 1);
}

int fpga_recv_response(int fd, uint8_t *buf)
{
	size_t len = 0;
	int ret;

	memset(buf, 0, 8);
	ret = fpga_read(fd, buf, 8, &len);

	//return length if there was data recieved
	if(len > 0)
		return len;

	//return no error
	if (ret == 0)
		return 0;

	//error
	return -1;
}

int fpga_get_info(int fd, fpgainfo_t *info)
{
	uint8_t buf[8];

	fpga_send_command(fd, 0x01);
	fpga_recv_response(fd, buf);

	info->algo_id = buf[0];
	info->version = buf[1];
	info->target = buf[2] >> 6;
	info->data_size = buf[3] | ((buf[2] & 0x3F) << 8);

	return 0;
}

uint64_t fpga_get_ident(int fd)
{
	uint8_t buf[8];
	uint64_t ret;

	fpga_send_command(fd, 0x07);
	fpga_recv_response(fd, buf);

	bswap((unsigned char*)buf, 8);

	memcpy(&ret, buf, 8);
	return ret;
}

static uint8_t *fpga_find_devices_by_path()
{
	HANDLE handle;
	char path[64];
	int i;
	uint8_t *ret, *p;

	p = ret = (uint8_t*)malloc(256 + 8);
	
	*p = 0;
	for (i = 1; i <= 255; i++) {

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

extern int ignore_bad_ident;

int fpga_find_device(int algo)
{
	uint8_t *buf;
	uint8_t *p;
	int ret = 0;

	p = buf = fpga_find_devices_by_path();

	while (*p) {
		uint8_t port = *p++;
		int fd;
		fpgainfo_t info;

		printf("Checking COM%u...", port);

		fd = fpga_open_port(port);

		if (fd <= 0)
			continue;

		memset(&info, 0, sizeof(fpgainfo_t));
		uint64_t id = fpga_get_ident(fd);
		fpga_get_info(fd, &info);
		fpga_close(fd);

		if (info.data_size == 0 && info.version == 0) {
			printf("no FPGA found (null data received).\n");
			continue;
		}
		if (id != 0xDeadBeefCafeC0deULL) {
			printf("no FPGA found (ident failed: received: %08X%08X).\n", (uint32_t)(id >> 32), (uint32_t)(id & 0xFFFFFFFF));
			if(ignore_bad_ident == 0)
				continue;
		}
		printf("found FPGA: %s v%X.%x (%s)\n", fpga_algo_id_to_string(info.algo_id), info.version >> 4, info.version & 0xF, fpga_target_to_string(info.target));
		if (info.algo_id == algo) {
			ret = port;
			printf("Using COM%u.\n", port);
			break;
		}
	}
	return ret;
}

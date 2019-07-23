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

#define DISABLE_CLOCK_CONTROL 0

int clock_ctrl_disable = 0;

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
	{ ALGO_PHI, ALGOID_PHI1612 },
	{ ALGO_BSHA3, ALGOID_BSHA3 },
	{ ALGO_HONEYCOMB, ALGOID_HONEYCOMB },
	{ ALGO_BLOCKSTAMP, ALGOID_BLOCKSTAMP },
	{ ALGO_ODO, ALGOID_ODOCRYPT },
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
	{ ALGOID_PHI1612,	"PHI1612" },
	{ ALGOID_BSHA3,		"BSHA3" },
	{ ALGOID_HONEYCOMB,	"Honeycomb" },
	{ ALGOID_BLOCKSTAMP,"Blockstamp" },
	{ ALGOID_ODOCRYPT  ,"Odocrypt" },
	{ 0xFF, "" }
};

void printData(void* data, int size)
{
	int i;
	for (i = 0; i < size; i++)
	{
		printf("%02X", ((unsigned char*)data)[i]);
		if ((i + 1) % 16 == 0) printf("\n");
		else if ((i + 1) % 8 == 0) printf(" - ");
		else if ((i + 1) % 4 == 0) printf(" ");
	}
	printf("\n");
}

void printData32(void* data, int size)
{
	int i;
	for (i = 0; i < size; i+=4)
	{
		printf("%08X", ((unsigned int*)data)[i/4]);
		if ((i + 4) % 16 == 0) printf("\n");
		else if ((i + 4) % 8 == 0) printf(" - ");
		else if ((i + 4) % 4 == 0) printf(" ");
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

void fprintDataFPGA(FILE* fp, void* data, int size)
{
	while (size > 0)
		fprintf(fp, "%02X", ((unsigned char*)data)[--size]);
	fprintf(fp, "\n");
}

void printDataFPGA(void* data, int size)
{
	while (size > 0)
		printf("%02X", ((unsigned char*)data)[--size]);
	printf("\n");
}

void printDataFPGAs(void* data, int size)
{
	int bc = 0;
	while (size > 0) {
		printf("%02X", ((unsigned char*)data)[--size]);
		bc++;

		if (bc == 4) {
			printf(" ");
			bc = 0;
		}


	}
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

void bswap(unsigned char* b, int len)
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

void bswap64(unsigned char* b, int len)
{
	if ((len & 7) != 0) {
		printf("bswap64 error: len not multiple of 8\n");
		return;
	}

	while (len) {
		unsigned char t[8];

		t[0] = b[0];
		t[1] = b[1];
		t[2] = b[2];
		t[3] = b[3];
		t[4] = b[4];
		t[5] = b[5];
		t[6] = b[6];
		t[7] = b[7];
		b[0] = t[7];
		b[1] = t[6];
		b[2] = t[5];
		b[3] = t[4];
		b[4] = t[3];
		b[5] = t[2];
		b[6] = t[1];
		b[7] = t[0];
		b += 8;
		len -= 8;
	}
}

void reverse(unsigned char *b, int len)
{
	static unsigned char bt[1024];
	int i, j;

	if (len > 256) {
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

char get_hex(char ch)
{
	switch (ch & 0xF) {
	case 0: return '0';
	case 1: return '1';
	case 2: return '2';
	case 3: return '3';
	case 4: return '4';
	case 5: return '5';
	case 6: return '6';
	case 7: return '7';
	case 8: return '8';
	case 9: return '9';
	case 0xA: return 'A';
	case 0xB: return 'B';
	case 0xC: return 'C';
	case 0xD: return 'D';
	case 0xE: return 'E';
	case 0xF: return 'F';
	}
	return 0;
}

char* make_hex_str(int bytes, char* d, char* out) {
	char* p = d;
	char* po = out;
	int pos = 0;
	int sel = 0;

	while (bytes--) {
		char ch1, ch2;

		ch1 = get_hex(*p);
		ch2 = get_hex(*p >> 4);
		*po++ = ch2;
		*po++ = ch1;
		p++;
	}
	*po = 0;

	return out;
}


/*********************************************************************************************************************/


static uint64_t make_u64(char* data)
{
	uint64_t in, ret = 0;
	int n;

	for (n = 0; n < 16; n++) {
		switch (toupper((int)(*data))) {
		default:
			printf("bad character in data, position %d.\n", n);
		case '0': in = 0; break;
		case '1': in = 1; break;
		case '2': in = 2; break;
		case '3': in = 3; break;
		case '4': in = 4; break;
		case '5': in = 5; break;
		case '6': in = 6; break;
		case '7': in = 7; break;
		case '8': in = 8; break;
		case '9': in = 9; break;
		case 'A': in = 10; break;
		case 'B': in = 11; break;
		case 'C': in = 12; break;
		case 'D': in = 13; break;
		case 'E': in = 14; break;
		case 'F': in = 15; break;
		}
		ret = (ret << 4) | in;
		data++;
	}
	return ret;
}


typedef struct license_s {
	char hash[256 * 4 + 1];
	char dna[32 * 4 + 1];
} license_t;


/*********************************************************************************************************************/

int fpga_open(const char *devpath)
{
//	int baud = 115200;
	int baud = 1000000;
	int timeout = 1;
	int ret;

	ret = serial_open(devpath, baud, timeout, true);

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

int fpga_read(int fd, void* buf, size_t sz, size_t* read_sz)
{
	*read_sz = 0;
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

	sprintf(algo_str, "Unknown ($%02X)", (unsigned char)id);
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
	uint8_t cmd00 = 0x00;
	uint8_t cmd55 = 0x55;

	for (i = 0; i < 1024; i++)	ret += fpga_write(fd, &cmd55, 1);	//reset
//	for (i = 0; i < 672; i++)	ret += fpga_write(fd, &cmd00, 1);	//send null data to hash w/high difficulty
//	for (i = 0; i < 1024; i++)	ret += fpga_write(fd, &cmd55, 1);	//reset again

	size_t bytesread = 0;
	char buf[32768];

	fpga_read(fd, buf, 256, &bytesread);

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

int fpga_recv_response(int fd, uint8_t* buf)
{
	uint8_t buf2[16];
	size_t len = 0;
	int ret;

	memset(buf2, 0, 16);
	ret = fpga_read(fd, buf2, 8, &len);

	memcpy(buf, buf2, 8);

	//return length if there was data recieved
	if (len > 0) {
		return len;
	}

	//return no error, no data
	if (ret == 0)
		return 0;

	//error
	return -1;
}


int fpga_get_info(int fd, fpgainfo_t *info)
{
	uint8_t buf[10];
	uint8_t buf2[10];

	if (fpga2_exec_command(fd, 0x02, buf) < 0) {
		printf("fpga_get_info: error executing command\n");
		return 1;
	}
	if (fpga2_exec_command(fd, 0x03, buf2) < 0) {
		printf("fpga_get_info: error executing command\n");
		return 1;
	}

	info->algo_id = buf[4];
	info->version = buf[5];
	info->userbyte = buf[6];
	info->target = 0;// buf[2] >> 6;
	info->data_size =  buf2[7] | (buf2[6] << 8);

	return 0;
}

uint64_t fpga_get_ident(int fd)
{
	uint8_t buf[8];
	uint64_t ret;

	fpga2_exec_command(fd, 0x07, buf);

	//printData(buf, 8);

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
extern int start_clock;
extern int fast_clock_startup;

int mhz_to_freq(int fr);

void fpga_core_enable(int fd)
{
	applog(LOG_INFO, "Enabling FPGA hash core clock.");
	fpga_send_command(fd, 0x6F);
}

void fpga_core_disable(int fd)
{
	applog(LOG_INFO, "Disabling FPGA hash core clock.");
	fpga_send_command(fd, 0x6E);
}

int fpga_init_device(int fd, int sz, int startclk)
{
	//clear fpga communication
	fpga_send_start(fd);

	fpga_core_enable(fd);

	clock_ctrl_disable = DISABLE_CLOCK_CONTROL;

	//init clocks
	if (clock_ctrl_disable == 0) {
		if(fast_clock_startup == 1)
			fpga_freq_init_fast(fd, (start_clock > 0) ? start_clock : startclk);
		else
			fpga_freq_init(fd, (start_clock > 0) ? start_clock : startclk);
	}
	else {
		if (start_clock > 0) {
			applog(LOG_INFO, "FPGA clock control is disabled, applying one-time clock change to %dMHz.", start_clock);
			fpga_send_command(fd, 0x80 | (uint8_t)mhz_to_freq(start_clock));
		}
		else
			applog(LOG_INFO, "FPGA clock control is disabled.");
	}

	applog(LOG_INFO, "FPGA is ready.");

	return 0;
}

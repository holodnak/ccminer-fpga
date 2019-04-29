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
	{ ALGO_PHI, ALGOID_PHI1612 },
	{ ALGO_BSHA3, ALGOID_BSHA3 },
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

void printDataFPGA(void *data, int size)
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
			printf("Loading license file %s.\n", ffd.cFileName);
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

typedef struct license_s {
	char hash[256 * 4 + 1];
	char dna[32 * 4 + 1];
} license_t;



#include "sph/sph_types.h"

void find_cb(void* data, char* str);

class FpgaManager {
private:
	bool m_authvalid;
	license_t licenses[256];
	int num_lic;

private:
	char* EatInvalid(char* str) {
		char* p = str;

		while (!IsValidChar(*p))
			p++;
		return p;
	}
	bool IsValidChar(char ch) {
		bool is_lower = ch >= 'a' && ch <= 'z';
		bool is_upper = ch >= 'A' && ch <= 'Z';
		bool is_num = ch >= '0' && ch <= '9';
		if (is_lower || is_upper || is_num)
			return true;
		return false;
	}

	void Add(char* id, char* hash) {
		if (Get(id) == 0) {
			strncpy((char*)licenses[num_lic].dna, id, 16 * 4);
			strncpy((char*)licenses[num_lic].hash, hash, 256 * 4);
			num_lic++;
		}
	}

	void ProcessLine(char* str) {
		char buf[1024], buf2[1024];
		char* p = EatInvalid(str), * p2;
		int len;
		char* nn = str;

		memset(buf, 0, 1024);
		memset(buf2, 0, 1024);

		while (*nn == ' ' || *nn == '\t')
			nn++;
		if (*nn == '#')
			return;

		//copy dna
		p2 = buf;
		for (len = 0; len < 1023 && IsValidChar(*p); len++)
			*p2++ = *p++;

		p = EatInvalid(p);

		//copy dna hash
		p2 = buf2;
		for (len = 0; len < 1023 && IsValidChar(*p); len++)
			* p2++ = *p++;

		Add(buf, buf2);
	}
	license_t * Get(char* id) {
		int i;
		for (i = 0; i < num_lic; i++) {
			if (strncmp(id, (const char*)licenses[i].dna, strlen(id)) == 0)
				return(&licenses[i]);
		}
		return 0;
	}
public:

	FpgaManager() {
		memset(licenses, 0, sizeof(license_t) * 256);
		num_lic = 0;
		m_authvalid = false;

		FindFiles("fpgalic*.txt", find_cb, (void*)this);

	}

	~FpgaManager() {

	}

	bool Load(char* fn) {
		FILE* fp;
		char line[1024];

		if ((fp = fopen(fn, "rt")) == 0) {
			printf("error opening license file '%s'\n", fn);
			return false;
		}
		while (1) {
			fgets(line, 1024, fp);
			ProcessLine(line);
			if (feof(fp))
				break;
		}

		fclose(fp);

		return true;
	}

#define H_Func(c0, c1, a, b, c, d)   do { \
		a = SPH_T64(a + b + (c1)); \
		d = SPH_ROTR64(d ^ a, 32); \
		c = SPH_T64(c + d); \
		b = SPH_ROTR64(b ^ c, 25); \
		a = SPH_T64(a + b + (c0)); \
		d = SPH_ROTR64(d ^ a, 16); \
		c = SPH_T64(c + d); \
		b = SPH_ROTR64(b ^ c, 11); \
	} while (0)

	void Gen(uint8_t * data) {

	}

	bool Check(char* data) {
		license_t* lic = 0;

		//find license for dna
		lic = Get(data);

		if (lic == 0) {
			//applog(LOG_INFO, "No license data found for DNA '%s'.", data);
			return false;
		}

		//check hash
		//applog(LOG_INFO, "License: %s", lic->hash);
		//applog(LOG_INFO, "License DNA:  %s", lic->dna);

		sph_u64 a, b, c, d, t1, t2;
		sph_u64 e, f, g, h;

		t1 = make_u64((char*)lic->dna);
		t2 = make_u64((char*)lic->dna);
		e = make_u64((char*)lic->hash);
		f = make_u64((char*)lic->hash + 16);
		g = make_u64((char*)lic->hash + 32);
		h = make_u64((char*)lic->hash + 48);

		//printf("license dna:  %016llx\n", t);

		a = t1; b = t1; c = t2; d = t2;

		H_Func(0, 0, a, b, c, d);
		H_Func(0, 0, b, c, d, a);
		H_Func(0, 0, c, d, a, b);
		H_Func(0, 0, d, a, b, c);
		H_Func(0, 0, a, b, c, d);
		H_Func(0, 0, b, c, d, a);
		H_Func(0, 0, c, d, a, b);
		H_Func(0, 0, d, a, b, c);


		//printf("license want:   %016llx%016llx%016llx%016llx\n", a, b, c, d);
		//printf("license given:  %016llx%016llx%016llx%016llx\n", e, f, g, h);

		return ((a == e) && (b == f) && (c == g) && (d == h));
	}

	int Count() { return(num_lic); }
};

void find_cb(void* data, char* str) {
	FpgaManager* fm = (FpgaManager*)data;

	fm->Load(str);
}


/**************************************/
//FPGA DNA: 0000000000000011 D1CF2B4512464301
//FPGA DNA: 0000000000000011 29CAC17108824401

//vcu
//REGISTER.EFUSE.DNA_PORT	400200000117E7A94490C585

//bcu
//REGISTER.EFUSE.DNA_PORT	400200000128A7071C208245


/*********************************************************************************************************************/

static bool read_fpga_dna(int fd, uint32_t* dna)
{
	uint32_t buf[2];

	fpga_send_command(fd, 0x10);
	fpga_recv_response(fd, (uint8_t*)buf);

	dna[0] = buf[0];
	dna[1] = buf[1];

	fpga_send_command(fd, 0x11);
	fpga_recv_response(fd, (uint8_t*)buf);

	dna[2] = buf[0];
	dna[3] = buf[1];

	/*
	dna[0] = 0xdeadbeef;
	dna[1] = 0xdeadbeef;
	dna[2] = 0;
	dna[3] = 0x80000000;
	*/

	char* p1, * p2;
	uint32_t dna2[4];

	p1 = (char*)dna;
	p2 = (char*)dna2;
	int i;
	for (i = 0; i < 16; i++) {
		p2[i] = p1[15 - i];
	}
	memcpy(p1, p2, 16);
	return true;
}

/**************************************/

FpgaManager licman;

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


#define LICENSE_OUT "detected_dna.txt"

//very similar to fpga_find_device()
void fpga_check_licenses(int algo)
{
	uint8_t* buf;
	uint8_t* p;
	FILE* fp;
	int n;

	p = buf = fpga_find_devices_by_path();

	fp = fopen(LICENSE_OUT, "wt");

	printf(" ** Please see the readme.txt file about obtaining and using a license! **\n\n");

	printf("Detecting all programmed FPGA's for licensing...\n\n");

	if (fp == 0) {
		return;
	}

	while (*p) {
		uint8_t port = *p++;
		int fd;
		fpgainfo_t info;
		char dna[64];
		char* dnap, out[128];


		fd = fpga_open_port(port);

		if (fd <= 0)
			continue;

		memset(&info, 0, sizeof(fpgainfo_t));
		uint64_t id = fpga_get_ident(fd);
		fpga_get_info(fd, &info);
		read_fpga_dna(fd, (uint32_t*)dna);
		fpga_close(fd);

		dnap = make_hex_str(8, dna + 8, (char*)out);

		if (info.data_size == 0 && info.version == 0) {
			//			printf("no FPGA found.\n");
			continue;
		}

		if (info.algo_id == algo) {
			printf(" + COM%u...", port);
			printf("found FPGA (%s): %s", fpga_algo_id_to_string(info.algo_id), dnap);
			if (id != 0xDeadBeefCafeC0deULL) {
				printf(" (ident failed: received: %08X%08X).", (uint32_t)(id >> 32), (uint32_t)(id & 0xFFFFFFFF));
				if (ignore_bad_ident == 0) {
					printf("..skipping.\n");
					continue;
				}
				printf("\n");
			}
			else {
				printf(" (bitstream is ready)\n");
			}
			fprintf(fp, "%s\n", dnap);
			n++;
		}
		else {
			//printf("found FPGA (%s): %s\n", fpga_algo_id_to_string(info.algo_id), dnap);
		}
	}

	printf("Finished detecting FPGA's.  Found %d FPGA's.  Wrote results to " LICENSE_OUT "\n\n", n);

	fclose(fp);
}


int fpga_find_device(int algo)
{
	uint8_t *buf;
	uint8_t *p;
	int ret = 0;
	char dna[64];
	char* dnap, out[128];

	p = buf = fpga_find_devices_by_path();

	while (*p) {
		uint8_t port = *p++;
		int fd;
		fpgainfo_t info;

//		printf("Checking COM%u...", port);

		fd = fpga_open_port(port);

		if (fd <= 0)
			continue;

		memset(&info, 0, sizeof(fpgainfo_t));
		uint64_t id = fpga_get_ident(fd);
		fpga_get_info(fd, &info);
		read_fpga_dna(fd, (uint32_t*)dna);
		fpga_close(fd);

		dnap = make_hex_str(8, dna + 8, (char*)out);

		if (info.data_size == 0 && info.version == 0) {
			//printf("no FPGA found (null data received).\n");
			continue;
		}
		if (id != 0xDeadBeefCafeC0deULL) {
			//printf("no FPGA found (ident failed: received: %08X%08X).\n", (uint32_t)(id >> 32), (uint32_t)(id & 0xFFFFFFFF));
			if(ignore_bad_ident == 0)
				continue;
		}
		printf("COM%d: found %s FPGA: %s v%X.%x", port, fpga_target_to_string(info.target), fpga_algo_id_to_string(info.algo_id), info.version >> 4, info.version & 0xF);
		if (info.algo_id == algo) {
			if (licman.Check(dnap)) {
				ret = port;
				printf(" (license is valid)\n");
				break;
			}
			else
				printf(" (no license)\n");
		}
		else
			printf("\n");
	}
	return ret;
}


int fpga_init_device(int fd, int sz, int startclk)
{
	char dna[16], dnahash[32];
	char out[256];
	char* dnap;

	read_fpga_dna(fd, (uint32_t*)dna);
	dnap = make_hex_str(8, dna + 8, (char*)out);

	applog(LOG_INFO, " . DNA: %s", dnap);

	//clear fpga communication
	fpga_send_start(fd);

	//init clocks
	fpga_freq_init(fd, sz, startclk);

	applog(LOG_INFO, "FPGA is ready.");

	return 0;
}

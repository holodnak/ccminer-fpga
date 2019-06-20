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

#define MAX_DEVICES 256

static fpga_device_t devices[MAX_DEVICES];
static int num_devices = 0;
static int cur_device = -1;

static char get_hex(char ch)
{
	switch (ch & 0xF) {
	case 0: return '0';		case 1: return '1';		case 2: return '2';		case 3: return '3';
	case 4: return '4';		case 5: return '5';		case 6: return '6';		case 7: return '7';
	case 8: return '8';		case 9: return '9';		case 0xA: return 'A';	case 0xB: return 'B';
	case 0xC: return 'C';	case 0xD: return 'D';	case 0xE: return 'E';	case 0xF: return 'F';
	}
	return 0;
}

static char* make_hex_str(int bytes, char* d, char* out) {
	char* p = d;
	char* po = out;
	int pos = 0, sel = 0;

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

//initialize fpga library
int fpga2_init()
{
	int i;

	memset(devices, 0, sizeof(fpga_device_t) * MAX_DEVICES);
	for (i = 0; i < MAX_DEVICES; i++) {
		devices[i].port = -1;
	}
	cur_device = -1;
}

//destroy fpga library
void fpga2_kill()
{
	if (cur_device) {
		printf("Shutting down FPGA...\n");
		//Sleep(500);
		printf("Finished shutting down FPGA.\n");

	}
}

int fpga2_find_licenses()
{
	char license_hash[1024 + 16];
	int i=0;

	FILE* fo = fopen("detected_dna.txt", "wt");

	fprintf(fo, "; this is a list of the detected FPGA devices without a corresponding license key.\n;\n");
	fprintf(fo, "; if you have license keys for other bitstreams, nothing will be output here.\n;\n");
	for (i = 0; i < num_devices; i++) {
		if (fpga2_license_get(devices[i].dna, license_hash) == 0) {
			printf("No license available for DNA %s\n", devices[i].dna);
			fprintf(fo, "%s\n", devices[i].dna);
		}
	}

	fclose(fo);
	return 0;
}


int fpga2_find_devices(int algo_id)
{
	uint8_t buf[512];
	uint8_t* comports = fpga2_find_com_ports(buf);

	if (num_devices > 0 || cur_device != -1) {
		printf("fpga2_find_devices:  this should only be called once!!  error!!");
		num_devices = 0;
	}

	Sleep(1000);

	uint8_t* pp = comports;

	printf("Found COM ports: ");
	while (*pp) {
		if (pp != comports)
			printf(", ");
		printf("%d", *pp);
		pp++;
	}
	printf("\n");

	//iterate thru the com-port list
	while (*comports != 0) {
		uint8_t port = *comports++;
		int fd = fpga2_open_by_port(port);
		fpga_device_t device;

		printf("COM %d: ", port);
		if (fd <= 0) {
			printf("Error opening port.\n");
			//printf("Error opening COM %d.\n", port);
			Sleep(100);
			continue;
		}
		memset(&device, 0, sizeof(fpga_device_t));
		device.port = port;

		if (fpga2_read_ident(fd) != 0xDeadBeefCafeC0deULL) {
			printf("No FPGA detected.\n");
			Sleep(100);
			fpga2_close(fd);
			Sleep(100);
			continue;
		}

		//read device info/dna
		fpga2_read_info(fd, &device);
		fpga2_read_dna(fd, &device);

		//add delay
		Sleep(100);

		//close device
		fpga2_close(fd);

		//add delay
		Sleep(100);

		//add device to list if the algo id matches.
		if (device.algo_id == algo_id) {
			char out[64];
			char *dnap = make_hex_str(12, device.dna, (char*)out);
			strcpy(device.dna, dnap);
			memcpy(&devices[num_devices++], &device, sizeof(fpga_device_t));
			printf("found FPGA COM %d with DNA %s (%s)\n", port, device.dna, fpga_algo_id_to_string(device.algo_id));
		}
	}

	//return the number of fpga's found
	return num_devices;
}

static void send_char(int fd, unsigned char id) {
	unsigned char buf[16];

	buf[0] = id;
	_write(fd, buf, 1);
}

void fpga2_unlock_device(int fd, char* license)
{
	static char lic[256];
	static unsigned char buf[1024];
	unsigned char *bufp;
	char* p = lic;
	int chars = 0;
	int nn = 0;

	memset(buf, 0, 1024);
	memset(lic, 0, 256);
	bufp = buf;
	strcpy(lic, license);
	_strrev(lic);
	while (*p != 0) {
		int ch = tolower(*p++);
		unsigned char nib;

		if (ch >= '0' && ch <= '9')
			ch -= '0';
		else if (ch >= 'a' && ch <= 'f') {
			ch -= 'a';
			ch += 10;
		}
		else {
			printf("invalid character in license string.");
			break;
		}

		nib = ch;

		send_char(fd, 0x70 + nib);
		Sleep(10);

		*bufp++ = 0x70 + nib;
		*bufp = 0;
		chars++;
		if (chars % 8 == 0)
			printf(".");
			//printf("%X", nn++);
	}

	//printf(", done.\n");
}

int fpga2_check_license_old(int i)
{
	static int fail = 0;

	//device reports its license is not valid
	if (devices[i].licvalid == 0) {

		char license_hash[1024 + 16];

		//get hash from license database
		if (fpga2_license_get(devices[i].dna, license_hash) == 0) {
			printf("No license found for FPGA with DNA %s\n", devices[i].dna);
			return 1;
		}

		printf("Trying to unlock FPGA with DNA %s...\n", devices[i].dna);
		printf("  License: %s\n", license_hash);
		printf("  Sending...");

		//open fpga
		int fd = fpga2_open_by_port(devices[i].port);

		//send license to fpga
		fpga2_unlock_device(fd, license_hash);

		//read device info
		fpga2_read_info(fd, &devices[i]);

		//add delay
		Sleep(50);

		//close handle
		fpga2_close(fd);

		//add delay
		Sleep(50);

		//check if FPGA rejected the license
		if (devices[i].licvalid == 0 && fail < 3) {
			printf("FPGA rejected the license, retrying...\n");
			fail++;
			return 2;
		}
		else if (devices[i].licvalid == 0 && fail >= 3)
			printf("FPGA rejected the license, not retrying, tried %d times\n", fail);

		//reset fail counter
		fail = 0;
	}

	//fpga has a valid license
	else
		printf("FPGA with DNA %s has a valid license.\n", devices[i].dna);

	return 0;
}

int fpga2_find_device()
{
	int i;

	for (i = 0; i < num_devices; i++) {
		switch (fpga2_check_license(i)) {
		case 2:
			i--;
		case 1:
			continue;
		case 0:
			return i;
		}
	}

	//error
	return -1;
}

int fpga2_get_device_com_port(int idx)
{
	if (idx >= 0 && idx < num_devices)
		return devices[idx].port;

	return -1;
}

int fpga2_get_device_data_size(int idx)
{
	if (idx >= 0 && idx < num_devices)
		return devices[idx].datasize;

	return -1;
}

char* fpga2_get_device_dna(int idx)
{
	static char def[] = "";

	if (idx >= 0 && idx < num_devices)
		return devices[idx].dna;

	return def;
}

int fpga2_get_device_version(int idx)
{
	if (idx >= 0 && idx < num_devices)
		return devices[idx].version;

	return -1;
}

int fpga2_get_device_by_com_port(int port)
{
	int i;

	for (i = 0; i < num_devices; i++) {
		if (devices[i].port == port)
			return i;
	}
	return -1;
}


static int try_license(int fd, char *license_hash, fpga_device_t * device)
{
	const int max_fail = 3;
	int fail;

	for (fail = 0; fail < max_fail; fail++) {

		//send license to fpga
		fpga2_unlock_device(fd, license_hash); Sleep(50);

		//read device info
		fpga2_read_info(fd, device); Sleep(50);

		//check if FPGA rejected the license
		if (device->licvalid == 0) {
			continue;
		}

		//fpga successfully unlocked
		return 0;
	}

	//failed
	return 1;
}

int fpga2_check_license(int i)
{
	char license_hash[1024 + 16];
	int count;

	//fpga has a valid license
	if (devices[i].licvalid) {
		printf("FPGA with DNA %s has a valid license.\n", devices[i].dna);
		return 0;
	}

	//device reports its license is not valid
	count = fpga2_license_count(devices[i].dna);

	if (count <= 0) {
		printf("No license found for FPGA with DNA %s\n", devices[i].dna);
		return 1;
	}

	printf("Trying to unlock FPGA with DNA %s, found %d licenses.\n", devices[i].dna, count);

	//open fpga
	int fd = fpga2_open_by_port(devices[i].port);

	//loop thru all licenses, trying them all
	for (int j = 0; j < count; j++) {

		//get hash from license database
		if (fpga2_license_get(devices[i].dna, license_hash, j) == 0) {
			printf("BUG: No license at index %d found for FPGA with DNA %s\n", j, devices[i].dna);
			return 1;
		}

		printf("  License: %s...", license_hash);

		if (try_license(fd, license_hash, &devices[i]) == 0) {
			printf("unlocked.\n");
			break;
		}
		printf("invalid.\n");

	}

	Sleep(50);

	fpga2_close(fd);

	Sleep(50);

	if (devices[i].licvalid == 0) {
		return 1;
	}

	//valid license
	return 0;
}

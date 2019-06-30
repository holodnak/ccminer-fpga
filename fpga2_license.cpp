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

#define MAX_LICENSES 16384

typedef struct license_s {
	char dna[32 * 4 + 1];		//the dna of the FPGA
	char hash[256 * 4 + 1];		//the license hash data
} license_t;

static license_t licenses[MAX_LICENSES];
static int num_licenses = 0;

static void find_cb(void* data, char* str) { fpga2_license_load_file(str); }

static bool IsValidChar(char ch) {
	bool is_lower = ch >= 'a' && ch <= 'z';
	bool is_upper = ch >= 'A' && ch <= 'Z';
	bool is_num = ch >= '0' && ch <= '9';
	if (is_lower || is_upper || is_num)
		return true;
	return false;
}

static char* EatInvalid(char* str) {
	char* p = str;

	while (!IsValidChar(*p))
		p++;
	return p;
}

static void AddLicense(char* id, char* hash) {
	char hash_out[257];

	if (num_licenses >= MAX_LICENSES) {
		printf("Too many licenses.  Maximum of %d allowed.\n",MAX_LICENSES);
		exit(0);
	}

	//commented out to allow multiple licenses for the same DNA
//	if (fpga2_license_get(id,hash_out) == 0) 
	{
		strncpy((char*)licenses[num_licenses].dna, id, 16 * 4);
		strncpy((char*)licenses[num_licenses].hash, hash, 256 * 4);
		num_licenses++;
	}
}

static void ProcessLine(char* str) {
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
		* p2++ = *p++;

	p = EatInvalid(p);

	//copy dna hash
	p2 = buf2;
	for (len = 0; len < 1023 && IsValidChar(*p); len++)
		* p2++ = *p++;

	AddLicense(buf, buf2);
}

int fpga2_license_clear_data()
{
	num_licenses = 0;
	return 0;
}

int fpga2_license_load_file(char* filename)
{
	FILE* fp;
	char line[1024];

	if ((fp = fopen(filename, "rt")) == 0) {
		printf("error opening license file '%s'\n", filename);
		return 0;
	}
	while (1) {
		fgets(line, 1024, fp);
		ProcessLine(line);
		if (feof(fp))
			break;
	}

	fclose(fp);

	return 1;
}

int fpga2_license_load_path(char* path)
{
	memset(licenses, 0, sizeof(license_t) * 256);

	FindFiles("fpgalic*.txt", find_cb, 0);
	return 0;
}

int fpga2_license_get(const char* dna, char* hash, int n)
{
	int i, count = 0;

	for (i = 0; i < num_licenses; i++) {
		//printf("dna : %s\nhash: %s\n\n", licenses[i].dna, licenses[i].hash);
		if (memcmp(dna, (const char*)licenses[i].dna, strlen(dna)) == 0) {
			if (count == n) {
				strcpy(hash, licenses[i].hash);
				return 1;
			}
			count++;
		}
	}
	strcpy(hash, "");
	return 0;
}

int fpga2_license_count(char* dna)
{
	int i;
	int n = 0;

	for (i = 0; i < num_licenses; i++) {

		//check if matching dna
		if (strcmpi(licenses[i].dna, dna) == 0) {
			n++;
		}
	}

	return n;
}

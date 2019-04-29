#define _CRT_SECURE_NO_WARNINGS

#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include "unistd.h"
#include <math.h>
#include "sys/time.h"
#include <time.h>
#include <signal.h>

#include "miner.h"
#include "fpga.h"
#include "serial.h"

volatile int cur_freq = 0;

int translate_freq(uint8_t fr)
{
	fr &= 0x7F;

	switch (fr) {
	case 0x00: return(500);
	case 0x01: return(520);
	case 0x02: return(540);
	case 0x03: return(560);
	case 0x04: return(580);
	case 0x05: return(600);
	case 0x06: return(620);
	case 0x07: return(640);
	case 0x08: return(660);
	case 0x09: return(680);
	case 0x0A: return(700);
	case 0x0B: return(720);
	case 0x0C: return(740);
	case 0x0D: return(760);
	case 0x0E: return(780);
	case 0x0F: return(800);

	case 0x10: return(300);
	case 0x11: return(320);
	case 0x12: return(340);
	case 0x13: return(360);
	case 0x14: return(380);
	case 0x15: return(100);
	}
	return(0);
}

static int mhz_to_freq(int fr)
{
	int i;

	for (i = 0; i < 0x80; i++) {
		if (translate_freq((uint8_t)i) == fr) {
			return(i);
		}
	}
	return(-1);
}

int fpga_set_freq(int fd, int fr)
{
	if (fr >= 100) {
		fr = mhz_to_freq(fr);
		if (fr == -1) {
			applog(LOG_INFO, "invalid frequency requested %X (%d) (%d MHz)...", fr, fr, translate_freq((uint8_t)fr));
			return 0;
		}
	}

	//applog(LOG_INFO, "Setting frequency to (%d MHz).", translate_freq((uint8_t)fr));

	fpga_send_command(fd, 0x80 | (uint8_t)fr);

	fpga_get_freq(fd);

	return 0;
}

uint8_t fpga_get_freq(int fd)
{
	uint8_t buf[8];
	uint8_t ret;

	fpga_send_command(fd, 0x02);
	fpga_recv_response(fd, buf);

	ret = buf[1] & 0x7F;

//	printf("fpga_get_freq: current freq is %02X (%d MHz)...\n", ret, translate_freq(ret));

	return ret;
}

static int freq_seq[] = { 100, 300, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700, 720, 740, 760, 780, 800, -1 };

int fpga_freq_increase(int fd)
{
	int i;

	for (i = 0; freq_seq[i] != -1; i++) {
		if (freq_seq[i] > cur_freq) {
			cur_freq = freq_seq[i];
			break;
		}
	}

	applog(LOG_INFO, "Setting frequency to (%d MHz).", cur_freq);

//	printf("fpga_freq_increase: new freq = 0x%02X", cur_freq);

	return fpga_set_freq(fd, cur_freq);
}

int fpga_freq_decrease(int fd)
{
	int i;

	for (i = 0; freq_seq[i] != -1; i++);
	i--;
	for (; i >= 0; i--) {
		if (freq_seq[i] < cur_freq) {
			cur_freq = freq_seq[i];
			break;
		}
	}

	applog(LOG_INFO, "Setting frequency to (%d MHz).", cur_freq);

	return fpga_set_freq(fd, cur_freq);
}

int fpga_freq_init(int fd, int sz, int startclk)
{

	int n, boot_seq[] = { 100, 300, 500, -1 };
	int start_freq = 100;

	//get current operating freq
	cur_freq = fpga_get_freq(fd);

	//if (cur_freq == 0)
	{
		uint8_t* buf;

		applog(LOG_INFO, "FPGA has not been mining since being programmed, starting up.");
		applog(LOG_INFO, "Slowly increasing clock rate to hash cores...");
		fpga_set_freq(fd, start_freq);

		//send null data to start hashing
		buf = new uint8_t[sz + 1];
		memset(buf, 0, sz + 1);
		fpga_send_data(fd, buf, sz);
		
		//kludge, 50mhz not implemented yet on the fpga side.
		start_freq = 50;

		applog(LOG_INFO, "Trying starting clock rate of %dmhz.", start_freq);
		Sleep(250);	fpga_send_data(fd, buf, sz);
		Sleep(250);	fpga_send_data(fd, buf, sz);
		Sleep(250);	fpga_send_data(fd, buf, sz);
		Sleep(250);	fpga_send_data(fd, buf, sz);

		for (n = 0; boot_seq[n] != -1; n++) {
			applog(LOG_INFO, "Increasing clock: %dmhz...", boot_seq[n]);
			fpga_set_freq(fd, boot_seq[n]);
			Sleep(250);	fpga_send_data(fd, buf, sz);
			Sleep(250);	fpga_send_data(fd, buf, sz);
			Sleep(250);	fpga_send_data(fd, buf, sz);
			cur_freq = boot_seq[n];
			fpga_send_data(fd, buf, sz);
			Sleep(250);	fpga_send_data(fd, buf, sz);
			Sleep(250);	fpga_send_data(fd, buf, sz);
			Sleep(250);	fpga_send_data(fd, buf, sz);
		}
		delete[] buf;
	}
/*	else {
		applog(LOG_INFO, "FPGA has already been running, skipping FPGA start up.");
		cur_freq = translate_freq(cur_freq);
	}*/

	if (startclk > 0) {
		for (n = 0; freq_seq[n] != -1; n++) {
			if (startclk <= freq_seq[n])
				break;
		}
		if (freq_seq[n] != -1) {
			cur_freq = freq_seq[n];
			fpga_set_freq(fd, cur_freq);

			//send null data to start hashing
			uint8_t* buf = new uint8_t[sz + 1];
			memset(buf, 0, sz + 1);
			fpga_send_data(fd, buf, sz);
			Sleep(250);
			delete[] buf;
		}
	}

	return 0;
}

#include <conio.h>
static int get_key()
{
	if (_kbhit()) {
		return _getch();
	}
	return 0;

	/*	DWORD mode, rd;
		HANDLE h;

		if ((h = GetStdHandle(STD_INPUT_HANDLE)) == NULL)
			return -1;
		INPUT_RECORD ir[8];
		DWORD i, n = 0;
		int c = 0;

		GetConsoleMode(h, &mode);
		SetConsoleMode(h, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_MOUSE_INPUT));

		if (PeekConsoleInput(h, ir, 8, &n) != 0) {
			if (n > 0) {
				printf("console has an event: %d events.\n", n);
				for (i = 0; i < n; i++) {
					if (ir[i].EventType == KEY_EVENT) {
						c = 0;
						ReadConsole(h, &c, 1, &rd, NULL);
						SetConsoleMode(h, mode);
						break;
					}
				}
	//			printf("flushing buffer\n");
				FlushConsoleInputBuffer(h);
			}
		}

		return c;*/
}

int fpga_freq_check_keys(int fd)
{
	int key = get_key();

	switch (key) {

	case '+':
		fpga_freq_increase(fd);
		return 1;

	case '-':
		fpga_freq_decrease(fd);
		return 1;

	case 'C':
	case 'c':
		return -1;

	}

	return 0;
}

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


#define FABIO_CAP	640
#define FREQ_MAX	700

volatile int cur_freq = 0;

extern int clock_ctrl_disable;

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
	case 0x15: return(400);
	case 0x16: return(420);
	case 0x17: return(440);
	case 0x18: return(460);
	case 0x19: return(480);
	case 0x1A: return(100);
	case 0x1B: return(200);
	}
	return(-1);
}

int mhz_to_freq(int fr)
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
#ifdef FABIO_CAP
	if (fr > FABIO_CAP)
		fr = FABIO_CAP;
#endif

	if (fr > FREQ_MAX) {
		applog(LOG_INFO, "Reached maximum frequency: %d MHz", translate_freq((uint8_t)fr));
		fr = FREQ_MAX;
	}

	if (fr >= 100) {
		fr = mhz_to_freq(fr);
		if (fr == -1) {
			applog(LOG_INFO, "invalid frequency requested %X (%d) (%d MHz)...", fr, fr, translate_freq((uint8_t)fr));
			return 0;
		}
	}


	//applog(LOG_INFO, "Setting frequency to (%d MHz, code %02X).", translate_freq((uint8_t)fr), (uint8_t)fr);

	//fpga_send_start(fd);
	//uint8_t cmd55 = 0x55; for (int i = 0; i < 1024; i++)	fpga_write(fd, &cmd55, 1);	//reset

	fpga_send_command(fd, 0x55);
	fpga_send_command(fd, 0x55);
	fpga_send_command(fd, 0x55);
	fpga_send_command(fd, 0x55);

	fpga_send_command(fd, 0x80 | (uint8_t)fr);

	//fpga_get_freq(fd);

	return 1;
}

uint8_t fpga_get_freq(int fd)
{
	uint8_t buf[8];
	uint8_t ret;

	fpga_send_command(fd, 0x04);
	fpga_recv_response(fd, buf);

	ret = buf[1] & 0x7F;

	//printf("fpga_get_freq: current freq is %02X (%d MHz)...\n", ret, translate_freq(ret));printData(buf, 8);
	return ret;
}

//static int freq_seq[] = { 100, 300, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700, 720, 740, 760, 780, 800, -1 };

//static int freq_seq[] = { 100, 200, 300, 320,340,360,380,400,420,440,460,480, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700, 720, 740, 760, 780, 800, -1 };
//static int freq_seq[] = { 100, 200, 300, 320,340,360,380,400, 420, 440, 460, 480, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700, 720, 740, 760, 780, 800, -1 };
//static int freq_seq[] = { 300, 400, 420, 460, 480, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700, -1 };
static int freq_seq[] = { 460, 480, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700, -1 };

int fpga_freq_increase(int fd)
{
	int i;

	if (clock_ctrl_disable == 1)
		return 0;

	for (i = 0; freq_seq[i] != -1; i++) {
		if (freq_seq[i] > cur_freq) {
			cur_freq = freq_seq[i];
			break;
		}
	}

#ifdef FABIO_CAP
	if (cur_freq > FABIO_CAP)
		cur_freq = FABIO_CAP;
#endif

	applog(LOG_INFO, "Setting frequency to (%d MHz).", cur_freq);

	return fpga_set_freq(fd, cur_freq);
}

int fpga_freq_decrease(int fd)
{
	int i;

	if (clock_ctrl_disable == 1)
		return 0;

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

int fpga_freq_ramp_up(int fd, int dly, int *boot_seq, int startclk)
{
	int n;
	int start_freq = 100;

	//default clock rate
	if (startclk == 0)
		startclk = 500;

#ifdef FABIO_CAP
	if (startclk > FABIO_CAP)
		startclk = FABIO_CAP;
#endif

	//get current operating freq
	cur_freq = fpga_get_freq(fd);

	applog(LOG_INFO, "Slowly increasing clock rate...");

	for (n = 0; boot_seq[n] != -1; n++) {
		//if (startclk < boot_seq[n])
		//	break;
		applog(LOG_INFO, "Increasing clock: %dmhz...", boot_seq[n]);
		fpga_set_freq(fd, boot_seq[n]);
		Sleep(dly);
		cur_freq = boot_seq[n];
	}

	if (startclk > cur_freq) {
		for (n = 0; freq_seq[n] != -1; n++) {
			if (startclk <= freq_seq[n])
				break;
		}
		if (freq_seq[n] != -1) {
			cur_freq = freq_seq[n];
			applog(LOG_INFO, "Setting user specified clock: %dmhz...", cur_freq);
			fpga_set_freq(fd, cur_freq);
			Sleep(dly);
		}
	}

	return 0;
}

int fpga_freq_init_fast(int fd, int startclk)
{
	//int boot_seq[] = { 100, 200, 300, 400, 500, 600, -1 };
	int boot_seq[] = { 100, 200, 300, 400, 500, -1 };

	return fpga_freq_ramp_up(fd, 500, boot_seq, startclk);
}

int fpga_freq_init(int fd, int startclk)
{
	//int boot_seq[] = { 100, 200, 300, 320, 340, 360, 380, 400, 420, 440, 460, 480, 500, 520, 540, 560, 580, 600, 620, 640, 660, 680, 700, 720, 740, 760, 780, 800, -1 };
	int boot_seq[] = { 100, 200, 300, 400, 500, -1 };

	return fpga_freq_ramp_up(fd, 3000, boot_seq, startclk);
}


/*int fpga_freq_init(int fd, int sz, int startclk)
{

	//	int n, boot_seq[] = { 100, 200, 300, 380, 460, 500, -1 };
	int n, boot_seq[] = { 100, 200, 300, 400, 500, -1 };
	int start_freq = 100;

	//get current operating freq
	cur_freq = fpga_get_freq(fd);

	applog(LOG_INFO, "Slowly increasing clock rate...");
	fpga_set_freq(fd, start_freq);
	Sleep(500);

	for (n = 0; boot_seq[n] != -1; n++) {
		applog(LOG_INFO, "Increasing clock: %dmhz...", boot_seq[n]);
		fpga_set_freq(fd, boot_seq[n]);
		Sleep(500);
		cur_freq = boot_seq[n];
		if (startclk > 0 && startclk < cur_freq)
			break;
	}

	if (startclk > 0) {
		for (n = 0; freq_seq[n] != -1; n++) {
			if (startclk <= freq_seq[n])
				break;
		}
		if (freq_seq[n] != -1) {
			cur_freq = freq_seq[n];
			applog(LOG_INFO, "Setting user specified clock: %dmhz...", cur_freq);
			fpga_set_freq(fd, cur_freq);
		}
	}

	return 0;
}*/

int fpga_freq_deinit(int fd, int sz)
{

	int n, boot_seq[] = { 400, 300, 200, 100, -1 };
	int start_freq = 100;
	static uint8_t buf[1024];

	if (sz >= 1023) {
		applog(LOG_INFO, "fpga_freq_deinit: data size is too large for the buffer.");
		exit(0);
	}
	memset(buf, 0, sz + 1);

	//printf("FPGA is currently running at %d MHz, ramping down...\n", cur_freq);
	applog(LOG_INFO, "FPGA clock is ramping down...");

	for (n = 0; boot_seq[n] != -1; n++) {
		if (cur_freq <= boot_seq[n])
			continue;

		applog(LOG_INFO, "Decreasing clock: %dmhz...", boot_seq[n]);
		fpga_set_freq(fd, boot_seq[n]);
		Sleep(333);
		cur_freq = boot_seq[n];
	}

	fpga_core_disable(fd);
	//Sleep(500);
	cur_freq = boot_seq[n];

	//Sleep(1000);

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
		return fpga_freq_increase(fd);

	case '-':
		return fpga_freq_decrease(fd);

	case 'C':
	case 'c':
		return -1;

	}

	return 0;
}

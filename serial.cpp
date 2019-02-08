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
#include "serial.h"

int serial_setup_com_port(HANDLE hSerial, unsigned long baud, signed short timeout, bool purge)
{
	COMMCONFIG comCfg = { 0 };
	comCfg.dwSize = sizeof(COMMCONFIG);
	comCfg.wVersion = 1;
	comCfg.dcb.DCBlength = sizeof(DCB);
	comCfg.dcb.BaudRate = baud;
	comCfg.dcb.fBinary = 1;
	comCfg.dcb.fDtrControl = DTR_CONTROL_ENABLE;
	comCfg.dcb.fRtsControl = RTS_CONTROL_ENABLE;
	comCfg.dcb.ByteSize = 8;

	SetCommConfig(hSerial, &comCfg, sizeof(comCfg));

	// Code must specify a valid timeout value (0 means don't timeout)
	const DWORD ctoms = (timeout * 100);
	//const DWORD ctoms = (1 * 100);
	COMMTIMEOUTS cto = { ctoms, 1, ctoms, 1, ctoms };
	SetCommTimeouts(hSerial, &cto);

	// Configure Windows to Monitor the serial device for Character Reception
	SetCommMask(hSerial, EV_RXCHAR);

	if (purge) {
		PurgeComm(hSerial, PURGE_RXABORT);
		PurgeComm(hSerial, PURGE_TXABORT);
		PurgeComm(hSerial, PURGE_RXCLEAR);
		PurgeComm(hSerial, PURGE_TXCLEAR);
	}

	return 0;
}

int serial_open(const char *devpath, unsigned long baud, signed short timeout, bool purge)
{
	HANDLE hSerial = CreateFile(devpath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if ((hSerial == INVALID_HANDLE_VALUE))
	{
		DWORD e = GetLastError();
		switch (e) {
		case ERROR_ACCESS_DENIED:
			applog(LOG_ERR, "Do not have user privileges required to open %s", devpath);
			break;
		case ERROR_SHARING_VIOLATION:
			applog(LOG_ERR, "%s is already in use by another process", devpath);
			break;
		case ERROR_FILE_NOT_FOUND:
			applog(LOG_ERR, "Device %s not found", devpath);
			break;
		default:
			applog(LOG_ERR, "Open %s failed, GetLastError:%d", devpath, (int)e);
			break;
		}
		return -1;
	}

	if (serial_setup_com_port(hSerial, baud, timeout, purge) != 0)
		return -1;

	return _open_osfhandle((intptr_t)hSerial, 0);
}

static size_t _serial_read(int fd, char *buf, size_t bufsiz, char *eol)
{
	size_t len, tlen = 0;
	while (bufsiz) {
		len = _read(fd, buf, eol ? 1 : bufsiz);
		if (unlikely(len == -1))
			break;
		tlen += len;
		if (eol && *eol == buf[0])
			break;
		buf += len;
		bufsiz -= len;
	}
	return tlen;
}

int serial_recv(int fd, char *buf, size_t bufsize, size_t *readlen)
{
	BOOL Status;
	DWORD dwEventMask = 0;
	const HANDLE fh = (HANDLE)_get_osfhandle(fd);

	/*	Status = WaitCommEvent(fh, &dwEventMask, NULL); //Wait for the character to be received

	if (Status == FALSE) {
	printf("\n    Error! in Setting WaitCommEvent()");
	return(-1);
	}*/

	DWORD NoBytesRead = 0;
	char TempChar;
	int len = 0;

	do {
		Status = ReadFile(fh, &TempChar, sizeof(TempChar), &NoBytesRead, NULL);

		buf[len++] = TempChar;

		if (len == bufsize)
			break;

	} while (NoBytesRead > 0);

	*readlen = (size_t)len;
	return(0);
}

void serial_close(int fd)
{
	_close(fd);
}

int serial_send(int fd, char *buf, size_t bufsize)
{
	return _write(fd, buf, bufsize);
}

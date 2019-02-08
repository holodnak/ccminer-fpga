#pragma once

int serial_setup_com_port(HANDLE hSerial, unsigned long baud, signed short timeout, bool purge);
int serial_open(const char *devpath, unsigned long baud, signed short timeout, bool purge);
void serial_close(int fd);
int serial_recv(int fd, char *buf, size_t bufsize, size_t *readlen);
int serial_send(int fd, char *buf, size_t bufsize);

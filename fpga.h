#pragma once

int fpga_open(const char *devpath);

int serial_open(const char *devpath, unsigned long baud, signed short timeout, bool purge);
int serial_recv(int fd, char *buf, size_t bufsize, size_t *readlen);

#pragma once

#ifdef WIN32
#ifndef timersub
#define timersub(a, b, result)                     \
    do {                                               \
      (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;    \
      (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
      if ((result)->tv_usec < 0) {                     \
        --(result)->tv_sec;                            \
        (result)->tv_usec += 1000000;                  \
      }                                                \
    } while (0)
#endif
#ifndef timeradd
#define timeradd(a, b, result)            \
   do {                   \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;       \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;        \
    if ((result)->tv_usec >= 1000000)           \
      {                   \
  ++(result)->tv_sec;             \
  (result)->tv_usec -= 1000000;           \
      }                   \
   } while (0)
#endif
#endif
#define EPOCHFILETIME (116444736000000000LL)

void printData(void* data, int size);
void printData32(void* data, int size);
void printDataFPGA(void *data, int size);
void printDataFPGAs(void* data, int size);
void printDataC(void *data, int size);

void decius_time(lldiv_t *lidiv);
void cgtime(struct timeval *tv);
void bswap(unsigned char* b, int len);
void bswap64(unsigned char* b, int len);
void reverse(unsigned char *b, int len);

int fpga_open(const char *devpath);
int fpga_open_port(int port);
void fpga_close(int fd);
int fpga_read(int fd, void *buf, size_t sz, size_t *read_sz);
int fpga_write(int fd, void *buf, size_t sz);

int fpga_freq_increase(int fd);
uint8_t fpga_get_freq(int fd);
int fpga_set_freq(int fd, int fr);
int fpga_freq_decrease(int fd);
int fpga_freq_init(int fd, int sz, int startclk);
int fpga_freq_check_keys(int fd);

typedef struct fpgainfo_s {
	uint8_t algo_id;
	uint8_t version;
	uint8_t target;
	uint16_t data_size;
} fpgainfo_t;

//algo id definitions
#define ALGOID_TEST			0x00
#define ALGOID_0xBITCOIN	0x01
#define ALGOID_VERIBLOCK	0x02
#define ALGOID_KECCAK		0x10
#define ALGOID_SHA256Q		0x11
#define ALGOID_SHA256T		0x12
#define ALGOID_GROESTL		0x13
#define ALGOID_SKEIN2		0x14
#define ALGOID_BMW512		0x15
#define ALGOID_PHI1612		0x30
#define ALGOID_POLYTIMOS	0x31
#define ALGOID_BSHA3		0x32

//hardware definitions
#define HW_XILINX	0x0
#define HW_ALTERA	0x1
#define HW_LATTICE	0x2
//#define HW_UNKNOWN	0x3

struct algo_id_str_s {
	uint8_t id;
	char *name;
};

extern struct algo_id_str_s algo_id_str[];

int fpga_send_start(int fd);
int fpga_get_info(int fd, fpgainfo_t *info);
uint64_t fpga_get_ident(int fd);

int fpga_send_data(int fd, void *buf, size_t sz);
int fpga_send_command(int fd, uint8_t cmd);
int fpga_recv_response(int fd, uint8_t *buf);

int fpga_init_device(int fd, int sz, int startclk);
int fpga_find_device(int algo);

char *fpga_algo_id_to_string(int id);
char *fpga_target_to_string(int id);
int fpga_algo_to_algoid(int id);

void fpga_check_licenses(int algo);
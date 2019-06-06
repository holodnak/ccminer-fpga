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
void fprintDataFPGA(FILE* fp, void* data, int size);
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
#define ALGOID_NEOSCRYPT	0x33
#define ALGOID_HONEYCOMB	0x34

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

char *fpga_algo_id_to_string(int id);
char *fpga_target_to_string(int id);
int fpga_algo_to_algoid(int id);


//fpga2.cpp
typedef struct fpga_device_s {

	//com port
	int port;

	//dna
	char dna[32];

	//bitstream info
	int fresh;
	int licvalid;
	int freq;
	int algo_id;
	int version;
	int hardware;
	int datasize;

} fpga_device_t;

int fpga2_init();
void fpga2_kill();
int fpga2_find_devices(int algo_id);
uint64_t fpga2_read_ident(int fd);
bool fpga2_read_dna(int fd, fpga_device_t* device);
bool fpga2_read_info(int fd, fpga_device_t* device);
int fpga2_find_device();
int fpga2_get_device_com_port(int idx);
char* fpga2_get_device_dna(int idx);
int fpga2_get_device_version(int idx);
int fpga2_get_device_by_com_port(int port);
int fpga2_find_licenses();
int fpga2_check_license(int i);

//fpga2_helper.cpp
uint8_t* fpga2_find_com_ports();
uint8_t* fpga2_find_fpga_ports();

//fpga2_open.cpp
int fpga2_open(const char* devpath);
int fpga2_open_by_port(int port);
int fpga2_open_by_dna(const char* dna);
void fpga2_close(int fd);

//fpga2_license.cpp
int fpga2_license_clear_data();
int fpga2_license_load_file(char* filename);
int fpga2_license_load_path(char* path);
int fpga2_license_get(const char* dna, char* hash);

int FindFiles(char* filter, void (*cb)(void*, char*), void* data);
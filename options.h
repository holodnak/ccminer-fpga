#pragma once

struct pool_info_s {
	int algo;
	char url[1024];
	char user[1024];
	char pass[1024];
};

typedef struct pool_info_s pool_info_t; 

int get_dev_pool(pool_info_t *info, int algo);
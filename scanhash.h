#pragma once

#include <stdint.h>

int scanhash_sha256q(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);

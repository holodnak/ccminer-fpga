#pragma once

#include <stdint.h>

int scanhash_sha256q(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_skein2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_lyra2v3(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done);
int scanhash_bmw512(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done);
int scanhash_phi1612(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done);
int scanhash_neoscrypt(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done);
int scanhash_honeycomb(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done);
int scanhash_bsha3(int thr_id, struct work* work, uint32_t max_nonce, uint64_t* hashes_done);
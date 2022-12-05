/* Copyright 2022 - Linaro Ltd. www.linaro.org
 *
 */
#include <openssl/engine.h>
#include <stdio.h>

#ifndef INCLUDE_MD5_MB_COMMON_H
#define INCLUDE_MD5_MB_COMMON_H

// #define ERR_PRINT	printf
#define ERR_PRINT(format, ...) \
	fprintf(stderr, "%s %d:" format, __FILE__, __LINE__, ##__VA_ARGS__)

// #define DBG_PRINT
#define DBG_PRINT(format, ...) \
	fprintf(stderr, "%s %d:" format, __FILE__, __LINE__, ##__VA_ARGS__)

/* served as a key to ASYNC_JOBs */
extern const char *engine_id;

/**
 * @brief this structure contains the private data for interfacing
 *        with multi-threaded isa-l_crypto
 * @ctx_idx: index of a MD5_HASH_CTX from the pool, allocated by this engine
 *           during EVP_MD init()
 */ 
struct digest_priv_ctx {
	int ctx_idx;
};

int md5_mb_digest_init_common(struct digest_priv_ctx *priv);
int md5_mb_digest_update_common(struct digest_priv_ctx *priv,
				const void *data, size_t data_len);
int md5_mb_digest_final_common(struct digest_priv_ctx *priv,
			       unsigned char *out,
			       size_t *outl,
			       size_t outsz);
#endif /* INCLUDE_MD5_MB_COMMON_H */

/* Copyright 2022 - Linaro Ltd. www.linaro.org
 *
 */
#ifndef ISAL_CRYPTO_INF_H
#define ISAL_CRYPTO_INF_H 

#define unlikely(x)	__builtin_expect((x), 0)
#define likely(x)	__builtin_expect((x), 1)

extern int wd_do_digest_init(void);
extern int wd_do_digest_sync(int ctx_idx, const unsigned char *buff, uint32_t len);
extern int wd_do_digest_async(int ctx_idx, const unsigned char *buff, uint32_t len, int wait_fd);
extern int wd_do_digest_final(int ctx_idx, unsigned char *digest);
extern int isal_crypto_md5_multi_thread_init(void);
extern int isal_crypto_md5_multi_thread_destroy (void);
extern int free_bandwidth_ctx_slots(void);

#endif
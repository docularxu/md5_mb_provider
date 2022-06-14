/* Copyright 2022 - Linaro Ltd. www.linaro.org
 *
 */
#include <openssl/engine.h>

extern const char *engine_id;
extern int md5_mb_bind_digest(ENGINE *e);
extern void md5_mb_destroy_digest(void);

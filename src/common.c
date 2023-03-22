/* Copyright 2022 - Linaro Ltd. www.linaro.org
 *
 */

/* These are common stuffs shared by OpenSSL v1.1.1 Engine and
 * OpenSSL v3.0 Provider
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <openssl/engine.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/async.h>
#include <sys/eventfd.h>
#include "e_md5_mb.h"
#include "isal_crypto_inf.h"
#include "common.h"

/* served as a key to ASYNC_JOBs */
const char *engine_id = "md5_mb";

static void async_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
			     OSSL_ASYNC_FD readfd, void *custom)
{
	close(readfd);
}

/**
 * @brief common routine to initialize md5_mb_digest
 * 
 * @param priv: digest context information
 * @return int, 0 for failure, 1 for success 
 */
int md5_mb_digest_init_common(struct digest_priv_ctx *priv)
{
	ASYNC_JOB *a_job;
	int ret = 0;

	/* to check if it's async or not? */
	a_job = ASYNC_get_current_job();
	if (a_job != NULL) {	/* this is an OPENSSL async job */
		DBG_PRINT("_init: Async mode\n");
	} else {
		DBG_PRINT("_init: NOT Async mode\n");
	}

	ret = wd_do_digest_init();
	if (unlikely(ret < 0))
		goto err;
	priv->ctx_idx = ret;

	return 1;
err:
	return 0;
}

/**
 * @brief common routine to update the digest using data of data_len
 * 
 * @param priv: digest context information
 * @param data: pointer to data to be MD5'ed
 * @param data_len: length of data
 * @return int, 0 for failure, 1 for success. 
 */
int md5_mb_digest_update_common(struct digest_priv_ctx *priv,
				const void *data, size_t data_len)
{
	ASYNC_JOB *a_job;
	ASYNC_WAIT_CTX *wait_ctx;
	OSSL_ASYNC_FD wait_fd;
	uint64_t buf;
	int ret;

	/* to check if it's async or not? */
	a_job = ASYNC_get_current_job();
	if (a_job != NULL) {	/* this is an OPENSSL async job */
		DBG_PRINT("_update Async mode\n");

		/* set wait_fd */
		wait_ctx = ASYNC_get_wait_ctx(a_job);
		if (wait_ctx == NULL) {
			ERR_PRINT("ASYNC_get_wait_ctx() returns NULL\n");
			return 0;
		}

		// if (ASYNC_WAIT_CTX_get_fd(wait_ctx, engine_id, &wait_fd, NULL) == 0) {
		/* TODO: move this to _init */
		wait_fd = eventfd(0, EFD_NONBLOCK);
		if (unlikely(wait_fd == -1))
			return 0;

		if (ASYNC_WAIT_CTX_set_wait_fd(wait_ctx, engine_id, wait_fd,
					       NULL, async_fd_cleanup) == 0) {
			ERR_PRINT("ASYNC_WAIT_CTX set wait fd error\n");
			async_fd_cleanup(wait_ctx, engine_id, wait_fd, NULL);
			return 0;
		}
		DBG_PRINT("before calling wd_do_digest_async(), wait_fd=%d\n", wait_fd);

		/* do job async'ly */
		wd_do_digest_async(priv->ctx_idx, data, data_len, wait_fd);

		/* pause */
		if (ASYNC_pause_job() == 0)
			return 0;	/* failure */

		DBG_PRINT("resumed from ASYNC_pause_job(), wait_fd=%d\n", wait_fd);
		/* resumed */
		ret = read(wait_fd, &buf, sizeof(uint64_t));
		if (unlikely(ret != sizeof(uint64_t))) {
			return 0;
		}
		DBG_PRINT("read(wait_fd=%d) retured bytes: ret=%d\n", wait_fd, ret);
		/* TODO: move this to _init */
		/* TODO: check the return value */
		ASYNC_WAIT_CTX_clear_fd(wait_ctx, engine_id);
		close(wait_fd);
		return 1;
	} else {
		DBG_PRINT("_update: NOT Async mode\n");
	}

	/* sync mode */
	ret = wd_do_digest_sync(priv->ctx_idx, data, data_len);
	if (unlikely(ret < 0)) {
		/* failed */
		return 0;
	}

	/* succeed */
	return 1;
}

/**
 * @brief common routine to retrieve the digest value and place it in *out
 * 
 * @param dctx: a pointer to the provider side context
 * @param out: pointer to a output buffer for MD5 digest
 * @param outl: if not NULL, return the length of the digest
 * @param outsz: the digest should not exceed <outsz> bytes
 * @return int, 0 for failure, 1 for success. 
 */
int md5_mb_digest_final_common(struct digest_priv_ctx *priv,
			       unsigned char *out,
			       size_t *outl,
			       size_t outsz)
{

	int ret = 0;
	ASYNC_JOB *a_job;

	/* to check if it's async or not? */
	a_job = ASYNC_get_current_job();
	if (a_job != NULL) {	/* this is an OPENSSL async job */
		DBG_PRINT("_final: Async mode\n");
	}

	ret = wd_do_digest_final(priv->ctx_idx, out);

	if (unlikely(ret < 0)) {
		/* failed */
		return 0;
	}

	/* succeeded */
	if (unlikely(outl != NULL))
		*outl = MD5_DIGEST_LENGTH;
	return 1;
}
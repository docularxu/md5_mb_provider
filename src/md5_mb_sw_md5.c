/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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

#define ERR_PRINT	printf
#define DBG_PRINT
// #define DBG_PRINT	printf

/**
 * @brief this structure contains the private data for interfacing
 *        with multi-threaded isa-l_crypto
 * @ctx_idx: index of a MD5_HASH_CTX from the pool, allocated by this engine
 *           during EVP_MD init()
 */ 
struct digest_priv_ctx {
	int ctx_idx;
};

static int digest_nids[] = {
	NID_md5,
	0,
};

static EVP_MD *md5_mb_md5;

static int md5_mb_engine_digests(ENGINE *e, const EVP_MD **digest,
			       const int **nids, int nid)
{
	int ok = 1;

	if (!digest) {
		*nids = digest_nids;
		return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
	}

	switch (nid) {
	case NID_md5:
		*digest = md5_mb_md5;
		break;
	default:
		ok = 0;
		*digest = NULL;
		break;
	}

	return ok;
}

/**
 * @brief initialize md5_mb_digest
 * 
 * @param ctx 
 * @return int, 0 for failure, 1 for success. 
 */
static int md5_mb_digest_init(EVP_MD_CTX *ctx)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
	int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));
	int ret;

	/* to check if it's async or not? */
	ASYNC_JOB *a_job;
	a_job = ASYNC_get_current_job();
	if (a_job != NULL) {	/* this is an OPENSSL async job */
		DBG_PRINT("_init: Async mode\n");
	}
	/* TODO: intialize &priv user data
	 *   - ref: uadk-engine sets ctx_cfg, ctxs, and sched policy
	 */

	// TODO: ret = wd_digest_init(&priv->ctx_cfg, &priv->sched);

	switch (nid) {
	case NID_md5:
		ret = wd_do_digest_init();
		if (unlikely(ret < 0))
			goto out;
		priv->ctx_idx = ret;
		break;
	default:
		goto out;
	}

	/* TODO: do we need a session? */
	// priv->sess = wd_digest_alloc_sess(&priv->setup);

	return 1;
out:
	return 0;
}


static void async_fd_cleanup(ASYNC_WAIT_CTX *ctx, const void *key,
			     OSSL_ASYNC_FD readfd, void *custom)
{
	close(readfd);
}

/**
 * @brief update the digest using data of data_len
 * 
 * @param ctx 
 * @param data: pointer to data to be MD5'ed
 * @param data_len: length of data
 * @return int, 0 for failure, 1 for success. 
 */
static int md5_mb_digest_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
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
		DBG_PRINT("wait_fd=%d\n", wait_fd);

		if (ASYNC_WAIT_CTX_set_wait_fd(wait_ctx, engine_id, wait_fd,
					       NULL, async_fd_cleanup) == 0) {
			ERR_PRINT("ASYNC_WAIT_CTX set wait fd error\n");
			async_fd_cleanup(wait_ctx, engine_id, wait_fd, NULL);
			return 0;
		}
		DBG_PRINT("before calling wd_do_Async, wait_fd=%d\n", wait_fd);

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
		DBG_PRINT("read(wait_fd) retured bytes: ret=%d\n", ret);
		/* TODO: move this to _init */
		/* TODO: check the return value */
		ASYNC_WAIT_CTX_clear_fd(wait_ctx, engine_id);
		close(wait_fd);
		return 1;
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
 * @brief Retrieves the digest value from ctx and places it in *digest
 * 
 * @param ctx 
 * @param digest: pointer to a output buffer for MD5 digest
 * @return int, 0 for failure, 1 for success. 
 */
static int md5_mb_digest_final(EVP_MD_CTX *ctx, unsigned char *digest)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
	int ret;

	/* to check if it's async or not? */
	ASYNC_JOB *a_job;
	a_job = ASYNC_get_current_job();
	if (a_job != NULL) {	/* this is an OPENSSL async job */
		DBG_PRINT("_final: Async mode\n");
	}

	ret = wd_do_digest_final(priv->ctx_idx, digest);

	if (unlikely(ret < 0)) {
		/* failed */
		return 0;
	}

	/* succeeded */
	return 1;
}

/**
 * @brief cleanup before the private data in *ctx can be freed
 * 
 * @param ctx 
 * @return int, 0 for failure, 1 for success. 
 */
static int md5_mb_digest_cleanup(EVP_MD_CTX *ctx)
{
	/* TODO, WD special. do we need similar?
	wd_digest_free_sess(priv->sess);
	wd_digest_uninit();
	for (i = 0; i < priv->ctx_cfg.ctx_num; i++)
		wd_release_ctx(priv->ctx_cfg.ctxs[i].ctx);
	free(priv->ctx_cfg.ctxs);
	*/

	return 1;
}

#define MD5_MB_DIGEST_DESCR(name, pkey_type, md_size, flags,		\
	block_size, ctx_size, init, update, final, cleanup)		\
do { \
	md5_mb_##name = EVP_MD_meth_new(NID_##name, NID_##pkey_type);	\
	if (md5_mb_##name == 0 ||						\
	    !EVP_MD_meth_set_result_size(md5_mb_##name, md_size) ||	\
	    !EVP_MD_meth_set_input_blocksize(md5_mb_##name, block_size) || \
	    !EVP_MD_meth_set_app_datasize(md5_mb_##name, ctx_size) ||	\
	    !EVP_MD_meth_set_flags(md5_mb_##name, flags) ||		\
	    !EVP_MD_meth_set_init(md5_mb_##name, init) ||			\
	    !EVP_MD_meth_set_update(md5_mb_##name, update) ||		\
	    !EVP_MD_meth_set_final(md5_mb_##name, final) ||		\
	    !EVP_MD_meth_set_cleanup(md5_mb_##name, cleanup))		\
		return 0; \
} while (0)

int md5_mb_bind_digest(ENGINE *e)
{
	/* bind to ISA-L_crypto MD5 multi-thread framework */
	isal_crypto_md5_multi_thread_init();

	MD5_MB_DIGEST_DESCR(md5, md5WithRSAEncryption, MD5_DIGEST_LENGTH,
			  0, MD5_CBLOCK,
			  sizeof(EVP_MD *) + sizeof(struct digest_priv_ctx),	/* TODO */
			  md5_mb_digest_init, md5_mb_digest_update,
			  md5_mb_digest_final, md5_mb_digest_cleanup);

	return ENGINE_set_digests(e, md5_mb_engine_digests);
}

void md5_mb_destroy_digest(void)
{
	EVP_MD_meth_free(md5_mb_md5);
	md5_mb_md5 = 0;

	/* tear down */
	isal_crypto_md5_multi_thread_destroy();
}
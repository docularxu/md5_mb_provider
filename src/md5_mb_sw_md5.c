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
#include "common.h"

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
/* The EVP_MD_type(), EVP_MD_nid(), EVP_MD_name(), EVP_MD_pkey_type(),
 * EVP_MD_size(), EVP_MD_block_size(), EVP_MD_flags(), EVP_MD_CTX_size(),
 * EVP_MD_CTX_block_size(), EVP_MD_CTX_type(), and EVP_MD_CTX_md_data()
 * functions were renamed to include C<get> or C<get0> in their names in
 * OpenSSL 3.0, respectively. The old names are kept as non-deprecated
 * alias macros.
 *
 * The EVP_MD_CTX_md() function was deprecated in OpenSSL 3.0; use
 * EVP_MD_CTX_get0_md() instead.
 */
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
	int nid = EVP_MD_nid(EVP_MD_CTX_md(ctx));

	/* TODO: intialize &priv user data
	 *   - ref: uadk-engine sets ctx_cfg, ctxs, and sched policy
	 */

	// TODO: ret = wd_digest_init(&priv->ctx_cfg, &priv->sched);

	switch (nid) {
	case NID_md5:
		return md5_mb_digest_init_common(priv);
	default:
		goto out;
	}

	/* TODO: do we need a session? */
	// priv->sess = wd_digest_alloc_sess(&priv->setup);
out:
	return 0;
}

/**
 * @brief update the digest using data of data_len
 * 
 * @param ctx 
 * @param data: pointer to data to be MD5'ed
 * @param data_len: length of data
 * @return int, 0 for failure, 1 for success
 */
static int md5_mb_digest_update(EVP_MD_CTX *ctx, const void *data, size_t data_len)
{
	struct digest_priv_ctx *priv =
		(struct digest_priv_ctx *) EVP_MD_CTX_md_data(ctx);
	return md5_mb_digest_update_common(priv, data, data_len);
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

	return md5_mb_digest_final_common(priv, digest, NULL, MD5_DIGEST_LENGTH);
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
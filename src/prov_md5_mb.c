/* This is a wrapper who embeds the underlying md5_mb algorithm into
 * a provider to be used by OpenSSL 3.0 and above
 *
 * Copyright 2022 Linaro Ltd.
 * Author: Guodong Xu <guodong.xu@linaro.org>
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/async.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/proverr.h>
#include <openssl/md5.h>

#include "common.h"
#include "isal_crypto_inf.h"

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_teardown_fn md5_mb_prov_teardown;
static OSSL_FUNC_provider_query_operation_fn md5_mb_prov_query;
static OSSL_FUNC_provider_gettable_params_fn md5_mb_prov_gettable_params;
static OSSL_FUNC_provider_get_params_fn md5_mb_prov_get_params;
static OSSL_FUNC_provider_get_capabilities_fn md5_mb_prov_get_capabilities;

#define ALG(NAMES, FUNC) { NAMES, "provider=md5mb", FUNC }

#ifdef STATIC_MD5_MB
OSSL_provider_init_fn ossl_md5_mb_prov_init;
# define OSSL_provider_init ossl_md5_mb_prov_init
#endif

/* Forward declaration of md5 implementation functions */
static OSSL_FUNC_digest_newctx_fn	md5_mb_newctx;
static OSSL_FUNC_digest_freectx_fn	md5_mb_freectx;
static OSSL_FUNC_digest_dupctx_fn	md5_mb_dupctx;
static OSSL_FUNC_digest_init_fn		md5_mb_dinit;
static OSSL_FUNC_digest_update_fn	md5_mb_dupdate;
static OSSL_FUNC_digest_final_fn	md5_mb_dfinal;
static OSSL_FUNC_digest_get_params_fn	md5_mb_get_params;
static OSSL_FUNC_digest_gettable_params_fn
					md5_mb_gettable_params;

/*
 * md5 algorithm implementations
 */
static void *md5_mb_newctx(void *prov_ctx)
{
	struct digest_priv_ctx *ctx;
	
	ctx = OPENSSL_zalloc(sizeof(*ctx));
	return ctx;
}

static void md5_mb_freectx(void *dctx)
{
	struct digest_priv_ctx *ctx;

	ctx = (struct digest_priv_ctx *)dctx;
	OPENSSL_clear_free(ctx,  sizeof(*ctx));
}

static void *md5_mb_dupctx(void *dctx)
{
	struct digest_priv_ctx *in;
	struct digest_priv_ctx *ret;
	
	in = (struct digest_priv_ctx *)dctx;
	ret = OPENSSL_zalloc(sizeof(struct digest_priv_ctx *));
	
	if (ret != NULL)
		*ret = *in;
	return ret;
}

static int md5_mb_dinit(void *dctx, const OSSL_PARAM params[])
{
	DBG_PRINT("enter %s\n", __func__);
	return md5_mb_digest_init_common((struct digest_priv_ctx *)dctx);
}

static int md5_mb_dupdate(void *dctx, const unsigned char *in, size_t inl)
{
	DBG_PRINT("enter %s\n", __func__);
	return md5_mb_digest_update_common((struct digest_priv_ctx *)dctx,
					   in, inl);
}

/*
 * Note:
 * The I<dctx> parameter contains a pointer to the provider side context.
 * The digest should be written to I<*out> and the length of the digest to I<*outl>.
 * The digest should not exceed I<outsz> bytes.
 */
static int md5_mb_dfinal(void *dctx, unsigned char *out, size_t *outl,
				  size_t outsz)
{
	DBG_PRINT("enter %s\n", __func__);
	return md5_mb_digest_final_common((struct digest_priv_ctx *)dctx,
					  out, outl, outsz);
}

/* some params related code is copied from OpenSSL v3.0 prov/digestcommon.h */
static const OSSL_PARAM digest_default_known_gettable_params[] = {
	OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, NULL),
	OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, NULL),
	OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, NULL),
	OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, NULL),
	OSSL_PARAM_END
};

static const OSSL_PARAM *md5_mb_gettable_params(void *provctx)
{
	return digest_default_known_gettable_params;
}

static int ossl_digest_default_get_params(OSSL_PARAM params[], size_t blksz,
				   size_t paramsz)
{

	OSSL_PARAM *p = NULL;

	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
	if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
	if (p != NULL
		&& !OSSL_PARAM_set_int(p, 0)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
	if (p != NULL
		&& !OSSL_PARAM_set_int(p, 0)) {
		ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
		return 0;
	}
	return 1;
}

static int md5_mb_get_params(OSSL_PARAM params[])
{
	return ossl_digest_default_get_params(params, MD5_CBLOCK,
					      MD5_DIGEST_LENGTH);
}

/* Note: all or none should be implemented:
 * OSSL_FUNC_digest_newctx, OSSL_FUNC_digest_freectx, OSSL_FUNC_digest_init,
 * OSSL_FUNC_digest_update and OSSL_FUNC_digest_final
 */
const OSSL_DISPATCH md5_mb_prov_md5_functions[] = {
	{ OSSL_FUNC_DIGEST_NEWCTX, (void (*)(void))md5_mb_newctx },
	{ OSSL_FUNC_DIGEST_FREECTX, (void (*)(void))md5_mb_freectx },
	{ OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void))md5_mb_dupctx },
	{ OSSL_FUNC_DIGEST_INIT, (void (*)(void))md5_mb_dinit },
	{ OSSL_FUNC_DIGEST_UPDATE, (void (*)(void))md5_mb_dupdate },
	{ OSSL_FUNC_DIGEST_FINAL, (void (*)(void))md5_mb_dfinal },
	{ OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void))md5_mb_get_params },
	{ OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void))md5_mb_gettable_params },
	{ 0, NULL }
};

static const OSSL_ALGORITHM md5_mb_prov_digests[] = {
	ALG(OSSL_DIGEST_NAME_MD5, md5_mb_prov_md5_functions),
	/*
	 * ALG("MD5:SSL3-MD5:1.2.840.113549.2.5", md5_mb_prov_md5_functions),
	 */
	{ NULL, NULL, NULL }
};

/*
 *  Provider context
 */
struct provider_ctx_st {
	const OSSL_CORE_HANDLE *core_handle;
	OSSL_LIB_CTX *libctx;
};

static void provider_ctx_free(struct provider_ctx_st *ctx)
{
	OPENSSL_free(ctx);
}

static struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *handle,
                                                OSSL_LIB_CTX *libctx)
{
	struct provider_ctx_st *ctx;

	if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) != NULL) {
		ctx->core_handle = handle;
		ctx->libctx = libctx;
	}

	return ctx;
}

/*
 * provider DISPATCH routines
 */
static const OSSL_ALGORITHM *md5_mb_prov_query(void *provctx, int operation_id,
						   int *no_cache)
{
	*no_cache = 0;
	switch (operation_id) {
	case OSSL_OP_DIGEST:
		return md5_mb_prov_digests;
	}
	return NULL;
}

/* Parameters we provide to the core */
static const OSSL_PARAM md5_mb_prov_param_types[] = {
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
	OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
	OSSL_PARAM_END
};

static const OSSL_PARAM *md5_mb_prov_gettable_params(void *provctx)
{
	return md5_mb_prov_param_types;
}

static int md5_mb_prov_get_params(void *provctx, OSSL_PARAM params[])
{
	OSSL_PARAM *p;

	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "MD5 multi-buffer Provider"))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "0.1"))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
	if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "rc0"))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
	if (p != NULL && !OSSL_PARAM_set_int(p, 1))
		return 0;
	return 1;
}

static int md5_mb_prov_get_capabilities(void *provctx,
					const char *capability,
					OSSL_CALLBACK *cb,
					void *arg)
{
	int ret = 0;

	/* a single letter 'f' is a request for available free bandwidth
	 * NOTE: to ensure the speed, avoid using longer string and strcmp
	 */
	if (*capability == 'f')
	{
		/* poll the underlying implementor to get free-bandwidth */
		/* (*cb) is ignored */
		/* (*arg) is set to an integer value */
		*(int *)arg = free_bandwidth_ctx_slots();
		ret = 1;
	}
	return ret;
}

static void md5_mb_prov_teardown(void *provctx)
{
	struct provider_ctx_st *pctx = provctx;

	DBG_PRINT("enter %s\n", __func__);
	if (pctx != NULL) {
		OSSL_LIB_CTX_free(pctx->libctx);
		provider_ctx_free(pctx);
	}

	DBG_PRINT("before isal_cryto thread destroy %s\n", __func__);
	/* tear down */
	isal_crypto_md5_multi_thread_destroy();
	DBG_PRINT("exit %s\n", __func__);
}

/* The base dispatch table */
static const OSSL_DISPATCH md5_mb_prov_dispatch_table[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))md5_mb_prov_teardown },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))md5_mb_prov_query },
	{ OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))md5_mb_prov_gettable_params },
	{ OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))md5_mb_prov_get_params },
	{ OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))md5_mb_prov_get_capabilities },
	{ 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
					   const OSSL_DISPATCH *in,
					   const OSSL_DISPATCH **out,
					   void **provctx)
{
	OSSL_LIB_CTX *libctx = NULL;

	/* bind to ISA-L_crypto MD5 multi-thread framework */
	if (isal_crypto_md5_multi_thread_init() != 0)
		goto err;

	/* create libctx */
	if ((libctx = OSSL_LIB_CTX_new()) == NULL) {
		OSSL_LIB_CTX_free(libctx);
		goto err;
	}

	/* set up provctx */
	*provctx = provider_ctx_new(handle, libctx);
	if (*provctx == NULL) {
		OSSL_LIB_CTX_free(libctx);
		goto err;
	}

	*out = md5_mb_prov_dispatch_table;
	DBG_PRINT("prov_md5_mb Provider Init succeed!\n");
	return 1;

err:
	md5_mb_prov_teardown(*provctx);
	*provctx = NULL;
	ERR_PRINT("prov_md5_mb Provider Init failed!\n");
	return 0;
}

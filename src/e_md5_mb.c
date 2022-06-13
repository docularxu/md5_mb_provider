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
#include <openssl/engine.h>
#include "e_md5_mb.h"

/* Constants used when creating the ENGINE */
static const char *engine_id = "md5_mb";
static const char *engine_name = "md5 multi-buffer software engine support";

__attribute__((constructor))
static void md5_mb_constructor(void)
{
}

__attribute__((destructor))
static void md5_mb_destructor(void)
{
}

static int md5_mb_destroy(ENGINE *e)
{
	/* TODO: implement this */
	md5_mb_destroy_digest();

	return 1;
}


static int md5_mb_init(ENGINE *e)
{
	return 1;
}

static int md5_mb_finish(ENGINE *e)
{
	return 1;
}

/*
 * This stuff is needed if this ENGINE is being
 * compiled into a self-contained shared-library.
 */
static int bind_fn(ENGINE *e, const char *id)
{

	if (id && (strcmp(id, engine_id) != 0)) {
		fprintf(stderr, "wrong engine id\n");
		return 0;
	}

	if (!ENGINE_set_id(e, engine_id) ||
	    !ENGINE_set_destroy_function(e, md5_mb_destroy) ||
	    !ENGINE_set_init_function(e, md5_mb_init) ||
	    !ENGINE_set_finish_function(e, md5_mb_finish) ||
	    !ENGINE_set_name(e, engine_name)) {
		fprintf(stderr, "bind failed\n");
		return 0;
	}

	if (!md5_mb_bind_digest(e))
			fprintf(stderr, "md5_mb bind digest failed\n");

	return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

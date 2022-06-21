/**********************************************************************
  Copyright(c) 2022 Linaro Ltd. All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**********************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>

#include <stdlib.h>
#include <poll.h>
#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/md5.h>
#include <isa-l_crypto/md5_mb.h>		/* isa-l_crypto header */
#include "isal_crypto_inf.h"

// #define ERR_PRINT	printf
#define ERR_PRINT(format, ...) \
	fprintf(stderr, "%s %d:" format, __FILE__, __LINE__, ##__VA_ARGS__)

#define DBG_PRINT
// #define DBG_PRINT(format, ...) \
	fprintf(stderr, "%s %d:" format, __FILE__, __LINE__, ##__VA_ARGS__)

// #define DIGEST_VERIFY	/* verify the digest against OpenSSL */

#define NUM_CTX_SLOTS	1024	/* number of available CTX slots
				 * in the CTX_POOL */
#define MAGIC_NUMBER_EXIT_THREAD	(NUM_CTX_SLOTS*2)
#define max(a,b)		(((a) > (b)) ? (a) : (b))

#define CTX_FLUSH_NSEC		(10000)	/* nanoseconds before forced mb_flush */
typedef enum {
	TIME_FLUSH_NEVER = 0,	/* 1 hour */
	TIME_FLUSH_FIRST = 1,	/* CTX_FLUSH_NSEC */
} TIME_FLUSH_LEVEL;

/* Inter-thread communication pipe
 *   One consumer: md5_mb_worker_thread_main
 *   Multiple producers: user threads who calls wd_digest APIs
 */
int pipefd[2];

/* handle of md5 multibuffer work thread */
pthread_t md5_mbthread;

/* MD5_mb manager struct
 *   From a resource viewpoint, one mb manager represents one CPU core. Data
 *   lanes in one CPU core are all the computing resources a mb manager
 *   can use.
 */
MD5_HASH_CTX_MGR md5_ctx_mgr;

typedef int md5_callback_t(void *cb_param);

typedef struct {
	uint32_t	len;
	unsigned char	*buff;
	HASH_CTX_FLAG	flags;
	md5_callback_t	*cb;
	void		*cb_param;
	uint64_t	len_processed;		/* total length of data which has
						 * been processed */
	/* sync mode special */
	sem_t		sem_job_done;		/* sem_post() when finished processing of this CTX */
	/* async mode special */
	bool		is_async;		/* yes or no: OpenSSL ASYNC mode */
	int		wait_fd;		/* write() when finished processing of this CTX */
} MD5_CTX_USERDATA;

/* pre-allocated space for userdata[] */
MD5_CTX_USERDATA	userdata[NUM_CTX_SLOTS];

/* struct of CTX_POOL
 *   All incoming requests must get one MD5_HASH_CTX before it
 *   can be serviced
 */
struct CTX_POOL {
	sem_t		sem_ctx_filled;		/* unlocked when new CTX ready */
	MD5_HASH_CTX	ctxpool[NUM_CTX_SLOTS];
	int		inuse[NUM_CTX_SLOTS];	/* to mark the related
						   ctxpool[slot] in use (1)
						   or not (0) */
	int		cur_idx;		/* the index to start searching */
	pthread_mutex_t	mutex_a;		/* to protect inuse[] and cur_idx */
} md5_ctx_pool;

/* ctx_pool_init -- initialize a pool of MD5_HASH_CTX
 * Return:
 *    0: succeeded
 *   -1: failed
 */
static int ctx_pool_init(void)
{
	int ret = 0;

	if (sem_init(&md5_ctx_pool.sem_ctx_filled, 0, 0) == -1) {
		ERR_PRINT("sem_init .sem_ctx_filled failed\n");
		return -1;
	}

	for (int i = 0; i < NUM_CTX_SLOTS; i ++) {
		md5_ctx_pool.inuse[i] = 0;	// initialzed to not in use
		hash_ctx_init(&md5_ctx_pool.ctxpool[i]);	// Init ctx contents
		// setup .userdata pointer
		md5_ctx_pool.ctxpool[i].user_data = &userdata[i];
		// initialize semaphore
		sem_init(&userdata[i].sem_job_done, 0, 0);
	}
	md5_ctx_pool.cur_idx = 0;		// starting from 0

	if (pthread_mutex_init(&md5_ctx_pool.mutex_a, NULL) != 0) {
		ERR_PRINT("pthread_mutex_init .mutex_a failed\n");
		return -1;
	}

	return 0;	
}

/* ctx_slot_request -- request a free MD5_HASH_CTX from md5_ctx_pool
 * Return:
 *   on success, it returns the index of a free CTX slot.
 *   on failure, it returns a negative value.
 * 	-1: no free CTX slot
 */
static int ctx_slot_request(void)
{
	int ret = -1;

	pthread_mutex_lock(&md5_ctx_pool.mutex_a);
	for (int i = 0; i < NUM_CTX_SLOTS; i ++) {
		if (md5_ctx_pool.inuse[md5_ctx_pool.cur_idx] == 0) {
			md5_ctx_pool.inuse[md5_ctx_pool.cur_idx] = 1;	// update .inuse[]
			ret = md5_ctx_pool.cur_idx;			// return this slot
			md5_ctx_pool.cur_idx =				// increment .cur_idx
				(md5_ctx_pool.cur_idx + 1) % NUM_CTX_SLOTS;
			break;
		};
		md5_ctx_pool.cur_idx =				// increment .cur_idx
			(md5_ctx_pool.cur_idx + 1) % NUM_CTX_SLOTS;
	}
	pthread_mutex_unlock(&md5_ctx_pool.mutex_a);
	return ret;
}

/* ctx_slot_release -- release the designated CTX slot back to the pool
 * Input:
 *   ctx_idx: index of the CTX slot to be released
 * Return:
 *   on success, it returns 0
 *   on failure, it returns a negative value.
 */
static int ctx_slot_release(int ctx_idx)
{
	pthread_mutex_lock(&md5_ctx_pool.mutex_a);
	md5_ctx_pool.inuse[ctx_idx] = 0;	// update .inuse[]
	pthread_mutex_unlock(&md5_ctx_pool.mutex_a);

	return 0;
}

/* wd_md5_ctx_callback -- common callback function for MD5 CTX
 * Input:
 *   ctx: a pointer to a finished MD5_HASH_CTX
 * Return:
 *   on success, it returns 0
 *   on failure, it returns a negative value.
 */
static int wd_md5_ctx_callback(MD5_HASH_CTX *ctx)
{
	MD5_CTX_USERDATA *userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);
	uint64_t buf = 1;

	// update the len_processed
	userdata->len_processed += userdata->len;

	if (userdata->is_async) { /* async mode */
		/* notify by wait_fd */
		if (unlikely(write(userdata->wait_fd, &buf, sizeof(uint64_t)) == -1)) {
			ERR_PRINT("failed to write to wait_fd - error: %d\n", errno);
			return -1;
		}
		return 0;
	} else { /* sync mode */
		return sem_post(&userdata->sem_job_done);
	}
}

/* set_time_flush -- set flush timeout */
static void set_time_flush(struct timespec *ts, TIME_FLUSH_LEVEL level)
{
	clock_gettime(CLOCK_REALTIME, ts);
	switch (level) {
	case TIME_FLUSH_NEVER:
		ts->tv_sec += (60 * 60);	/* 1 hour */
		break;
	case TIME_FLUSH_FIRST:
	default:
		ts->tv_nsec += CTX_FLUSH_NSEC;
		if (ts->tv_nsec >= 1000000000) {
			ts->tv_sec+=1;
			ts->tv_nsec-=1000000000;
		}
		break;
	}
}

/* md5_mb_worker_thread_main -- main thread of md5 multibuffer
 */
static void *md5_mb_worker_thread_main(void *args)
{
	struct timespec time_flush = { 0 };
	MD5_HASH_CTX *ctx = NULL;
	MD5_CTX_USERDATA *userdata;
	int ctx_idx;
	int ret;

	DBG_PRINT("Enter %s\n", __func__);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	set_time_flush(&time_flush, TIME_FLUSH_NEVER);

	while (1) {
		ret = sem_timedwait(&md5_ctx_pool.sem_ctx_filled, &time_flush);
		if (ret == -1 && errno == ETIMEDOUT) {	// timeout
			DBG_PRINT("sem timed out. sec=%ld, nsec=%ld ns\n", time_flush.tv_sec,
					time_flush.tv_nsec);
			// DBG_PRINT(".");
			/* TODO: should we _flush repetitively to finish all jobs,
			 *         or should we _flush only once?
			 *       If _flush only once, should we decrease time_flush
			 *         to make the next timeout come faster?
			 */
			// call _flush() on timeout
			ctx = md5_ctx_mgr_flush(&md5_ctx_mgr);

			// check if a valid *job is returned, call its _cb())
			if (ctx != NULL) {
				userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);
				(userdata->cb)(userdata->cb_param);
				set_time_flush(&time_flush, TIME_FLUSH_FIRST);
			} else {
				// not job pending, no need to timed wait
				set_time_flush(&time_flush, TIME_FLUSH_NEVER);
			}
			continue;	// loop back for next
		}
		
		if (ret == 0) {		// new CTX coming
			// read in CTX index
			ret = read(pipefd[0], &ctx_idx, sizeof(int));
			/* TODO: Need better handling of when (ret != 4)?
			 *       should we read() again, or should we discard?
			 *       If we read() again, how to concatenate &ctx_idx
			 *       If we discard, how to let the producer know?
			 */
			if (unlikely(ret != sizeof(int))) {
				ERR_PRINT("Failed to read from pipe. ret=%d, errno=%d", ret, errno);
				continue;
			}
			if (unlikely(ctx_idx == MAGIC_NUMBER_EXIT_THREAD)) {
				DBG_PRINT("EXIT: md5_mb worker thread\n");
				break;
			} else if (unlikely(ctx_idx >= NUM_CTX_SLOTS)) {
				ERR_PRINT("Unexpected CTX slot index. ctx_idx=%d\n", ctx_idx);
				continue;
			}

			ctx = &md5_ctx_pool.ctxpool[ctx_idx];
			userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);

			DBG_PRINT("read %d bytes from pipe, ctx_idx=%d, data_len=%d\n",
							ret, ctx_idx, userdata->len);

			// call _submit() on new CTX
			ctx = md5_ctx_mgr_submit(&md5_ctx_mgr, ctx, userdata->buff,
						 userdata->len, userdata->flags);

			// check if a valid *job is returned, call its _cb())
			if (ctx != NULL) {
				DBG_PRINT("FULL job lanes. ========================\n");
				DBG_PRINT("Finished: ctx_idx = %ld\n", ctx - &md5_ctx_pool.ctxpool[0]);
				userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);
				(userdata->cb)(userdata->cb_param);
			}

			set_time_flush(&time_flush, TIME_FLUSH_FIRST);
			continue;	// loop back for next
		}

		// on all other errors
		continue;
	}; // end of while
	
	/* exit */
	pthread_exit(&ret);
}

/**
 * @brief Allocate a CTX slot from the md5_ctx_pool and return the index
 * @return:
 *    0 or positive: succeed, return the CTX index
 *    negative: failure
 *    -EBUSY: All CTXs in the md5_ctx_pool have been used. Upper
 *              layer can try again at a later time.
 */
int wd_do_digest_init(void)
{
	int ctx_idx;
	MD5_HASH_CTX *ctx;
	MD5_CTX_USERDATA *userdata;

	// alloc a free CTX
	ctx_idx = ctx_slot_request();
	if (ctx_idx < 0)
		return -EBUSY;
	ctx = &md5_ctx_pool.ctxpool[ctx_idx];
	userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);

	//   - Init ctx contents
	hash_ctx_init(ctx);
	//   - set len_processed to 0
	userdata->len_processed = 0;
	//   - set callback params into .userdata
	userdata->cb_param = (void *)ctx;
	//   - set callback into .userdata
	userdata->cb = (md5_callback_t *)wd_md5_ctx_callback;

	return ctx_idx;
}

/**
 * @brief setup CTX and notify MD5 mb worker thread
 * @return int 
 *     0: succeeded
 *    -1: failed
 */
static inline int send_to_worker_thread(MD5_CTX_USERDATA *userdata,
					   int ctx_idx,
					   const unsigned char *buff,
					   uint32_t len)
{
	int ret;
	//   - according to len_processed to set flags
	if (userdata->len_processed == 0)
		userdata->flags = HASH_FIRST;
	else if (len == 0)
		userdata->flags = HASH_LAST;
	else
		userdata->flags = HASH_UPDATE;

	//   - set *buff and len into .userdata
	userdata->buff = (unsigned char *)buff;
	userdata->len = len;

	// write 'ctx_idx' into pipe
	ret = write(pipefd[1], &ctx_idx, sizeof(ctx_idx));
	if (unlikely(ret < 0)) {
		ERR_PRINT("write to pipefd failed\n");
		return -1;
	}

	// notify MD5 mb worker thread
	sem_post(&md5_ctx_pool.sem_ctx_filled);
	return 0;
}

/**
 * @brief Interface API published to upper layers. When called,
 *     it do MD5 digest calculation in a synchronised manner.
 *
 * @param ctx_idx
 * @param buff
 * @param len
 * @return
 *    0: succeeded
 *    negative: failure
 */
int wd_do_digest_sync(int ctx_idx, const unsigned char *buff, uint32_t len)
{

	int ret;
	MD5_HASH_CTX *ctx;
	MD5_CTX_USERDATA *userdata;

	ctx = &md5_ctx_pool.ctxpool[ctx_idx];
	userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);

	//   - set is_async
	userdata->is_async = false;
	ret = send_to_worker_thread(userdata, ctx_idx, buff, len);
	if (unlikely(ret < 0)) {
		ERR_PRINT("write to pipefd failed\n");
		return -1;
	}

	// waiting on sem_job_done, ->cb() will unlock it when the job is done
	sem_wait(&userdata->sem_job_done);

	return 0;
}

/**
 * @brief Do MD5 digest calculation in a asynchronised manner.
 *
 * @param ctx_idx
 * @param buff
 * @param len
 * @param wait_fd: write() to notify completion of the work
 * @return
 *    0: succeeded
 *    negative: failure
 */
int wd_do_digest_async(int ctx_idx, const unsigned char *buff, uint32_t len,
		       int wait_fd)
{

	int ret;
	MD5_HASH_CTX *ctx;
	MD5_CTX_USERDATA *userdata;

	ctx = &md5_ctx_pool.ctxpool[ctx_idx];
	userdata = (MD5_CTX_USERDATA *)hash_ctx_user_data(ctx);

	//   - set is_async
	userdata->is_async = true;
	userdata->wait_fd = wait_fd;
	ret = send_to_worker_thread(userdata, ctx_idx, buff, len);
	if (unlikely(ret < 0)) {
		ERR_PRINT("write to pipefd failed\n");
		return -1;
	}

	return 0;
}

/**
 * @brief retrieve the digest value and free the CTX slot
 *
 * @param ctx_idx
 * @param digest
 * @return
 *    0: succeeded
 *    negative: failure
 */
#ifdef DIGEST_VERIFY
int wd_do_digest_final(int ctx_idx, unsigned char *digest, unsigned char *md5_ssl)
#else
int wd_do_digest_final(int ctx_idx, unsigned char *digest)
#endif
{
	MD5_HASH_CTX *ctx;

	ctx = &md5_ctx_pool.ctxpool[ctx_idx];

	/* finalize this CTX */
	wd_do_digest_sync(ctx_idx, NULL, 0);

	memcpy(digest, hash_ctx_digest(ctx), MD5_DIGEST_LENGTH);

#ifdef DIGEST_VERIFY
	for (int j = 0; j < MD5_DIGEST_NWORDS; j++) {
		if (ctx->job.result_digest[j] != to_le32(((uint32_t *)md5_ssl)[j])) {
			ERR_PRINT("\n================= DIGEST_FAILURE %08X <=> %08X\n",
				ctx->job.result_digest[j],
				to_le32(((uint32_t *) md5_ssl)[j]));
		}
	}
#endif

	ctx_slot_release(ctx_idx);
	return 0;
}

/**
 * @brief Initialize ISA-L_crypto MD5 multi-thread multi-buffer
 *        framework.
 * Return:
 *    0: succeeded
 *   -1: failed
 */
int isal_crypto_md5_multi_thread_init(void)
{
	int ret = 0;

	
	/* step 1: create a pipe for communitcations */
	if (pipe2(pipefd, O_DIRECT) != 0) {
		ERR_PRINT("pipe creation failed\n");
		return -1;
	}

	/* step 1.1: initialize CTX pool */
	if (ctx_pool_init() !=0) { ERR_PRINT("ctx_pool_init() failed\n");
		// TODO: tear down the pipe
		return -1;
	}

	/* step 2: initialize mb mgr */
	md5_ctx_mgr_init(&md5_ctx_mgr);

	/* step 3: create md5_mb worker thread */
	ret = pthread_create(&md5_mbthread, NULL,
			     &md5_mb_worker_thread_main, (void *)NULL);
	if (ret != 0)
		ERR_PRINT("md5_mb worker thread pthread_create() failed\n");

	return ret;
}

/**
 * @brief Tear down ISA-L_crypto MD5 multi-thread multi-buffer
 *        framwork.
 * Return:
 *    0: succeeded
 *   -1: failed
 */
int isal_crypto_md5_multi_thread_destroy (void)
{
	int ctx_idx = MAGIC_NUMBER_EXIT_THREAD;
	int ret;

	/* TODO:
	 1. flush all unfinished jobs
	 2. destroy mutex, semaphore, such.
	 */
	/* to cancel worker thread, write a invalid positive ctx_idx */
	ret = write(pipefd[1], &ctx_idx, sizeof(ctx_idx));
	if (ret < 0) {
		ERR_PRINT("write to pipefd failed\n");
		return -1;
	}
	// notify MD5 mb worker thread
	sem_post(&md5_ctx_pool.sem_ctx_filled);

	/* wait md5_mbthread to exit */
	pthread_join(md5_mbthread, NULL);

	return 0;
}
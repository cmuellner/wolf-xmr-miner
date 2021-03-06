#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <jansson.h>
#include <stdatomic.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sched.h>

#include "cryptonight.h"
#include "minerutils.h"
#include "minerlog.h"
#include "minernet.h"
#include "ocl.h"

#define ERR_SUCCESS				0
#define ERR_STUPID_PARAMS		-1
#define ERR_OCL_API				-2
#define ERR_NO_SUCH_ALGO		-3

#define STRATUM_TIMEOUT_SECONDS			120

// I know, it's lazy.
#define STRATUM_MAX_MESSAGE_LEN_BYTES	4096

typedef struct _JobInfo
{
	uint32_t XMRTarget;
	uint8_t ID[32];
	uint8_t XMRBlob[76];
	char *blockblob;
} JobInfo;

typedef struct _StatusInfo
{
	uint64_t SolvedWork;
	uint64_t RejectedWork;
	double *ThreadHashCounts;
	double *ThreadTimes;
} StatusInfo;

pthread_mutex_t StatusMutex = PTHREAD_MUTEX_INITIALIZER;
StatusInfo GlobalStatus;

static cryptonight_func *cryptonight_hash_ctx;

typedef struct _WorkerInfo
{
	char *User;
	char *Pass;
	struct _WorkerInfo *NextWorker;
} WorkerInfo;

typedef struct _PoolInfo
{
	SOCKET sockfd;
	char *PoolName;
	char *StrippedURL;
	char *Port;
	WorkerInfo WorkerData;
	uint32_t MinerThreadCount;
	uint32_t *MinerThreads;
	atomic_uint StratumID;
	char XMRAuthID[64];
} PoolInfo;

atomic_bool *RestartMining;

bool ExitFlag = false;
int ExitPipe[2];

JobInfo Jobs[2];
volatile JobInfo *CurrentJob;
volatile int JobIdx;

typedef struct _Share
{
	struct _Share *next;
	JobInfo *Job;
	uint32_t Nonce;
	int Gothash;
	uint8_t Blob[32];
} Share;

typedef struct _ShareQueue
{
	Share *first;
	Share *last;
} ShareQueue;

Share *ShareList;

Share *GetShare()
{
	Share *ret;
	if (ShareList) {
		ret = ShareList;
		ShareList = ret->next;
	} else {
		ret = malloc(sizeof(Share));
	}
	return ret;
}

void SubmitShare(ShareQueue *queue, Share *NewShare)
{
	NewShare->next = NULL;
	
	if(!queue->first) queue->first = queue->last = NewShare;
	else queue->last = queue->last->next = NewShare;
}

Share *RemoveShare(ShareQueue *queue)
{
	Share *tmp = queue->first;
	if(queue->first) queue->first = queue->first->next;	
	return(tmp);
}

void FreeShare(Share *share)
{
	share->next = ShareList;
	ShareList = share;
}

ShareQueue CurrentQueue;
pthread_mutex_t QueueMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t QueueCond = PTHREAD_COND_INITIALIZER;

typedef struct _PoolBroadcastInfo
{
	int poolsocket;
	WorkerInfo WorkerData;
} PoolBroadcastInfo;

int sendit(int fd, char *buf, int len)
{
	int rc;
	do
	{
		rc = send(fd, buf, len, 0);
		if (rc == -1)
			return rc;
		buf += rc;
		len -= rc;
	} while (len > 0);
	return rc < 1 ? -1 : 0;
}

#define BIG_BUF_LEN	262144
void *DaemonUpdateThreadProc(void *Info)
{
	uint64_t id = 10;
	PoolInfo *pbinfo = (PoolInfo *)Info;
	char s[BIG_BUF_LEN];
	void *c_ctx = cryptonight_ctx();

	pthread_mutex_lock(&QueueMutex);
	for(;;)
	{
		pthread_cond_wait(&QueueCond, &QueueMutex);
		for(Share *CurShare = RemoveShare(&CurrentQueue); CurShare; CurShare = RemoveShare(&CurrentQueue))
		{
			char ASCIINonce[9];
			char *ptr;
			int ret, len, hdrlen;

			if (!CurShare->Job->blockblob)
			{
				sleep(1);
				continue;
			}
			BinaryToASCIIHex(ASCIINonce, &CurShare->Nonce, 4U);
			memcpy(CurShare->Job->blockblob+78, ASCIINonce, 8);

			hdrlen = sprintf(s, "POST /json_rpc HTTP/1.0\r\nContent-Length: xxx\r\n\r\n");
			ptr = s + hdrlen;

			len = snprintf(ptr, BIG_BUF_LEN - hdrlen, "{\"method\": \"submitblock\", \"params\": "
				"[\"%s\"]}", CurShare->Job->blockblob);
			sprintf(ptr - 7, "%d", len);
			ptr[-4] = '\r';

			free(CurShare->Job->blockblob);
			CurShare->Job->blockblob = NULL;
			FreeShare(CurShare);

			ret = sendit(pbinfo->sockfd, s, len + hdrlen);
			if (ret == -1)
				break;

			pthread_mutex_lock(&StatusMutex);
			GlobalStatus.SolvedWork++;
			pthread_mutex_unlock(&StatusMutex);

			Log(LOG_NETDEBUG, "Request: %s", s);
		}
	}
	pthread_mutex_unlock(&QueueMutex);
	// free(c_ctx);
	return(NULL);
}

#define JSON_BUF_LEN	345

void *PoolBroadcastThreadProc(void *Info)
{
	uint64_t id = 10;
	PoolInfo *pbinfo = (PoolInfo *)Info;
	char s[JSON_BUF_LEN];
	void *c_ctx = cryptonight_ctx();

	pthread_mutex_lock(&QueueMutex);
	for(;;)
	{
		pthread_cond_wait(&QueueCond, &QueueMutex);
		for(Share *CurShare = RemoveShare(&CurrentQueue); CurShare; CurShare = RemoveShare(&CurrentQueue))
		{
			char ASCIINonce[9], ASCIIResult[65];
			uint8_t HashResult[32];
			int ret, len;
			
			BinaryToASCIIHex(ASCIINonce, &CurShare->Nonce, 4U);
			
			if (!CurShare->Gothash) {
				((uint32_t *)(CurShare->Job->XMRBlob + 39))[0] = CurShare->Nonce;
				cryptonight_hash_ctx(HashResult, CurShare->Job->XMRBlob, c_ctx);
				BinaryToASCIIHex(ASCIIResult, HashResult, 32);
			} else {
				BinaryToASCIIHex(ASCIIResult, CurShare->Blob, 32);
			}
			len = snprintf(s, JSON_BUF_LEN,
				"{\"method\": \"submit\", \"params\": {\"id\": \"%s\", "
				"\"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, "
				"\"id\":1}\r\n\n",
				pbinfo->XMRAuthID, CurShare->Job->ID, ASCIINonce, ASCIIResult);

			FreeShare(CurShare);
			pthread_mutex_lock(&StatusMutex);
			GlobalStatus.SolvedWork++;
			pthread_mutex_unlock(&StatusMutex);
			
			Log(LOG_NETDEBUG, "Request: %s", s);
			
			ret = sendit(pbinfo->sockfd, s, len);
			if (ret == -1)
				break;
			
		}
	}
	pthread_mutex_unlock(&QueueMutex);
	// free(c_ctx);
	return(NULL);
}

static void RestartMiners(PoolInfo *Pool)
{
	for(int i = 0; i < Pool->MinerThreadCount; ++i)
		atomic_store(RestartMining + i, true);
}

static const char getblkc[] = "POST /json_rpc HTTP/1.0\r\nContent-Length: 27\r\n\r\n"
	"{\"method\": \"getblockcount\"}";

#define WALLETLEN	95

static char getblkt[] = "POST /json_rpc HTTP/1.0\r\nContent-Length: 178\r\n\r\n"
	"{\"method\": \"getblocktemplate\", \"params\": {\"reserve_size\": 8, \"wallet_address\": "
	"\"9xaXMreKDK7bctpHtTE9zUUTgffkRvwZJ7UvyJGAQHkvBFqUYWwhVWWendW6NAdvtB8nn883WQxtU7cpe5eyJiUxLZ741t5\"}}";

void *DaemonThreadProc(void *InfoPtr)
{
	PoolInfo *Pool = (PoolInfo *)InfoPtr;
	JobInfo *NextJob;
	char *l, *crlf;
	int poolsocket, ret;
	size_t PartialMessageOffset;
	char rawresponse[BIG_BUF_LEN];
	int len, delay = 32;
	int rlen;
	uint64_t height, prevheight = 0;
	time_t job_time;

	poolsocket = Pool->sockfd;

	if (strlen(Pool->WorkerData.User) != WALLETLEN)
	{
		Log(LOG_ERROR, "Invalid username / wallet address\n");
		return(NULL);
	}
	memcpy(getblkt+128, Pool->WorkerData.User, WALLETLEN);

	ret = sendit(poolsocket, (char *)getblkt, sizeof(getblkt)-1);
	if (ret == -1)
		return(NULL);

	NextJob = &Jobs[0];
	PartialMessageOffset = 0;
	l = NULL;
	crlf = NULL;
	rlen = 0;

	// Listen for work until termination.
	for(;;)
	{
		char *tmsg;
		int mlen;

		// receive
		ret = recv(poolsocket, rawresponse + PartialMessageOffset, 256, 0);
		if (ret <= 0)
		{
fail:
			closesocket(poolsocket);
			RestartMiners(Pool);
retry:
			poolsocket = Pool->sockfd = ConnectToPool(Pool->StrippedURL, Pool->Port);

			if(poolsocket == INVALID_SOCKET)
			{
				Log(LOG_ERROR, "Unable to reconnect to daemon. Sleeping 10 seconds...\n");
				sleep(10);
				goto retry;
			}

			ret = sendit(poolsocket, (char *)getblkc, sizeof(getblkc)-1);
			if (ret == -1)
				return(NULL);

			PartialMessageOffset = 0;
			l = NULL;
			crlf = NULL;
			rlen = 0;
			continue;
		}
		PartialMessageOffset += ret;
		rawresponse[PartialMessageOffset] = 0x00;
		if (!l)
		{
			l = strstr(rawresponse, "Content-Length: ");
			if (!l)
				continue;
		}

		if (!crlf)
		{
			crlf = strstr(l, "\r\n\r\n");
			if (!crlf)
				continue;
		}

		if (!rlen)
		{
			if (sscanf(l + sizeof("Content-Length:"), "%d", &rlen) != 1)
			{
				goto fail;
			}
			tmsg = crlf + 4;
			tmsg[rlen] = 0;
		}
		mlen = PartialMessageOffset - (crlf - rawresponse) - 4;
		mlen = rlen - mlen;
		if (mlen)
		{
			ret = recv(poolsocket, rawresponse + PartialMessageOffset, mlen, 0);
			if (ret <= 0)
				goto fail;
			PartialMessageOffset += ret;
			if (ret < mlen)
				continue;
		}

		// We now have a complete message
		PartialMessageOffset = 0;
		l = NULL;
		crlf = NULL;
		rlen = 0;

		json_t *msg, *result, *err;
		double TotalHashrate = 0;

		Log(LOG_NETDEBUG, "Got something: %s", tmsg);
		msg = json_loads(tmsg, 0, NULL);
		if(!msg)
		{
			Log(LOG_CRITICAL, "Error parsing JSON from daemon.");
			closesocket(poolsocket);
			return(NULL);
		}
		result = json_object_get(msg, "result");
		if (result)
		{
			json_t *jcount, *jheight;
			if ((jcount = json_object_get(result, "count")))
			{
				height = json_integer_value(jcount);
				// new height, get the block info
				if (height != prevheight)
				{
					ret = sendit(poolsocket, getblkt, sizeof(getblkt)-1);
					if (ret == -1)
						return(NULL);
					json_decref(msg);
					continue;
				}
				// height is the same, wait and poll again
			} else if ((jheight = json_object_get(result, "height")))
			{
				height = json_integer_value(jheight);
				const char *tmpl = json_string_value(json_object_get(result, "blocktemplate_blob"));
				const char *hasher = json_string_value(json_object_get(result, "blockhashing_blob"));
				uint64_t diff = json_integer_value(json_object_get(result, "difficulty"));
				ASCIIHexToBinary(NextJob->XMRBlob, hasher, strlen(hasher));
				Log(LOG_NOTIFY, "New block at diff %lu", diff);
				diff = 0xffffffffffffffffUL / diff;
				NextJob->XMRTarget = diff >> 32;
				NextJob->blockblob = strdup(tmpl);
				CurrentJob = NextJob;
				JobIdx++;
				NextJob = &Jobs[JobIdx&1];
				RestartMiners(Pool);
				// reduce polling frequency right after
				// a new block has been announced.
				delay = 32;
				prevheight = height;
				time(&job_time);
				job_time += 240;
			}
			if (jcount || jheight)
			{
				struct timeval timeout;
				timeout.tv_sec = delay;
				timeout.tv_usec = 0;
				// reduce delay between polls
				if (delay > 1)
					delay >>= 1;
				fd_set readfds;
				FD_ZERO(&readfds);
				FD_SET(poolsocket, &readfds);
				ret = select(poolsocket + 1, &readfds, NULL, NULL, &timeout);
				if(ret != 1 || !FD_ISSET(poolsocket, &readfds))
				{
					// reduce polling impact:
					// getblockcount is nearly zero cost
					// but get a new template if we've spent too long on this job
					if (time(NULL) > job_time)
						ret = sendit(Pool->sockfd, (char *)getblkt, sizeof(getblkt)-1);
					else
						ret = sendit(Pool->sockfd, (char *)getblkc, sizeof(getblkc)-1);
					if (ret == -1)
						return(NULL);
				}
				json_decref(msg);
				continue;
			}
		}
		err = json_object_get(msg, "error");
		pthread_mutex_lock(&StatusMutex);

		if(!err && !strcmp(json_string_value(json_object_get(result, "status")), "OK"))
		{
			Log(LOG_INFO, "Block accepted: %d/%d (%.02f%%)", GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
		}
		else
		{
			const char *errmsg;
			GlobalStatus.RejectedWork++;
			errmsg = json_string_value(json_object_get(err, "message"));
			Log(LOG_INFO, "Block rejected (%s): %d/%d (%.02f%%)", errmsg, GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
			if (!JobIdx)
				return(NULL);
		}

		for(int i = 0; i < Pool->MinerThreadCount; ++i)
		{
			TotalHashrate += GlobalStatus.ThreadHashCounts[i] / GlobalStatus.ThreadTimes[i];
		}

		Log(LOG_INFO, "Total Hashrate: %.02fH/s\n", TotalHashrate);

		pthread_mutex_unlock(&StatusMutex);

		json_decref(msg);
		ret = sendit(Pool->sockfd, (char *)getblkt, sizeof(getblkt)-1);
		if (ret == -1)
			return(NULL);
	}
}

void *StratumThreadProc(void *InfoPtr)
{
	uint64_t id = 1;
	JobInfo *NextJob;
	char *workerinfo[3];
	int poolsocket, bytes, ret;
	size_t PartialMessageOffset;
	char rawresponse[STRATUM_MAX_MESSAGE_LEN_BYTES], partial[STRATUM_MAX_MESSAGE_LEN_BYTES];
	PoolInfo *Pool = (PoolInfo *)InfoPtr;
	bool GotSubscriptionResponse = false, GotFirstJob = false;
	char s[JSON_BUF_LEN];
	int len;
	
	poolsocket = Pool->sockfd;
	
	len = snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": "
		"{\"login\": \"%s\", \"pass\": \"%s\", "
		"\"agent\": \"wolf-hyc-xmr-miner/0.1\"}, \"id\": 1}\r\n\n",
		Pool->WorkerData.User, Pool->WorkerData.Pass);

	Log(LOG_NETDEBUG, "Request: %s", s);

	ret = sendit(Pool->sockfd, s, len);
	if (ret == -1)
		return(NULL);
	
	PartialMessageOffset = 0;
	
	SetNonBlockingSocket(Pool->sockfd);
	
	NextJob = &Jobs[0];

	// Listen for work until termination.
	for(;;)
	{
		fd_set readfds;
		uint32_t bufidx, MsgLen;
		struct timeval timeout;
		char StratumMsg[STRATUM_MAX_MESSAGE_LEN_BYTES];
		
		timeout.tv_sec = 480;
		timeout.tv_usec = 0;
		FD_ZERO(&readfds);
		FD_SET(poolsocket, &readfds);
		
		ret = select(poolsocket + 1, &readfds, NULL, NULL, &timeout);
		
		if(ret != 1 || !FD_ISSET(poolsocket, &readfds))
		{
retry2:
			Log(LOG_NOTIFY, "Stratum connection to pool timed out.");
			closesocket(poolsocket);
			RestartMiners(Pool);
retry:
			poolsocket = Pool->sockfd = ConnectToPool(Pool->StrippedURL, Pool->Port);
			
			// TODO/FIXME: This exit is bad and should be replaced with better flow control
			if(poolsocket == INVALID_SOCKET)
			{
				Log(LOG_ERROR, "Unable to reconnect to pool. Sleeping 10 seconds...\n");
				sleep(10);
				goto retry;
			}
			
			Log(LOG_NOTIFY, "Reconnected to pool... authenticating...");
reauth:
			
			Log(LOG_NETDEBUG, "Request: %s", s);

			ret = sendit(Pool->sockfd, s, len);
			if (ret == -1)
				return(NULL);
			
			PartialMessageOffset = 0;
			
			Log(LOG_NOTIFY, "Reconnected to pool.");
			
		}
		
		// receive
		ret = recv(poolsocket, rawresponse + PartialMessageOffset, STRATUM_MAX_MESSAGE_LEN_BYTES - PartialMessageOffset, 0);
		if (ret < 0)
			goto retry2;
		
		rawresponse[ret] = 0x00;
		
		bufidx = 0;
		
		while(strchr(rawresponse + bufidx, '\n'))
		{
			json_t *msg, *msgid, *method;
			json_error_t err;
			
			MsgLen = strchr(rawresponse + bufidx, '\n') - (rawresponse + bufidx) + 1;
			memcpy(StratumMsg, rawresponse + bufidx, MsgLen);
			StratumMsg[MsgLen] = 0x00;
			
			bufidx += MsgLen;
			
			Log(LOG_NETDEBUG, "Got something: %s", StratumMsg);
			msg = json_loads(StratumMsg, 0, NULL);
			
			if(!msg)
			{
				Log(LOG_CRITICAL, "Error parsing JSON from pool server.");
				closesocket(poolsocket);
				return(NULL);
			}
			
			msgid = json_object_get(msg, "id");
			
			// If the "id" field exists, it's either the reply to the
			// login, and contains the first job, or is a share
			// submission response, at least in this butchered XMR Stratum
			// The ID is also stupidly hardcoded to 1 in EVERY case.
			// No ID field means new job
			// Also, error responses to shares have no result
			if(msgid && json_integer_value(msgid))
			{
				json_t *result = json_object_get(msg, "result");
				json_t *authid = NULL;
				
				//if(!result)
				//{
				//	Log(LOG_CRITICAL, "Server sent a message with an ID and no result field.");
				//	json_decref(msg);
				//	close(poolsocket);
				//	return(NULL);
				//}
				
				// Only way to tell the two apart is that the result
				// object on a share submission response has ONLY
				// the status string.
				
				if(result) authid = json_object_get(result, "id");
				
				// Must be a share submission response if NULL
				// Otherwise, it's the first job.
				if(!authid)
				{
					double TotalHashrate = 0;
					json_t *result = json_object_get(msg, "result");
					json_t *err = json_object_get(msg, "error");
					
					pthread_mutex_lock(&StatusMutex);
					
					if(json_is_null(err) && !strcmp(json_string_value(json_object_get(result, "status")), "OK"))
					{
						Log(LOG_INFO, "Share accepted: %d/%d (%.02f%%)", GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
					}
					else
					{
						const char *errmsg;
						GlobalStatus.RejectedWork++;
						errmsg = json_string_value(json_object_get(err, "message"));
						Log(LOG_INFO, "Share rejected (%s): %d/%d (%.02f%%)", errmsg, GlobalStatus.SolvedWork - GlobalStatus.RejectedWork, GlobalStatus.SolvedWork, (double)(GlobalStatus.SolvedWork - GlobalStatus.RejectedWork) / GlobalStatus.SolvedWork * 100.0);
						if (!strcasecmp("Unauthenticated", errmsg)) {
							RestartMiners(Pool);
							pthread_mutex_unlock(&StatusMutex);
							goto reauth;
						}
					}
					
					for(int i = 0; i < Pool->MinerThreadCount; ++i)
					{
						TotalHashrate += GlobalStatus.ThreadHashCounts[i] / GlobalStatus.ThreadTimes[i];
					}
					
					Log(LOG_INFO, "Total Hashrate: %.02fH/s\n", TotalHashrate);
					
					pthread_mutex_unlock(&StatusMutex);
				}
				else
				{
					json_t *job, *blob, *jid, *target;
					
					// cpuminer has it hardcoded to 64, so hell, no point
					// in handling arbitrary sizes here
					strcpy(Pool->XMRAuthID, json_string_value(authid));
					
					job = json_object_get(result, "job");
					
					if(!job)
					{
						Log(LOG_CRITICAL, "Server did not respond to login request with a job.");
						json_decref(msg);
						return(NULL);
					}
					
					blob = json_object_get(job, "blob");
					jid = json_object_get(job, "job_id");
					target = json_object_get(job, "target");
					
					if(!blob || !jid || !target)
					{
						Log(LOG_CRITICAL, "Server sent invalid first job.");
						json_decref(msg);
						return(NULL);
					}
					
					const char *val = json_string_value(blob);
					ASCIIHexToBinary(NextJob->XMRBlob, val, strlen(val));
					strcpy(NextJob->ID, json_string_value(jid));
					NextJob->XMRTarget = __builtin_bswap32(strtoul(json_string_value(target), NULL, 16));
					CurrentJob = NextJob;
					JobIdx++;
					NextJob = &Jobs[JobIdx&1];
					Log(LOG_NOTIFY, "New job at diff %g", (double)0xffffffff / CurrentJob->XMRTarget);
				}
				json_decref(result);
			}
			else
			{
				method = json_object_get(msg, "method");
				if(!method)
				{
					Log(LOG_CRITICAL, "Server message has no id field and doesn't seem to have a method field...");
					json_decref(msg);
					closesocket(poolsocket);
					return(NULL);
				}
				
				if(!strcmp("job", json_string_value(method)))
				{
					json_t *job, *blob, *jid, *target;
					
					job = json_object_get(msg, "params");
					
					if(!job)
					{
						Log(LOG_CRITICAL, "Job notification sent no params.");
						json_decref(msg);
						return(NULL);
					}
					
					blob = json_object_get(job, "blob");
					jid = json_object_get(job, "job_id");
					target = json_object_get(job, "target");
					
					if(!blob || !jid || !target)
					{
						Log(LOG_CRITICAL, "Server sent invalid job.");
						json_decref(msg);
						return(NULL);
					}
					
					const char *val = json_string_value(blob);
					ASCIIHexToBinary(NextJob->XMRBlob, val, strlen(val));
					strcpy(NextJob->ID, json_string_value(jid));
					NextJob->XMRTarget = __builtin_bswap32(strtoul(json_string_value(target), NULL, 16));
					CurrentJob = NextJob;
					JobIdx++;
					NextJob = &Jobs[JobIdx&1];
					
					// No cleanjobs param, so we flush every time
					RestartMiners(Pool);
						
					Log(LOG_NOTIFY, "New job at diff %g", (double)0xffffffff / CurrentJob->XMRTarget);
				}	
				else
				{
					Log(LOG_NETDEBUG, "I have no idea what the fuck that message was.");
				}
				
				json_decref(msg);
			}
		}
		memmove(rawresponse, rawresponse + bufidx, ret - bufidx);
		PartialMessageOffset = ret - bufidx;
	}
}

// AlgoName must not be freed by the thread - cleanup is done by caller.
// RequestedWorksize and RequestedxIntensity should be zero if none was requested
typedef struct _MinerThreadInfo
{
	uint32_t ThreadID;
	uint32_t TotalMinerThreads;
	OCLPlatform *PlatformContext;
	AlgoContext AlgoCtx;
} MinerThreadInfo;

// Block header is 2 uint512s, 1024 bits - 128 bytes
void *MinerThreadProc(void *Info)
{
	int32_t err;
	double CurrentDiff;
	int MyJobIdx;
	JobInfo *MyJob;
	char ThrID[128];
	uint32_t Target, TmpWork[20];
	MinerThreadInfo *MTInfo = (MinerThreadInfo *)Info;
	uint32_t StartNonce = (0xFFFFFFFFU / MTInfo->TotalMinerThreads) * MTInfo->ThreadID;
	uint32_t MaxNonce = StartNonce + (0xFFFFFFFFU / MTInfo->TotalMinerThreads);
	uint32_t Nonce = StartNonce, PrevNonce, platform = 0, device = 1, CurENonce2;
	struct cryptonight_ctx *ctx;
	uint32_t *nonceptr = (uint32_t *)((char *)TmpWork + 39);
	unsigned long hashes_done;
	
	// Generate work for first run.
	MyJobIdx = JobIdx;
	MyJob = CurrentJob;
	memcpy(TmpWork, MyJob->XMRBlob, sizeof(MyJob->XMRBlob));
	Target = MyJob->XMRTarget;
	
	ctx = cryptonight_ctx();
	*nonceptr = StartNonce;
	sprintf(ThrID, "Thread %d, (CPU)", MTInfo->ThreadID);
	
	while(!ExitFlag)
	{
		TIME_TYPE begin, end;
		
		atomic_store(RestartMining + MTInfo->ThreadID, false);
		
		// If JobID is not equal to the current job ID, generate new work
		// off the new job information.
		// If JobID is the same as the current job ID, go hash.
		if(MyJobIdx != JobIdx)
		{
			Log(LOG_DEBUG, "%s: Detected new job, regenerating work.", ThrID);
			MyJobIdx = JobIdx;
			MyJob = CurrentJob;
			memcpy(TmpWork, MyJob->XMRBlob, sizeof(MyJob->XMRBlob));
			Target = MyJob->XMRTarget;
			
			*nonceptr = StartNonce;
		}
		else
		{
			if (!MTInfo->PlatformContext)
				++(*nonceptr);
		}
		
		PrevNonce = MTInfo->AlgoCtx.Nonce;
		
		begin = MinerGetCurTime();
		
		const uint32_t first_nonce = *nonceptr;
		uint32_t n = first_nonce - 1;
		uint32_t hash[32/4] __attribute__((aligned(32)));
		int found = 0;
again:
		do {
			*nonceptr = ++n;
			cryptonight_hash_ctx(hash, TmpWork, ctx);
			if (hash[7] < Target) {
				found = 1;
			} else if (atomic_load(RestartMining + MTInfo->ThreadID)) {
				found = 2;
			}
		} while (!found && n < MaxNonce);
		hashes_done = n - first_nonce;
		if (found == 1) {
			Log(LOG_DEBUG, "%s: SHARE found (nonce 0x%.8X)!", ThrID, *nonceptr);
			pthread_mutex_lock(&QueueMutex);
			Share *NewShare = GetShare();
			
			NewShare->Nonce = *nonceptr;
			NewShare->Gothash = 1;
			memcpy(NewShare->Blob, hash, 32);
			NewShare->Job = MyJob;
			
			SubmitShare(&CurrentQueue, NewShare);
			pthread_cond_signal(&QueueCond);
			pthread_mutex_unlock(&QueueMutex);
		}
		
		end = MinerGetCurTime();
		double Seconds = SecondsElapsed(begin, end);
		
		pthread_mutex_lock(&StatusMutex);
		if (MTInfo->PlatformContext)
			hashes_done = MTInfo->AlgoCtx.Nonce - PrevNonce;
		GlobalStatus.ThreadHashCounts[MTInfo->ThreadID] = hashes_done;
		GlobalStatus.ThreadTimes[MTInfo->ThreadID] = Seconds;
		pthread_mutex_unlock(&StatusMutex);
		
		Log(LOG_INFO, "%s: %.02fH/s", ThrID, hashes_done / (Seconds));
	}
	
	return(NULL);
}

void SigHandler(int signal)
{
	char c;
	ExitFlag = true;
	write(ExitPipe[1], &c, 1);
}

// Signed types indicate there is no default value
// If they are negative, do not set them.

typedef struct _DeviceSettings
{
	uint32_t Platform;
	uint32_t Index;
	uint32_t Threads;
	uint32_t rawIntensity;
	uint32_t Worksize;
	int32_t CoreFreq;
	int32_t MemFreq;
	int32_t FanSpeedPercent;
	int32_t PowerTune;
} DeviceSettings;

// Settings structure for a group of threads mining one algo.
// These threads may be running on diff GPUs, and there may
// be multiple threads per GPU.

typedef struct _AlgoSettings
{
	char *AlgoName;
	uint32_t NumGPUs;
	DeviceSettings *GPUSettings;
	uint32_t TotalThreads;
	uint32_t PoolCount;
	char **PoolURLs;
	WorkerInfo *Workers;
	json_t *AlgoSpecificConfig;
} AlgoSettings;

int ParseConfigurationFile(char *ConfigFileName, AlgoSettings *Settings)
{
	json_t *Config;
	json_error_t Error;
	
	Config = json_load_file(ConfigFileName, JSON_REJECT_DUPLICATES, &Error);
	
	if(!Config)
	{
		Log(LOG_CRITICAL, "Error loading configuration file: %s on line %d.", Error.text, Error.line);
		return(-1);
	}
	
	json_t *AlgoObjArr = json_object_get(Config, "Algorithms");
	if(!AlgoObjArr)
	{
		Log(LOG_CRITICAL, "No 'Algorithms' array found");
		return(-1);
	}
	
	if(!json_array_size(AlgoObjArr))
	{
		Log(LOG_CRITICAL, "Algorithms array empty!");
		return(-1);
	}
	
	json_t *AlgoObj = json_array_get(AlgoObjArr, 0);
	
	json_t *AlgoName = json_object_get(AlgoObj, "name");
	
	if(!AlgoName || !json_is_string(AlgoName))
	{
		Log(LOG_CRITICAL, "Algorithm name missing or not a string.");
		return(-1);
	}
	
	json_t *DevsArr = json_object_get(AlgoObj, "devices");
	
	if(!DevsArr || !json_array_size(DevsArr))
	{
		Log(LOG_CRITICAL, "No devices specified for algorithm %s.", json_string_value(AlgoName));
		return(-1);
	}
	
	Settings->NumGPUs = json_array_size(DevsArr);
	
	Settings->GPUSettings = (DeviceSettings *)malloc(sizeof(DeviceSettings) * Settings->NumGPUs);
	Settings->TotalThreads = 0;
	
	for(int i = 0; i < Settings->NumGPUs; ++i)
	{
		json_t *DeviceObj = json_array_get(DevsArr, i);
		json_t *num = json_object_get(DeviceObj, "index");
		
		if(!num || !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no index.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].Index = json_integer_value(num);
		
		num = json_object_get(DeviceObj, "rawintensity");
		
		if(!num || !json_is_integer(num) || !json_integer_value(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no rawintensity, or rawintensity is set to zero.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].rawIntensity = json_integer_value(num);
		
		num = json_object_get(DeviceObj, "worksize");
		
		if(!num || !json_is_integer(num) || !json_integer_value(num))
		{
			Log(LOG_CRITICAL, "Device structure #%d for algo %s has no worksize, or worksize is set to zero.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		Settings->GPUSettings[i].Worksize = json_integer_value(num);
		
		// Optional
		num = json_object_get(DeviceObj, "threads");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to threads in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].Threads = json_integer_value(num);
		else Settings->GPUSettings[i].Threads = 1;
		
		Settings->TotalThreads += Settings->GPUSettings[i].Threads;
		
		num = json_object_get(DeviceObj, "corefreq");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to corefreq in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].CoreFreq = json_integer_value(num);
		else Settings->GPUSettings[i].CoreFreq = -1;
		
		num = json_object_get(DeviceObj, "memfreq");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to memfreq in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].MemFreq = json_integer_value(num);
		else Settings->GPUSettings[i].MemFreq = -1;
		
		num = json_object_get(DeviceObj, "fanspeed");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to fanspeed in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num && ((json_integer_value(num) > 100) || (json_integer_value(num) < 0)))
		{
			Log(LOG_CRITICAL, "Argument to fanspeed in device structure #%d for algo %s is not a valid percentage (0 - 100).", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
		}
		
		if(num) Settings->GPUSettings[i].FanSpeedPercent = json_integer_value(num);
		else Settings->GPUSettings[i].FanSpeedPercent = -1;
		
		num = json_object_get(DeviceObj, "powertune");
		
		if(num && !json_is_integer(num))
		{
			Log(LOG_CRITICAL, "Argument to powertune in device structure #%d for algo %s is not an integer.", i, json_string_value(AlgoName));
			free(Settings->GPUSettings);
			return(-1);
		}
		
		if(num) Settings->GPUSettings[i].PowerTune = json_integer_value(num);
		else Settings->GPUSettings[i].PowerTune = 0;
	}
	
	// Remove the devices part from the algo object; it's
	// not part of the algo specific options.
	json_object_del(AlgoObj, "devices");
	
	json_t *PoolsArr = json_object_get(AlgoObj, "pools");
	
	if(!PoolsArr || !json_array_size(PoolsArr))
	{
		Log(LOG_CRITICAL, "No pools specified for algorithm %s.", json_string_value(AlgoName));
		return(-1);
	}
	
	Settings->PoolURLs = (char **)malloc(sizeof(char *) * (json_array_size(PoolsArr) + 1));
	Settings->Workers = (WorkerInfo *)malloc(sizeof(WorkerInfo) * ((json_array_size(PoolsArr) + 1)));
	Settings->PoolCount = json_array_size(PoolsArr);
	
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		json_t *PoolObj = json_array_get(PoolsArr, i);
		json_t *PoolURL = json_object_get(PoolObj, "url");
		json_t *PoolUser = json_object_get(PoolObj, "user");
		json_t *PoolPass = json_object_get(PoolObj, "pass");
		
		if(!PoolURL || !PoolUser || !PoolPass)
		{
			Log(LOG_CRITICAL, "Pool structure %d for algo %s is missing a URL, username, or password.", i, json_string_value(AlgoName));
			return(-1);
		}
		
		Settings->PoolURLs[i] = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolURL)) + 1));
		Settings->Workers[i].User = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolUser)) + 1));
		Settings->Workers[i].Pass = (char *)malloc(sizeof(char) * (strlen(json_string_value(PoolPass)) + 1));
		
		strcpy(Settings->PoolURLs[i], json_string_value(PoolURL));
		strcpy(Settings->Workers[i].User, json_string_value(PoolUser));
		strcpy(Settings->Workers[i].Pass, json_string_value(PoolPass));
		
		Settings->Workers[i].NextWorker = NULL;
	}
	
	// Remove the pools part from the algo object; it's
	// not part of the algo specific options.
	json_object_del(AlgoObj, "pools");
	
	Settings->AlgoSpecificConfig = AlgoObj;
	
	Settings->AlgoName = (char *)malloc(sizeof(char) * (strlen(json_string_value(AlgoName)) + 1));
	strcpy(Settings->AlgoName, json_string_value(AlgoName));
	
	return(0);
}

void FreeSettings(AlgoSettings *Settings)
{
	free(Settings->AlgoName);
	free(Settings->GPUSettings);
	
	for(int i = 0; i < Settings->PoolCount; ++i)
	{
		free(Settings->PoolURLs[i]);
		free(Settings->Workers[i].User);
		free(Settings->Workers[i].Pass);
	}
	
	free(Settings->PoolURLs);
	free(Settings->Workers);
}

// Only doing IPv4 for now.

// We should connect to the pool in the main thread,
// then give the socket to threads that need it, so
// that the connection may be cleanly closed.

// TODO: Get Platform index from somewhere else
// TODO/FIXME: Check functions called for error.
int main(int argc, char **argv)
{
	PoolInfo Pool = {0};
	AlgoSettings Settings;
	MinerThreadInfo *MThrInfo;
	OCLPlatform PlatformContext;
	int ret, poolsocket, PlatformIdx = 0;
	pthread_t Stratum, ADLThread, BroadcastThread, *MinerWorker;
	unsigned int tmp1, tmp2, tmp3, tmp4;
	int use_aesni = 0;
	int daemon = 0;
	
	InitLogging(LOG_INFO);
	
	if(argc != 2)
	{
		Log(LOG_CRITICAL, "Usage: %s <config file>", argv[0]);
		return(0);
	}
	
	if(ParseConfigurationFile(argv[1], &Settings)) return(0);
	
	cryptonight_hash_ctx = cryptonight_hash_aesni;

	MThrInfo = (MinerThreadInfo *)malloc(sizeof(MinerThreadInfo) * Settings.TotalThreads);
	MinerWorker = (pthread_t *)malloc(sizeof(pthread_t) * Settings.TotalThreads);
	
	pipe(ExitPipe);
	struct sigaction ExitHandler;
	memset(&ExitHandler, 0, sizeof(struct sigaction));
	ExitHandler.sa_handler = SigHandler;
	
	sigaction(SIGINT, &ExitHandler, NULL);
	signal(SIGPIPE, SIG_IGN);
	
	RestartMining = (atomic_bool *)malloc(sizeof(atomic_bool) * Settings.TotalThreads);
	
	char *TmpPort;
	uint32_t URLOffset;
	
	if(strstr(Settings.PoolURLs[0], "stratum+tcp://"))
		URLOffset = strlen("stratum+tcp://");
	else if(strstr(Settings.PoolURLs[0], "daemon+tcp://"))
	{
		URLOffset = strlen("daemon+tcp://");
		daemon = 1;
	}
	else
		URLOffset = 0;
	
	if(strrchr(Settings.PoolURLs[0] + URLOffset, ':'))
		TmpPort = strrchr(Settings.PoolURLs[0] + URLOffset, ':') + 1;
	else
		TmpPort = "3333";
	
	char *StrippedPoolURL = (char *)malloc(sizeof(char) * (strlen(Settings.PoolURLs[0]) + 1));
	
	int URLSize = URLOffset;
	
	for(; Settings.PoolURLs[0][URLSize] != ':' && Settings.PoolURLs[0][URLSize]; ++URLSize)
		StrippedPoolURL[URLSize - URLOffset] = Settings.PoolURLs[0][URLSize];
	
	StrippedPoolURL[URLSize - URLOffset] = 0x00;
	
	Log(LOG_DEBUG, "Parsed pool URL: %s", StrippedPoolURL);
	
	ret = NetworkingInit();
	
	if(ret)
	{
		Log(LOG_CRITICAL, "Failed to initialize networking with error code %d.", ret);
		return(0);
	}
	
	
	// DO NOT FORGET THIS
	Pool.StrippedURL = strdup(StrippedPoolURL);
	Pool.Port = strdup(TmpPort);
	Pool.WorkerData = Settings.Workers[0];
	Pool.MinerThreadCount = Settings.TotalThreads;
	Pool.MinerThreads = (uint32_t *)malloc(sizeof(uint32_t) * Pool.MinerThreadCount);
	
	for(int i = 0; i < Settings.TotalThreads; ++i) Pool.MinerThreads[i] = Settings.GPUSettings[i].Index;
	
	GlobalStatus.ThreadHashCounts = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	GlobalStatus.ThreadTimes = (double *)malloc(sizeof(double) * Settings.TotalThreads);
	
	GlobalStatus.RejectedWork = 0;
	GlobalStatus.SolvedWork = 0;
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		GlobalStatus.ThreadHashCounts[i] = 0;
		GlobalStatus.ThreadTimes[i] = 0;
	}
	
	for(int i = 0; i < Settings.TotalThreads; ++i) atomic_init(RestartMining + i, false);
	
	Log(LOG_NOTIFY, "Setting up GPU(s).");

	// Note to self - move this list BS into the InitOpenCLPlatformContext() routine
	uint32_t *GPUIdxList = (uint32_t *)malloc(sizeof(uint32_t) * Settings.NumGPUs);
	uint32_t numGPUs = Settings.NumGPUs;
	
	for(int i = 0; i < Settings.NumGPUs; ++i) {
		GPUIdxList[i] = Settings.GPUSettings[i].Index;
		if (Settings.GPUSettings[i].Index == -1)
			numGPUs--;
	}
	
	free(GPUIdxList);
	
	for(int i = 0; i < numGPUs; ++i) PlatformContext.Devices[i].rawIntensity = Settings.GPUSettings[i].rawIntensity;
	
	// Check for zero was done when parsing config
	for(int i = 0; i < numGPUs; ++i)
	{
		if(Settings.GPUSettings[i].Worksize > PlatformContext.Devices[i].MaximumWorkSize)
		{
			Log(LOG_NOTIFY, "Worksize set for device %d is greater than its maximum; using maximum value of %d.", i, PlatformContext.Devices[i].MaximumWorkSize);
			PlatformContext.Devices[i].WorkSize = PlatformContext.Devices[i].MaximumWorkSize;
		}
		else
		{
			PlatformContext.Devices[i].WorkSize = Settings.GPUSettings[i].Worksize;
		}
	}
	
	for(int ThrIdx = 0, GPUIdx = 0; ThrIdx < Settings.TotalThreads && GPUIdx < Settings.NumGPUs; ThrIdx += Settings.GPUSettings[GPUIdx].Threads, ++GPUIdx)
	{
		for(int x = 0; x < Settings.GPUSettings[GPUIdx].Threads; ++x)
		{
			MThrInfo[ThrIdx + x].PlatformContext = NULL;
			MThrInfo[ThrIdx + x].ThreadID = ThrIdx + x;
			MThrInfo[ThrIdx + x].TotalMinerThreads = Settings.TotalThreads;
		}
	}

	// TODO: Have ConnectToPool() return a Pool struct
	poolsocket = ConnectToPool(StrippedPoolURL, TmpPort);
	if(poolsocket == INVALID_SOCKET)
	{
		Log(LOG_CRITICAL, "Fatal error connecting to pool.");
		return(0);
	}
	Pool.sockfd = poolsocket;

	if (daemon)
	{
	Log(LOG_NOTIFY, "Successfully connected to daemon.");

	ret = pthread_create(&Stratum, NULL, DaemonThreadProc, (void *)&Pool);
	if(ret)
	{
		printf("Failed to create Stratum thread.\n");
		return(0);
	}
	} else
	{
	Log(LOG_NOTIFY, "Successfully connected to pool's stratum.");

	ret = pthread_create(&Stratum, NULL, StratumThreadProc, (void *)&Pool);
	if(ret)
	{
		printf("Failed to create Stratum thread.\n");
		return(0);
	}
	}

	// Wait until we've gotten work and filled
	// up the job structure before launching the
	// miner worker threads.
	for(;;)
	{
		if(CurrentJob) break;
		sleep(1);
	}
	
	// Work is ready - time to create the broadcast and miner threads
	if (daemon)
	{
	pthread_create(&BroadcastThread, NULL, DaemonUpdateThreadProc, (void *)&Pool);
	} else
	{
	pthread_create(&BroadcastThread, NULL, PoolBroadcastThreadProc, (void *)&Pool);
	}
	
	for(int i = 0; i < Settings.TotalThreads; ++i)
	{
		ret = pthread_create(MinerWorker + i, NULL, MinerThreadProc, MThrInfo + i);
		
		if(ret)
		{
			printf("Failed to create MinerWorker thread.\n");
			return(0);
		}
	}
	
	char c;
	read(ExitPipe[0], &c, 1);
	
	for(int i = 0; i < Settings.TotalThreads; ++i) pthread_cancel(MinerWorker[i]);
	
	FreeSettings(&Settings);
	free(RestartMining);
	free(Pool.MinerThreads);
	
	closesocket(poolsocket);
	
	NetworkingShutdown();
	
	printf("Stratum thread terminated.\n");
	
	return(0);
}


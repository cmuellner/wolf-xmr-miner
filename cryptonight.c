// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#if USE_INT128

#if __GNUC__ == 4 && __GNUC_MINOR__ >= 4 && __GNUC_MINOR__ < 6
typedef unsigned int uint128_t __attribute__ ((__mode__ (TI)));
#else
typedef __uint128_t uint128_t;
#endif

#endif

#define MEMORY         (1 << 21) /* 2 MiB */
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

static void do_blake_hash(const void* input, size_t len, char* output) {
	blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
	groestl(input, len * 8, (uint8_t*)output);
}

static void do_jh_hash(const void* input, size_t len, char* output) {
	int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
	assert((SUCCESS == r));
}

static void do_skein_hash(const void* input, size_t len, char* output) {
	int r = skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
	assert((SKEIN_SUCCESS == r));
}

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
	do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

struct cryptonight_ctx {
	uint8_t long_state[MEMORY] __attribute((aligned(16)));
	union cn_slow_hash_state state;
	uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
	uint8_t a[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t b[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));
	oaes_ctx* aes_ctx;
};

struct cryptonight_aesni_ctx {
    uint8_t long_state[MEMORY] __attribute((aligned(16)));
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint8_t c[AES_BLOCK_SIZE] __attribute__((aligned(16)));
    oaes_ctx* aes_ctx;
};


struct cryptonight_aesv8_ctx {
    uint8_t long_state[MEMORY] __attribute((aligned(16)));
    union cn_slow_hash_state state;
    uint8_t text[INIT_SIZE_BYTE] __attribute((aligned(16)));
    uint64_t a[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t b[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    uint64_t c[AES_BLOCK_SIZE >> 3] __attribute__((aligned(16)));
    oaes_ctx* aes_ctx;
};

/* ARMv8-A optimized with NEON and AES instructions.
 * Copied from the x86-64 AES-NI implementation. It has much the same
 * characteristics as x86-64: there's no 64x64=128 multiplier for vectors,
 * and moving between vector and regular registers stalls the pipeline.
 */
#include <arm_neon.h>

#define TOTALBLOCKS (MEMORY / AES_BLOCK_SIZE)
#define U64(x) ((uint64_t *) (x))

#define state_index(x) (((*((uint64_t *)x) >> 4) & (TOTALBLOCKS - 1)) << 4)
#define __mul() __asm__("mul %0, %1, %2\n\t" : "=r"(lo) : "r"(ctx->c[0]), "r"(ctx->b[0]) ); \
  __asm__("umulh %0, %1, %2\n\t" : "=r"(hi) : "r"(ctx->c[0]), "r"(ctx->b[0]) );

#define pre_aes() \
  j = state_index(ctx->a); \
  _c = vld1q_u8(&ctx->long_state[j]); \
  _a = vld1q_u8((const uint8_t *)ctx->a); \

#define post_aes() \
  vst1q_u8((uint8_t *)ctx->c, _c); \
  _b = veorq_u8(_b, _c); \
  vst1q_u8(&ctx->long_state[j], _b); \
  j = state_index(ctx->c); \
  p = U64(&ctx->long_state[j]); \
  ctx->b[0] = p[0]; ctx->b[1] = p[1]; \
  { uint64_t hi, lo; \
  __mul(); \
  ctx->a[0] += hi; ctx->a[1] += lo; }\
  p = U64(&ctx->long_state[j]); \
  p[0] = ctx->a[0];  p[1] = ctx->a[1]; \
  ctx->a[0] ^= ctx->b[0]; ctx->a[1] ^= ctx->b[1]; \
  _b = _c; \


/* Note: this was based on a standard 256bit key schedule but
 * it's been shortened since Cryptonight doesn't use the full
 * key schedule. Don't try to use this for vanilla AES.
*/
static void aes_expand_key(const uint8_t *key, uint8_t *expandedKey) {
__asm__("mov x2, %1\n\t" : : "r"(key), "r"(expandedKey));
__asm__(
"	adr	x3,Lrcon\n"
"\n"
"	eor	v0.16b,v0.16b,v0.16b\n"
"	ld1	{v3.16b},[x0],#16\n"
"	ld1	{v1.4s,v2.4s},[x3],#32\n"
"	b	L256\n"
".align 5\n"
"Lrcon:\n"
".long	0x01,0x01,0x01,0x01\n"
".long	0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d,0x0c0f0e0d	// rotate-n-splat\n"
".long	0x1b,0x1b,0x1b,0x1b\n"
"\n"
".align 4\n"
"L256:\n"
"	ld1	{v4.16b},[x0]\n"
"	mov	w1,#5\n"
"	st1	{v3.4s},[x2],#16\n"
"\n"
"Loop256:\n"
"	tbl	v6.16b,{v4.16b},v2.16b\n"
"	ext	v5.16b,v0.16b,v3.16b,#12\n"
"	st1	{v4.4s},[x2],#16\n"
"	aese	v6.16b,v0.16b\n"
"	subs	w1,w1,#1\n"
"\n"
"	eor	v3.16b,v3.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v3.16b,v3.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v6.16b,v6.16b,v1.16b\n"
"	eor	v3.16b,v3.16b,v5.16b\n"
"	shl	v1.16b,v1.16b,#1\n"
"	eor	v3.16b,v3.16b,v6.16b\n"
"	st1	{v3.4s},[x2],#16\n"
"	b.eq	Ldone\n"
"\n"
"	dup	v6.4s,v3.s[3]		// just splat\n"
"	ext	v5.16b,v0.16b,v4.16b,#12\n"
"	aese	v6.16b,v0.16b\n"
"\n"
"	eor	v4.16b,v4.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v4.16b,v4.16b,v5.16b\n"
"	ext	v5.16b,v0.16b,v5.16b,#12\n"
"	eor	v4.16b,v4.16b,v5.16b\n"
"\n"
"	eor	v4.16b,v4.16b,v6.16b\n"
"	b	Loop256\n"
"\n"
"Ldone:\n");
}

/* An ordinary AES round is a sequence of SubBytes, ShiftRows, MixColumns, AddRoundKey. There
 * is also an InitialRound which consists solely of AddRoundKey. The ARM instructions slice
 * this sequence differently; the aese instruction performs AddRoundKey, SubBytes, ShiftRows.
 * The aesmc instruction does the MixColumns. Since the aese instruction moves the AddRoundKey
 * up front, and Cryptonight's hash skips the InitialRound step, we have to kludge it here by
 * feeding in a vector of zeros for our first step. Also we have to do our own Xor explicitly
 * at the last step, to provide the AddRoundKey that the ARM instructions omit.
 */
static inline void aes_pseudo_round(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, int nblocks)
{
	const uint8x16_t *k = (const uint8x16_t *)expandedKey, zero = {0};
	uint8x16_t tmp;
	int i;

	for (i=0; i<nblocks; i++)
	{
		uint8x16_t tmp = vld1q_u8(in + i * AES_BLOCK_SIZE);
		tmp = vaeseq_u8(tmp, zero);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[0]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[1]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[2]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[3]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[4]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[5]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[6]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[7]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[8]);
		tmp = vaesmcq_u8(tmp);
		tmp = veorq_u8(tmp,  k[9]);
		vst1q_u8(out + i * AES_BLOCK_SIZE, tmp);
	}
}

static inline void aes_pseudo_round_xor(const uint8_t *in, uint8_t *out, const uint8_t *expandedKey, const uint8_t *xor, int nblocks)
{
	const uint8x16_t *k = (const uint8x16_t *)expandedKey;
	const uint8x16_t *x = (const uint8x16_t *)xor;
	uint8x16_t tmp;
	int i;

	for (i=0; i<nblocks; i++)
	{
		uint8x16_t tmp = vld1q_u8(in + i * AES_BLOCK_SIZE);
		tmp = vaeseq_u8(tmp, x[i]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[0]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[1]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[2]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[3]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[4]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[5]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[6]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[7]);
		tmp = vaesmcq_u8(tmp);
		tmp = vaeseq_u8(tmp, k[8]);
		tmp = vaesmcq_u8(tmp);
		tmp = veorq_u8(tmp,  k[9]);
		vst1q_u8(out + i * AES_BLOCK_SIZE, tmp);
	}
}

void cryptonight_hash_aesni(void *restrict output, const void *restrict input, struct cryptonight_ctx *restrict ct0)
{
    struct cryptonight_aesv8_ctx *ctx = (struct cryptonight_aesv8_ctx *)ct0;
    uint8_t expandedKey[240];
    uint8x16_t _a, _b, _c;
    const uint8x16_t zero = {0};
    size_t i, j;
    uint64_t *p = NULL;

    /* CryptoNight Step 1:  Use Keccak1600 to initialize the 'state' (and 'text') buffers from the data. */

    keccak1600(input, 76, (uint8_t *)&ctx->state.hs);
    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);

    /* CryptoNight Step 2:  Iteratively encrypt the results from Keccak to fill
     * the 2MB large random access buffer.
     */

    aes_expand_key(ctx->state.hs.b, expandedKey);
    for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
    {
        aes_pseudo_round(ctx->text, ctx->text, expandedKey, INIT_SIZE_BLK);
        memcpy(&ctx->long_state[i * INIT_SIZE_BYTE], ctx->text, INIT_SIZE_BYTE);
    }

    U64(ctx->a)[0] = U64(&ctx->state.k[0])[0] ^ U64(&ctx->state.k[32])[0];
    U64(ctx->a)[1] = U64(&ctx->state.k[0])[1] ^ U64(&ctx->state.k[32])[1];
    U64(ctx->b)[0] = U64(&ctx->state.k[16])[0] ^ U64(&ctx->state.k[48])[0];
    U64(ctx->b)[1] = U64(&ctx->state.k[16])[1] ^ U64(&ctx->state.k[48])[1];

    /* CryptoNight Step 3:  Bounce randomly 1 million times through the mixing buffer,
     * using 500,000 iterations of the following mixing function.  Each execution
     * performs two reads and writes from the mixing buffer.
     */

    _b = vld1q_u8((const uint8_t *)ctx->b);


    for(i = 0; i < ITER / 2; i++)
    {
        pre_aes();
        _c = vaeseq_u8(_c, zero);
        _c = vaesmcq_u8(_c);
        _c = veorq_u8(_c, _a);
        post_aes();
    }

    /* CryptoNight Step 4:  Sequentially pass through the mixing buffer and use 10 rounds
     * of AES encryption to mix the random data back into the 'text' buffer.  'text'
     * was originally created with the output of Keccak1600. */

    memcpy(ctx->text, ctx->state.init, INIT_SIZE_BYTE);

    aes_expand_key(&ctx->state.hs.b[32], expandedKey);
    for(i = 0; i < MEMORY / INIT_SIZE_BYTE; i++)
    {
        // add the xor to the pseudo round
        aes_pseudo_round_xor(ctx->text, ctx->text, expandedKey, &ctx->long_state[i * INIT_SIZE_BYTE], INIT_SIZE_BLK);
    }

    /* CryptoNight Step 5:  Apply Keccak to the state again, and then
     * use the resulting data to select which of four finalizer
     * hash functions to apply to the data (Blake, Groestl, JH, or Skein).
     * Use this hash to squeeze the state array down
     * to the final 256 bit hash output.
     */

    memcpy(ctx->state.init, ctx->text, INIT_SIZE_BYTE);
    keccakf((uint64_t*)(&ctx->state.hs), 24);
    extra_hashes[ctx->state.hs.b[0] & 3](&ctx->state, 200, output);
}

struct cryptonight_ctx* cryptonight_ctx(){
	struct cryptonight_ctx *ret;
	ret = mmap(0, sizeof(*ret), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB|MAP_POPULATE, 0, 0);
	if (ret == MAP_FAILED)
		ret = calloc(1, sizeof(*ret));
	if (ret) {
		madvise(ret, sizeof(*ret), MADV_RANDOM|MADV_WILLNEED|MADV_HUGEPAGE);
		if (!geteuid())
			mlock(ret, sizeof(*ret));
	}
	return ret;
}

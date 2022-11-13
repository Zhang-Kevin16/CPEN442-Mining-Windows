/*
 * sha256.cu Implementation of SHA256 Hashing
 *
 * Date: 12 June 2019
 * Revision: 1
 * *
 * Based on the public domain Reference Implementation in C, by
 * Brad Conte, original code here:
 *
 * https://github.com/B-Con/crypto-algorithms
 *
 * This file is released into the Public Domain.
 */

 // SHA256 CUDA retrieved from https://github.com/mochimodev/cuda-hashing-algos/blob/master/

 /*************************** HEADER FILES ***************************/
#include <cuda_runtime.h>
#include "device_launch_parameters.h"
#include <stdlib.h>
#include <memory.h>
#include <time.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
extern "C" {
#include "sha256.cuh"
}


/****************************** DATA STRUCTURE ******************************/
typedef struct {
	unsigned char data[64];
	unsigned int datalen;
	unsigned long long bitlen;
	unsigned int state[8];
} CUDA_SHA256_CTX;


/****************************** MACROS ******************************/
#define SHA256_HASH_SIZE 32            // SHA256 outputs a 32 byte digest
#define SHA256_BLOCK_SIZE 64
#define ID_SIZE 11
#define NUM_BLOCKS 8192
#define NUM_THREADS 256

// Error checking from https://stackoverflow.com/questions/14038589/what-is-the-canonical-way-to-check-for-errors-using-the-cuda-runtime-api
#define CHECK_ERROR(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code, const char* file, int line, bool abort = true)
{
	if (code != cudaSuccess)
	{
		fprintf(stderr, "GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
		if (abort) exit(code);
	}
}

/****************************** MACROS ******************************/
#ifndef ROTLEFT
#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#endif

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

/**************************** VARIABLES *****************************/
__constant__ unsigned int k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

unsigned int k_host[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

/*********************** FUNCTION DEFINITIONS ***********************/
__host__ __device__ __forceinline__ void cuda_sha256_transform(CUDA_SHA256_CTX* ctx, const unsigned char data[])
{
	unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
#ifdef __CUDA_ARCH__
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
#else
		t1 = h + EP1(e) + CH(e, f, g) + k_host[i] + m[i];
#endif

		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

__host__ __device__ void cuda_sha256_init(CUDA_SHA256_CTX* ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

__host__ __device__ void cuda_sha256_update(CUDA_SHA256_CTX* ctx, const unsigned char data[], size_t len)
{
	unsigned int i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			cuda_sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

__host__ __device__ void cuda_sha256_final(CUDA_SHA256_CTX* ctx, unsigned char hash[])
{
	unsigned int i;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		cuda_sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = (unsigned char) (ctx->bitlen);
	ctx->data[62] = (unsigned char) (ctx->bitlen >> 8);
	ctx->data[61] = (unsigned char) (ctx->bitlen >> 16);
	ctx->data[60] = (unsigned char) (ctx->bitlen >> 24);
	ctx->data[59] = (unsigned char) (ctx->bitlen >> 32);
	ctx->data[58] = (unsigned char) (ctx->bitlen >> 40);
	ctx->data[57] = (unsigned char) (ctx->bitlen >> 48);
	ctx->data[56] = (unsigned char) (ctx->bitlen >> 56);
	cuda_sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

__global__ void kernel_sha256_hash(unsigned char* indata, unsigned int inlen, unsigned char* outdata, unsigned int n_batch)
{
	unsigned int thread = blockIdx.x * blockDim.x + threadIdx.x;
	if (thread >= n_batch)
	{
		return;
	}
	unsigned char* in = indata + thread * inlen;
	unsigned char* out = outdata + thread * SHA256_HASH_SIZE;
	CUDA_SHA256_CTX ctx;
	cuda_sha256_init(&ctx);
	cuda_sha256_update(&ctx, in, inlen);
	cuda_sha256_final(&ctx, out);
}

__host__ __device__ unsigned char verify_zeroes(unsigned char* hash) {
	unsigned char num_zeroes = 0;
	unsigned char leading = 1;
	unsigned char i;

	for (i = 0; i < SHA256_HASH_SIZE; i++) {
		leading = leading && ((hash[i] | 0x0f) == 0x0f);
		num_zeroes += leading ? 1 : 0;
		leading = leading && ((hash[i] | 0xf0) == 0xf0);
		num_zeroes += leading ? 1 : 0;
	}
	return num_zeroes;
}

__global__ void kernel_mine_coin_child(CUDA_SHA256_CTX* hash_start, unsigned char* id, long long* result, long long start, unsigned char difficulty) {
	long long data_num = (blockIdx.x * blockDim.x + threadIdx.x) + start;
	unsigned char hash[SHA256_HASH_SIZE];

	CUDA_SHA256_CTX ctx;
	memcpy(&ctx, hash_start, sizeof(CUDA_SHA256_CTX));

	cuda_sha256_update(&ctx, (unsigned char*) &data_num, sizeof(data_num));
	cuda_sha256_update(&ctx, id, ID_SIZE);
	cuda_sha256_final(&ctx, hash);
	
	unsigned char num_zeroes = verify_zeroes(hash);
	if (num_zeroes < difficulty)
		return;
	*result = data_num;
}

extern "C" {
	long long cuda_mine_coin(const unsigned char* hash_start, const unsigned char* id, size_t hash_start_size, size_t id_size, unsigned char difficulty, int* latest_timestamp) {
		unsigned char* cuda_id;
		CUDA_SHA256_CTX* cuda_sha256_ctx;

		long long* cuda_result;
		long long host_result = -1;
		long long ret = -1;
		int timestamp = *latest_timestamp;

		CUDA_SHA256_CTX ctx;
		cuda_sha256_init(&ctx);
		cuda_sha256_update(&ctx, hash_start, hash_start_size);

		CHECK_ERROR(cudaHostAlloc((void**)&cuda_result, sizeof(long long), cudaHostAllocDefault));
		CHECK_ERROR(cudaMalloc((void**)&cuda_sha256_ctx, sizeof(CUDA_SHA256_CTX)));
		CHECK_ERROR(cudaMalloc((void**)&cuda_id, id_size));

		CHECK_ERROR(cudaMemcpy(cuda_sha256_ctx, &ctx, sizeof(CUDA_SHA256_CTX), cudaMemcpyHostToDevice));
		CHECK_ERROR(cudaMemcpy(cuda_id, id, id_size, cudaMemcpyHostToDevice));

		for (long long i = 0; i < LLONG_MAX - NUM_BLOCKS * NUM_THREADS; i += NUM_BLOCKS * NUM_THREADS) {
			host_result = -1;

			// Generate random start num for kernel
			long long start_num = rand();
			start_num = start_num << 31;
			start_num |= rand();
			// Prevent overflow when iterating in kernel
			start_num -= NUM_BLOCKS * NUM_THREADS;

			// Run kernel to compute hashes
			CHECK_ERROR(cudaMemcpy(cuda_result, &host_result, sizeof(long long), cudaMemcpyHostToDevice));
			kernel_mine_coin_child <<<NUM_BLOCKS, NUM_THREADS>>> (cuda_sha256_ctx, cuda_id, cuda_result, start_num, difficulty);
			CHECK_ERROR(cudaMemcpy(&host_result, cuda_result, sizeof(long long), cudaMemcpyDeviceToHost));

			// Check if valid hash was found
			if (host_result != -1) {
				ret = host_result;
				goto end;
			}

			// Check if coin is stale;
			if (*latest_timestamp > timestamp) {
				printf("Coin is stale. Ending iteration\n");
				ret = -1;
				goto end;
			}

		}

	end:
		CHECK_ERROR(cudaFree(cuda_id));
		CHECK_ERROR(cudaFreeHost(cuda_result));
		CHECK_ERROR(cudaFree(cuda_sha256_ctx));

		return ret;
	}
}
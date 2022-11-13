/*
 * sha256.cuh CUDA Implementation of SHA256 Hashing
 *
 * Date: 12 June 2019
 * Revision: 1
 *
 * Based on the public domain Reference Implementation in C, by
 * Brad Conte, original code here:
 *
 * https://github.com/B-Con/crypto-algorithms
 *
 * This file is released into the Public Domain.
 */

 // SHA256 CUDA retrieved from https://github.com/mochimodev/cuda-hashing-algos/blob/master/


/**************************** DATA TYPES ****************************/
long long cuda_mine_coin(const unsigned char* hash_start, const unsigned char* id, size_t hash_start_size, size_t id_size, unsigned char difficulty);

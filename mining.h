#pragma once


typedef struct coin_info_t {
	unsigned char coin_id[65];
	int coin_id_timestamp;
	int difficulty;
	int difficulty_timestamp;
} coin_info_t;

typedef struct response_t {
	unsigned char* data;
	size_t read_bytes;
} response_t;
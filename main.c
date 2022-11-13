// Compile with nvcc -O3 main.c sha256.cu -o mine.o
#define CURL_STATICLIB
#include "sha256.cuh"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <curl/curl.h>
#include <b64/cencode.h>
#include "mining.h"
#include <cjson/cJSON.h>

#pragma comment(lib, "Ws2_32.Lib")
#pragma comment(lib, "Crypt32.Lib")


#define SHA256_HASH_SIZE 32
#define SHA256_BLOCK_SIZE 64
#define CPEN_LEN 17
#define PREVIOUS_HASH_LEN 64
#define ID_LEN 11
#define BASE64_LEN 12
#define MAX_RESPONSE_LEN 1024

size_t write_callback(char* ptr, size_t size, size_t nmemb, response_t* response) {
    if(response->read_bytes + nmemb >= MAX_RESPONSE_LEN)
        return 0;
    response->read_bytes += nmemb;
    memcpy(response->data, ptr, nmemb);
    return nmemb;
}



// Initiailze parameters to retrieve mining info.
void set_curl_opts(CURL** curl_handlers, response_t responses[2]) {
    curl_easy_setopt(curl_handlers[0], CURLOPT_URL, "http://cpen442coin.ece.ubc.ca/last_coin");
    curl_easy_setopt(curl_handlers[0], CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handlers[0], CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl_handlers[0], CURLOPT_WRITEDATA, &responses[0]);
    curl_easy_setopt(curl_handlers[0], CURLOPT_FAILONERROR, 1);

    curl_easy_setopt(curl_handlers[1], CURLOPT_URL, "http://cpen442coin.ece.ubc.ca/difficulty");
    curl_easy_setopt(curl_handlers[1], CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handlers[1], CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl_handlers[1], CURLOPT_WRITEDATA, &responses[1]);
    curl_easy_setopt(curl_handlers[1], CURLOPT_FAILONERROR, 1);
}

int get_previous_hash_and_difficulty(CURLM* multi_curl, coin_info_t* coin_info, response_t responses[2]) {
    // Assuming multi_curl is initialized correctly with correct params.
    int still_running = 1;

    // From https://curl.se/libcurl/c/multi-app.html. Wait until all requests finished.
    while (still_running) {
        CURLMcode mc = curl_multi_perform(multi_curl, &still_running);
        if (still_running)
            mc = curl_multi_poll(multi_curl, NULL, 0, 1000, NULL);
        if (mc)
            break;
    }

    CURLMsg* msg;
    int msgs_left;

    // Check for HTTP errors
    while ((msg = curl_multi_info_read(multi_curl, &msgs_left))) {

        if (msg->msg != CURLMSG_DONE) {
            fprintf(stderr, "Something has gone horribly wrong...\n");
            return -1;
        }

        if (msg->data.result != CURLE_OK) {
            char* url = NULL;
            curl_easy_getinfo(msg->easy_handle, CURLINFO_EFFECTIVE_URL, &url);
            if (url)
                fprintf(stderr, "Failed to get data from: %s\n", url);
            fprintf(stderr, "Error: %s\n", curl_easy_strerror(msg->data.result));
            return -1;
        }
    }

    // Null terminate the response
    responses[0].data[responses[0].read_bytes] = 0;
    responses[1].data[responses[1].read_bytes] = 0;

    // Parse JSON responses.
    cJSON* last_coin_json = cJSON_Parse(responses[0].data);
    if (!last_coin_json) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) {
            fprintf(stderr, "Error parsing last coin: %s\n", error_ptr);
        }
        return -1;
    }

    cJSON* difficulty_json = cJSON_Parse(responses[1].data);
    if (!difficulty_json) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr){
            fprintf(stderr, "Error parsing difficulty: %s\n", error_ptr);
        }
        return -1;
    }

    memcpy(coin_info->coin_id, cJSON_GetObjectItemCaseSensitive(last_coin_json, "coin_id")->valuestring, 64);
    coin_info->coin_id[64] = 0;
    coin_info->coin_id_timestamp = cJSON_GetObjectItemCaseSensitive(last_coin_json, "time_stamp")->valueint;

    coin_info->difficulty = cJSON_GetObjectItemCaseSensitive(difficulty_json, "number_of_leading_zeros")->valueint;
    coin_info->difficulty_timestamp = cJSON_GetObjectItemCaseSensitive(difficulty_json, "time_stamp")->valueint;
    return 0;
}


void poll_mining_params() {
    CURL* curl_handlers[2];
    for (int i = 0; i < 2; i++) {
        curl_handlers[i] = curl_easy_init();
        if (!curl_handlers[i]) {
            printf("Couldn't initialize CURL handler. Exiting.\n");
            exit(0);
        }
    }

    response_t responses[2];
    set_curl_opts(curl_handlers, responses);

    while (1) {
        continue;
    }
}


int main() {
    coin_info_t coin_info;
    const unsigned char cpen[] = "CPEN 442 Coin2022";
    unsigned char previous_hash[SHA256_HASH_SIZE*2] = "a9c1ae3f4fc29d0be9113a42090a5ef9fdef93f5ec4777a008873972e60bb532";
    const unsigned char id[] = "free-vbucks";
    long long coin_blob;
    unsigned char base64_coin_blob[BASE64_LEN + 1];
    unsigned char* base64_ptr;
    unsigned char* hash_start = (unsigned char*)malloc(CPEN_LEN + PREVIOUS_HASH_LEN);

    srand(time(NULL));
    

    // Initialize CURL handlers and parameters. Using multi handler since we are querying two endpoints (difficulty and last coin).
    CURL* curl_handlers[2];
    for (int i = 0; i < 2; i++) {
        curl_handlers[i] = curl_easy_init();
        if (!curl_handlers[i]) {
            printf("Couldn't initialize CURL handler. Exiting.\n");
            exit(0);
        }
    }

    response_t responses[2];
    for (int i = 0; i < 2; i++) {
        responses[i].data = malloc(MAX_RESPONSE_LEN);
        responses[i].read_bytes = 0;
    }

    set_curl_opts(curl_handlers, responses);

    CURLM* multi_handle = curl_multi_init();
    curl_multi_add_handle(multi_handle, curl_handlers[0]);
    curl_multi_add_handle(multi_handle, curl_handlers[1]);

  
    


    memcpy(hash_start, cpen, CPEN_LEN);
    
    while (1) {
        get_previous_hash_and_difficulty(multi_handle, &coin_info, responses);
        
        memcpy(hash_start + CPEN_LEN, coin_info.coin_id, PREVIOUS_HASH_LEN);
        coin_blob = cuda_mine_coin(hash_start, id, CPEN_LEN + PREVIOUS_HASH_LEN, ID_LEN, coin_info.difficulty);
        if (coin_blob < 0)
            continue;

        //Base 64 encode coin blob
        base64_encodestate s;
        base64_init_encodestate(&s);
        base64_ptr = base64_coin_blob;
        base64_ptr += base64_encode_block(&coin_blob, sizeof(coin_blob), base64_ptr, &s);
        base64_ptr += base64_encode_blockend(base64_ptr, &s);
        *base64_ptr = 0;
        printf("Previous hash:%s\tFound base blob: %s\tNumber: %lld\tDifficulty: %d\n", coin_info.coin_id, base64_coin_blob, coin_blob, coin_info.difficulty);
        break;
    }

    return 0;
}
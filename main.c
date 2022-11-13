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
#include <sys/types.h>


#pragma comment(lib, "Ws2_32.Lib")
#pragma comment(lib, "Crypt32.Lib")

#define SHA256_HASH_SIZE 32
#define SHA256_BLOCK_SIZE 64
#define CPEN_LEN 17
#define PREVIOUS_HASH_LEN 64
#define ID_LEN 11
#define BASE64_LEN 12
#define MAX_RESPONSE_LEN 1024
#define LAST_COIN 0
#define DIFFICULTY 1
#define VERIFY 2

size_t write_callback(char* ptr, size_t size, size_t nmemb, response_t* response) {
    if(response->read_bytes + nmemb >= MAX_RESPONSE_LEN)
        return 0;
    response->read_bytes += nmemb;
    memcpy(response->data, ptr, nmemb);
    return nmemb;
}

void post_coin(CURL* handler, unsigned char* base64_blob, unsigned char* id, response_t* response) {
    CURLcode res;

    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "coin_blob", base64_blob);
    cJSON_AddStringToObject(json, "id_of_miner", id);
    char* json_string = cJSON_PrintUnformatted(json);
    
    // Set HTTP headers
    struct curl_slist* list = NULL;
    list = curl_slist_append(list, "Content-Type: application/json");
    curl_easy_setopt(handler, CURLOPT_HTTPHEADER, list);

    // Set POST body
    curl_easy_setopt(handler , CURLOPT_POSTFIELDS, json_string);
    res = curl_easy_perform(handler);

    response->data[response->read_bytes] = 0;

    if (res != CURLE_OK) {
        fprintf(stderr, "Failed to POST coin: %s\nMessage from server: %s\n", curl_easy_strerror(res), response->data);
    }

#ifdef DEBUG
    printf("Response from server: %s\n", response->data);
    printf("Sent to server: %s\n", json_string);
#endif // DEBUG

    curl_slist_free_all(list);
    cJSON_Delete(json);
    free(json_string);
}

void modify_url(CURL* handler, size_t path_len, const unsigned char* path) {
    unsigned char* new_path = malloc(path_len + 3);
    unsigned char hex_encoding[4];
    int idx = rand() % path_len + 1;
    snprintf(hex_encoding, 4, "%02X", path[idx]);

    strncpy(new_path, path, idx);
    strncpy(new_path + idx, hex_encoding, 3);
    strncpy(new_path + idx + 3, path + idx, path_len-idx);
    new_path[path_len + 3] = 0;

    printf("New path: %s\n", new_path);
    curl_easy_setopt(handler, CURLOPT_URL, new_path);

    free(new_path);
}

// Initiailze parameters to retrieve mining info.
void set_curl_opts(CURL** curl_handlers, response_t responses[3]) {

    curl_easy_setopt(curl_handlers[0], CURLOPT_URL, "http://cpen442coin.ece.ubc.ca/last_coin");
    curl_easy_setopt(curl_handlers[0], CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handlers[0], CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl_handlers[0], CURLOPT_WRITEDATA, &responses[LAST_COIN]);
    curl_easy_setopt(curl_handlers[0], CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl_handlers[0], CURLOPT_HTTPPROXYTUNNEL, 1L);

    curl_easy_setopt(curl_handlers[1], CURLOPT_URL, "http://cpen442coin.ece.ubc.ca/difficulty");
    curl_easy_setopt(curl_handlers[1], CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handlers[1], CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(curl_handlers[1], CURLOPT_WRITEDATA, &responses[DIFFICULTY]);
    curl_easy_setopt(curl_handlers[1], CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl_handlers[1], CURLOPT_HTTPPROXYTUNNEL, 1L);

    curl_easy_setopt(curl_handlers[2], CURLOPT_URL, "http://cpen442coin.ece.ubc.ca/verify_example_coin");
    curl_easy_setopt(curl_handlers[2], CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl_handlers[2], CURLOPT_WRITEDATA, &responses[VERIFY]);
    curl_easy_setopt(curl_handlers[2], CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl_handlers[2], CURLOPT_HTTPPROXYTUNNEL, 1L);
}

int get_previous_hash_and_difficulty(CURLM* multi_curl, coin_info_t* coin_info, response_t responses[2]) {
    // Assuming multi_curl is initialized correctly with correct params.
    int still_running = 1;
    int ret_val = 0;

    
    // From https://curl.se/libcurl/c/multi-app.html. Wait until all requests finished.
    while (still_running) {
        CURLMcode mc = curl_multi_perform(multi_curl, &still_running);
        if (still_running)
            mc = curl_multi_poll(multi_curl, NULL, 0, 1000, NULL);
        if (mc)
            break;
    }

    // Null terminate the response
    responses[LAST_COIN].data[responses[LAST_COIN].read_bytes] = 0;
    responses[DIFFICULTY].data[responses[DIFFICULTY].read_bytes] = 0;

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
            if (msg->data.result == CURLE_HTTP_RETURNED_ERROR) {
                long http_code;
                curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE, &http_code);
                fprintf(stderr, "HTTP Error Code: %ld\n", http_code);
            }
            return -1;
        }
    }

    // Parse JSON responses.
    cJSON* last_coin_json = cJSON_Parse(responses[LAST_COIN].data);
    cJSON* difficulty_json = cJSON_Parse(responses[DIFFICULTY].data);
    // Check for parsing errors.
    if (!last_coin_json || ! difficulty_json) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr) {
            fprintf(stderr, "Error parsing %s %s: %s\n", !last_coin_json ? "last coin," : "", !difficulty_json ? "difficulty" : "", error_ptr);
        }
        ret_val = -1;
        goto end;
    }


    memcpy(coin_info->coin_id, cJSON_GetObjectItemCaseSensitive(last_coin_json, "coin_id")->valuestring, 64);
    coin_info->coin_id[64] = 0;
    coin_info->coin_id_timestamp = cJSON_GetObjectItemCaseSensitive(last_coin_json, "time_stamp")->valueint;

    coin_info->difficulty = cJSON_GetObjectItemCaseSensitive(difficulty_json, "number_of_leading_zeros")->valueint;
    coin_info->difficulty_timestamp = cJSON_GetObjectItemCaseSensitive(difficulty_json, "time_stamp")->valueint;

end:
    cJSON_Delete(last_coin_json);
    cJSON_Delete(difficulty_json);
    return 0;
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
    unsigned char** proxies = malloc(sizeof(unsigned char*) * 10);

    srand(time(NULL));
    

    // Three easy handlers. First one is to last_coin. Second is to difficulty. Third is to verify.
    CURL* curl_handlers[3];
    for (int i = 0; i < 3; i++) {
        curl_handlers[i] = curl_easy_init();
        if (!curl_handlers[i]) {
            printf("Couldn't initialize CURL handler. Exiting.\n");
            exit(0);
        }
    }

    response_t responses[3];
    for (int i = 0; i < 3; i++) {
        responses[i].data = malloc(MAX_RESPONSE_LEN);
        responses[i].read_bytes = 0;
        responses[i].handler = curl_handlers[i];
    }

    struct curl_slist* list = NULL;
    //list = curl_slist_append(list, "Content-Length: 0");

    set_curl_opts(curl_handlers, responses, list);

    CURLM* multi_handle = curl_multi_init();
    curl_multi_add_handle(multi_handle, curl_handlers[0]);
    curl_multi_add_handle(multi_handle, curl_handlers[1]);

    memcpy(hash_start, cpen, CPEN_LEN);

    // Read proxy files
    int proxy_count = 0;
    FILE* fp = fopen("proxy_list.txt", "r");
    if (fp) {
        size_t line_len;
        unsigned char* line = malloc(50);
        
        while (fgets(line, 50, fp)) {
            proxies[proxy_count] = malloc(50);
            strncpy(proxies[proxy_count], line, 50);
            proxies[proxy_count][strcspn(proxies[proxy_count], "\n")] = 0;
            proxy_count++;
            proxies = realloc(proxies, (proxy_count+1)*sizeof(unsigned char*));
        }
    }

    
    while (1) {

        // Set proxy if available.
        int proxy_idx = rand() % proxy_count;
        if (proxy_count) {
            
            for (int i = 0; i < 3; i++) {
                curl_easy_setopt(curl_handlers[i], CURLOPT_PROXY, proxies[proxy_idx]);
            }
        }

        if (get_previous_hash_and_difficulty(multi_handle, &coin_info, responses)) {
            break;
            goto cleanup;
        }
        
        memcpy(hash_start + CPEN_LEN, coin_info.coin_id, PREVIOUS_HASH_LEN);
        coin_blob = cuda_mine_coin(hash_start, id, CPEN_LEN + PREVIOUS_HASH_LEN, ID_LEN, coin_info.difficulty);
        if (coin_blob < 0)
            goto cleanup;

        //Base 64 encode coin blob
        base64_encodestate s;
        base64_init_encodestate(&s);
        base64_ptr = base64_coin_blob;
        base64_ptr += base64_encode_block(&coin_blob, sizeof(coin_blob), base64_ptr, &s);
        base64_ptr += base64_encode_blockend(base64_ptr, &s);
        *base64_ptr = 0;
        printf("Previous hash:%s\tFound base blob: %s\tNumber: %lld\tDifficulty: %d\tURL Index: %d\n", coin_info.coin_id, base64_coin_blob, coin_blob, coin_info.difficulty, proxy_idx);

        // Send the coin blob
        post_coin(curl_handlers[2], base64_coin_blob, id, &responses[VERIFY]);

cleanup:
        // Rest the read_bytes of responses so it can be used again next loop.
        for (int i = 0; i < 3; i++) {
            responses[i].read_bytes = 0;
        }

        //Reset the multi handler so it can be used again
        curl_multi_remove_handle(multi_handle, curl_handlers[0]);
        curl_multi_remove_handle(multi_handle, curl_handlers[1]);
        curl_multi_add_handle(multi_handle, curl_handlers[0]);
        curl_multi_add_handle(multi_handle, curl_handlers[1]);

    }


    free(hash_start);
    free(proxies);
    curl_multi_remove_handle(multi_handle, curl_handlers[0]);
    curl_multi_remove_handle(multi_handle, curl_handlers[1]);
    curl_multi_cleanup(multi_handle);
    curl_slist_free_all(list);

    for (int i = 0; i < 3; i++) {
        curl_easy_cleanup(curl_handlers[i]);
        free(responses[i].data);
    }

    return 0;
}
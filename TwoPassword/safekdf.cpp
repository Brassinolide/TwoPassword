#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>
#include <openssl/thread.h>
#include <openssl/core_names.h>
#include "safekdf.h"

static void _memzero(uint8_t* mem, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        mem[i] = 0;
    }
}

bool safekdf(const uint8_t* in_data, size_t in_size, uint8_t* out_data, size_t out_size, const uint8_t* in_salt_1, const uint8_t* in_salt_2, const uint8_t* in_salt_3, size_t salt_size) {
    if (!in_data || !in_size || !out_data || !out_size) {
        return false;
    }

    uint8_t temp1[64] = { 0 };
    uint8_t temp2[64] = { 0 };

    if (PKCS5_PBKDF2_HMAC((const char*)in_data, in_size, in_salt_1, salt_size,
#ifdef _DEBUG
        1
#else
        600000
#endif
        , EVP_sha512(), sizeof temp1, temp1) != 1) {
        return false;
    }

    if (PKCS5_PBKDF2_HMAC((const char*)temp1, sizeof temp1, in_salt_2, salt_size,
#ifdef _DEBUG
        1
#else
        600000
#endif
        , EVP_sha3_512(), sizeof temp2, temp2) != 1) {
        return false;
    }

    _memzero(temp1, sizeof temp1);

    // 调试时不要在密钥派生上浪费太多时间

#ifdef _DEBUG
    uint32_t threads = 4, memcost = 65536, iterations = 1;
#else
    uint32_t threads = 4, memcost = 2097152, iterations = 10;
#endif
    if (OSSL_set_max_threads(NULL, threads) != 1) {
        return false;
    }

    OSSL_PARAM params[7] = { 0 }, * p = params;
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &threads);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)in_salt_3, salt_size);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void*)temp2, sizeof temp2);
    *p++ = OSSL_PARAM_construct_end();

    EVP_KDF* kdf = EVP_KDF_fetch(NULL, "ARGON2D", NULL);
    if (!kdf) {
        return false;
    }

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) {
        EVP_KDF_free(kdf);
        return false;
    }

    bool success = (EVP_KDF_derive(kctx, out_data, out_size, params) == 1);

    _memzero(temp1, sizeof temp1);
    _memzero(temp2, sizeof temp2);

    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    OSSL_set_max_threads(NULL, 0);

    return success;
}

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "aead.h"
#include "literals.h"

static EVP_CIPHER_CTX* _create_chacha20_poly1305_ctx(const uint8_t* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return nullptr;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, key, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

static EVP_CIPHER_CTX* _create_aes_gcm_ctx(const uint8_t* key, int key_size) {
    if (key_size != 128 && key_size != 192 && key_size != 256) {
        return nullptr;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return nullptr;
    }

    const EVP_CIPHER* cipher;
    switch (key_size) {
        case 128: cipher = EVP_aes_128_gcm(); break;
        case 192: cipher = EVP_aes_192_gcm(); break;
        case 256: cipher = EVP_aes_256_gcm(); break;
        default: return nullptr;
    }

    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

static bool _encrypt(EVP_CIPHER_CTX* ctx, uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, uint8_t* out_authtag_opt, const uint8_t* in_iv) {
    if (!ctx || !in_data || !data_size || !in_iv) {
        return false;
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, in_iv) != 1) {
        return false;
    }

    size_t total_outl = 0;
    int outl = 0;
    for (size_t offset = 0; offset < data_size;) {
        size_t remaining = data_size - offset;
        if (remaining >= 1_GiB) {
            if (EVP_EncryptUpdate(ctx, out_data_opt ? out_data_opt : in_data, &outl, in_data, 1_GiB) != 1) {
                return false;
            }
            offset += 1_GiB;
            total_outl += outl;
        }
        else {
            if (EVP_EncryptUpdate(ctx, out_data_opt ? out_data_opt : in_data, &outl, in_data, remaining) != 1) {
                return false;
            }
            total_outl += outl;
            break;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, (out_data_opt ? out_data_opt : in_data) + total_outl, &outl) != 1) {
        return false;
    }

    if (out_authtag_opt) {
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out_authtag_opt) != 1) {
            return false;
        }
    }
    return true;
}

static bool _decrypt(EVP_CIPHER_CTX* ctx, uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_authtag, const uint8_t* in_iv, bool validate) {
    if (!ctx || !in_data || !data_size || !in_iv) {
        return false;
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, in_iv) != 1) {
        return false;
    }

    size_t total_outl = 0;
    int outl = 0;
    for (size_t offset = 0; offset < data_size;) {
        size_t remaining = data_size - offset;
        if (remaining >= 1_GiB) {
            if (EVP_DecryptUpdate(ctx, out_data_opt ? out_data_opt : in_data, &outl, in_data, 1_GiB) != 1) {
                return false;
            }
            offset += 1_GiB;
            total_outl += outl;
        }
        else {
            if (EVP_DecryptUpdate(ctx, out_data_opt ? out_data_opt : in_data, &outl, in_data, remaining) != 1) {
                return false;
            }
            total_outl += outl;
            break;
        }
    }

    if (validate) {
        if (!in_authtag) {
            return false;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)in_authtag) != 1) {
            return false;
        }
    }

    if (EVP_DecryptFinal_ex(ctx, (out_data_opt ? out_data_opt : in_data) + total_outl, &outl) != 1) {
        return false;
    }

    return true;
}

bool aes_gcm_generate_iv_and_encrypt(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, int key_size, uint8_t* out_iv, uint8_t* out_authtag_opt) {
    if (!in_data || !data_size || !in_key || !out_iv) {
        return false;
    }

    if (RAND_bytes(out_iv, 12) != 1) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = _create_aes_gcm_ctx(in_key, key_size);
    if (!ctx) {
        return false;
    }

    bool success = _encrypt(ctx, in_data, out_data_opt, data_size, out_authtag_opt, out_iv);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool aes_gcm_decrypt_only(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, int key_size, const uint8_t* in_iv) {
    if (!in_data || !data_size || !in_key || !in_iv) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = _create_aes_gcm_ctx(in_key, key_size);
    if (!ctx) {
        return false;
    }

    bool success = _decrypt(ctx, in_data, out_data_opt, data_size, 0, in_iv, false);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool aes_gcm_decrypt_and_validate(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, int key_size, const uint8_t* in_iv, const uint8_t* in_authtag) {
    if (!in_data || !data_size || !in_key || !in_iv || !in_authtag) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = _create_aes_gcm_ctx(in_key, key_size);
    if (!ctx) {
        return false;
    }

    bool success = _decrypt(ctx, in_data, out_data_opt, data_size, in_authtag, in_iv, true);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool chacha20_poly1305_generate_iv_and_encrypt(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, uint8_t* out_iv, uint8_t* out_authtag_opt) {
    if (!in_data || !data_size || !in_key || !out_iv) {
        return false;
    }

    if (RAND_bytes(out_iv, 12) != 1) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = _create_chacha20_poly1305_ctx(in_key);
    if (!ctx) {
        return false;
    }

    bool success = _encrypt(ctx, in_data, out_data_opt, data_size, out_authtag_opt, out_iv);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool chacha20_poly1305_decrypt_only(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, const uint8_t* in_iv) {
    if (!in_data || !data_size || !in_key || !in_iv) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = _create_chacha20_poly1305_ctx(in_key);
    if (!ctx) {
        return false;
    }

    bool success = _decrypt(ctx, in_data, out_data_opt, data_size, 0, in_iv, false);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool chacha20_poly1305_decrypt_and_validate(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, const uint8_t* in_iv, const uint8_t* in_authtag) {
    if (!in_data || !data_size || !in_key || !in_iv || !in_authtag) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = _create_chacha20_poly1305_ctx(in_key);
    if (!ctx) {
        return false;
    }

    bool success = _decrypt(ctx, in_data, out_data_opt, data_size, in_authtag, in_iv, true);
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

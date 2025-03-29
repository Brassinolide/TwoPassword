#pragma once
#include <vector>
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <windows.h>

template <typename T>
void secure_erase_vector(std::vector<T>& vec) {
    if (!vec.empty()) {
        memset(vec.data(), 0, vec.size() * sizeof(T));
        vec.clear();
        vec.shrink_to_fit();
    }
}

template <typename T, size_t N>
void secure_erase_array(std::array<T, N>& arr) {
    if (!arr.empty()) {
        memset(arr.data(), 0, N * sizeof(T));
    }
}

void secure_erase_string(std::string& str);
void secure_erase_wstring(std::wstring& wstr);

struct ZeroDeleter {
    void operator()(uint8_t* ptr) const {
        if (ptr) {
            std::memset(ptr, 0, total_size_);
            delete[] ptr;
        }
    }
    ZeroDeleter(size_t size = 0) : total_size_(size) {}
    size_t total_size_ = 0;
};
using byteptr = std::unique_ptr<uint8_t[], ZeroDeleter>;
byteptr make_byteptr(size_t total_size);

struct deleter_EVP_CIPHER_CTX {
    void operator()(EVP_CIPHER_CTX* ctx) const {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};
using auto_EVP_CIPHER_CTX = std::unique_ptr<EVP_CIPHER_CTX, deleter_EVP_CIPHER_CTX>;

struct deleter_HANDLE {
    void operator()(void* h) const {
        if (h != INVALID_HANDLE_VALUE && h) {
            CloseHandle(h);
        }
    }
};
using auto_HANDLE = std::unique_ptr<std::remove_pointer_t<HANDLE>, deleter_HANDLE>;


void disable_memfree();
void safe_exit();

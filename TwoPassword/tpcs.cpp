#include "tpcs.h"

/*

Helper Function

*/

std::string winapi_get_last_error_utf8() {
    wchar_t buffer[1024] = { 0 };
    if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0, GetLastError(), 0, buffer, sizeof(buffer) / sizeof(wchar_t), 0)) {
        return "Unknown error";
    }

    std::wstring u16 = buffer;
    std::string u8;
    utf8::utf16to8(u16.begin(), u16.end(), back_inserter(u8));

    return u8.c_str();
}

std::string openssl_get_last_error_utf8() {
    char openssl_err_msg[1024] = { 0 };
    ERR_error_string_n(ERR_get_error(), openssl_err_msg, sizeof(openssl_err_msg));
    return openssl_err_msg;
}

static uint32_t endian_switch(uint32_t x) {
    return ((x >> 24) & 0x000000FF) |
        ((x >> 8) & 0x0000FF00) |
        ((x << 8) & 0x00FF0000) |
        ((x << 24) & 0xFF000000);
}

uint64_t get_utc_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    return static_cast<uint64_t>(seconds);
}

uint64_t asn1_get_uint64(const ASN1_INTEGER* a) {
    uint64_t u = 0;
    ASN1_INTEGER_get_uint64(&u, a);
    return u;
}

std::string utc_timestamp_to_iso8601(uint64_t t) {
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::time_point(std::chrono::seconds(t))));
}

/*

TPCS1

*/

size_t tpcs1_encrypt(byteptr& out, const uint8_t* in_data, size_t data_size, const uint8_t* in_key/*[64]*/) {
    if (out || !in_data || !data_size || !in_key) {
        return 0;
    }
    size_t total_size = sizeof_iv + sizeof_authtag + sizeof_tpcs1_header + data_size;
    out = make_byteptr(total_size);
    uint8_t* aes_iv_ptr = out.get();
    uint8_t* gcm_authtag_ptr = aes_iv_ptr + sizeof_iv;
    tpcs1_header* tpcs1_header_ptr = (tpcs1_header*)(gcm_authtag_ptr + sizeof_authtag);
    uint8_t* data_ptr = (uint8_t*)tpcs1_header_ptr + sizeof_tpcs1_header;
    memcpy_s(tpcs1_header_ptr->magic, 3, tpcs_magic, 3);
    tpcs1_header_ptr->version = version_tpcs1;
    tpcs1_header_ptr->data_size = data_size;
    memcpy_s(data_ptr, data_size, in_data, data_size);
    if (!chacha20_poly1305_generate_iv_and_encrypt(data_ptr, nullptr, data_size, in_key, tpcs1_header_ptr->chacha20_iv, tpcs1_header_ptr->poly1305_authtag)
        || !aes_gcm_generate_iv_and_encrypt((uint8_t*)tpcs1_header_ptr, nullptr, sizeof_tpcs1_header + data_size, in_key + 32, 256, aes_iv_ptr, gcm_authtag_ptr)) {
        out = nullptr;
        return 0;
    }
    return total_size;
}

size_t tpcs1_decrypt(byteptr& out, const uint8_t* in_data, size_t data_size, const uint8_t* in_key/*[64]*/) {
    if (out || !in_data || data_size < least_tpcs1_size || !in_key) {
        return 0;
    }
    const uint8_t* aes_iv_ptr = in_data;
    const uint8_t* gcm_authtag_ptr = aes_iv_ptr + sizeof_iv;
    const tpcs1_header* tpcs1_header_ptr = (const tpcs1_header*)(gcm_authtag_ptr + sizeof_authtag);
    tpcs1_header decrypted_tpcs1_header = { 0 };
    memcpy_s(&decrypted_tpcs1_header, sizeof_tpcs1_header, tpcs1_header_ptr, sizeof_tpcs1_header);
    aes_gcm_decrypt_only((uint8_t*)&decrypted_tpcs1_header, 0, sizeof_tpcs1_header, in_key + 32, 256, aes_iv_ptr);
    if (memcmp(decrypted_tpcs1_header.magic, tpcs_magic, 3) != 0) {
        return 0;
    }
    if (decrypted_tpcs1_header.version != version_tpcs1) {
        return 0;
    }
    if (sizeof_iv + sizeof_authtag + sizeof_tpcs1_header + decrypted_tpcs1_header.data_size != data_size) {
        return 0;
    }
    out = make_byteptr(sizeof_tpcs1_header + decrypted_tpcs1_header.data_size);
    uint8_t* data_ptr = out.get() + sizeof_tpcs1_header;
    if (!aes_gcm_decrypt_and_validate((uint8_t*)tpcs1_header_ptr, out.get(), sizeof_tpcs1_header + decrypted_tpcs1_header.data_size, in_key + 32, 256, aes_iv_ptr, gcm_authtag_ptr)
        || !chacha20_poly1305_decrypt_and_validate(data_ptr, nullptr, decrypted_tpcs1_header.data_size, in_key, decrypted_tpcs1_header.chacha20_iv, decrypted_tpcs1_header.poly1305_authtag)) {
        out = nullptr;
        return 0;
    }
    memmove_s(out.get(), decrypted_tpcs1_header.data_size, out.get() + sizeof_tpcs1_header, decrypted_tpcs1_header.data_size);
    return decrypted_tpcs1_header.data_size;
}

/*

TPCS2

*/

bool tpcs2_generate_salt_and_do_safekdf(const uint8_t* in_kdf_buffer, size_t kdf_buffer_size, uint8_t* out_key/*[64]*/, uint8_t* out_salt/*[48]*/) {
    if (!in_kdf_buffer || !kdf_buffer_size || !out_key || !out_salt) {
        return false;
    }

    if (RAND_bytes(out_salt, 48) != 1) {
        return false;
    }

    return safekdf(in_kdf_buffer, kdf_buffer_size, out_key, 64, out_salt, out_salt + 16, out_salt + 32, 16);
}

bool tpcs2_do_safekdf(const uint8_t* in_kdf_buffer, size_t kdf_buffer_size, uint8_t* out_key/*[64]*/, const uint8_t* in_salt/*[48]*/) {
    if (!in_kdf_buffer || !kdf_buffer_size || !out_key || !in_salt) {
        return false;
    }

    return safekdf(in_kdf_buffer, kdf_buffer_size, out_key, 64, in_salt, in_salt + 16, in_salt + 32, 16);
}

size_t tpcs2_pack(byteptr& out, const uint8_t* in_data, size_t data_size, const uint8_t* in_key/*[64]*/, const uint8_t* in_salt/*[48]*/) {
    if (out || !in_data || !data_size || !in_key || !in_salt) {
        return 0;
    }

    byteptr tpcs1 = nullptr;
    size_t tpcs1_size = tpcs1_encrypt(tpcs1, in_data, data_size, in_key);
    if (!tpcs1_size) {
        return 0;
    }
    size_t tpcs2_size = sizeof_tpcs2_header + tpcs1_size;
    out = make_byteptr(tpcs2_size);
    memcpy_s(out.get(), 48, in_salt, 48);
    memcpy_s(out.get() + 48, tpcs1_size, tpcs1.get(), tpcs1_size);
    return tpcs2_size;
}

/*

TPCS3

*/

size_t tpcs3_encode(byteptr& out, const std::vector<std::string>& passfile_list_utf8, const std::string& password_utf8) {
    if (out) {
        return 0;
    }

    const size_t password_size = password_utf8.size() * sizeof_tpcs3_encoded_char;
    const size_t passfile_size = passfile_list_utf8.size() * 8_KiB;
    const size_t tpcs3_size = password_size + passfile_size;
    out = make_byteptr(tpcs3_size);
    uint8_t* password_ptr = out.get();
    uint8_t* passfile_ptr = out.get() + password_size;

    // 这里的代码仅兼容小端平台

    std::vector<uint32_t> password_utf32;
    utf8::utf8to32(password_utf8.begin(), password_utf8.end(), back_inserter(password_utf32));
    for (size_t id = 0; id < password_utf32.size(); ++id) {
        tpcs3_encoded_char* tpcs3 = (tpcs3_encoded_char*)(password_ptr + id * sizeof_tpcs3_encoded_char);
        tpcs3->id = id;
        tpcs3->utf32 = id % 2 ? endian_switch(password_utf32[id]) : password_utf32[id];
    }
    secure_erase_vector(password_utf32);

    for (const std::string& passfile : passfile_list_utf8) {
        std::u16string u16;
        utf8::utf8to16(passfile.begin(), passfile.end(), std::back_inserter(u16));

        // 设置 FILE_FLAG_NO_BUFFERING 避免在操作系统内存中缓存
        HANDLE hFile = CreateFileW((LPCWSTR)u16.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, 0);
        if (hFile == INVALID_HANDLE_VALUE) {
            out = nullptr;
            return false;
        }

        DWORD dwRead = 0;
        if (!ReadFile(hFile, passfile_ptr, 8_KiB, &dwRead, 0)) {
            CloseHandle(hFile);
            out = nullptr;
            return false;
        }
        passfile_ptr += dwRead;

        CloseHandle(hFile);
    }

    return tpcs3_size;
}

/*

TPCS4

*/

ASN1_SEQUENCE(PasswordRecord) = {
    ASN1_SIMPLE(PasswordRecord, website, ASN1_UTF8STRING),
    ASN1_SIMPLE(PasswordRecord, username, ASN1_UTF8STRING),
    ASN1_SIMPLE(PasswordRecord, password, ASN1_UTF8STRING),
    ASN1_OPT(PasswordRecord, description, ASN1_UTF8STRING),
    ASN1_OPT(PasswordRecord, common_name, ASN1_UTF8STRING),
} ASN1_SEQUENCE_END(PasswordRecord)
IMPLEMENT_ASN1_FUNCTIONS(PasswordRecord)

ASN1_SEQUENCE(PasswordLibrary) = {
    ASN1_SIMPLE(PasswordLibrary, create_time, ASN1_INTEGER),
    ASN1_SIMPLE(PasswordLibrary, update_time, ASN1_INTEGER),
    ASN1_SEQUENCE_OF(PasswordLibrary, records, PasswordRecord),
} ASN1_SEQUENCE_END(PasswordLibrary)
IMPLEMENT_ASN1_FUNCTIONS(PasswordLibrary)

PasswordLibrary* tpcs4_create_library() {
    PasswordLibrary* lib = PasswordLibrary_new();
    if (!lib) {
        return nullptr;
    }

    uint64_t time = get_utc_timestamp();
    ASN1_INTEGER_set_uint64(lib->create_time, time);
    ASN1_INTEGER_set_uint64(lib->update_time, time);
    lib->records = sk_PasswordRecord_new_null();

    return lib;
}

bool tpcs4_insert_record(PasswordLibrary* lib, PasswordRecord* record) {
    if (!lib || !record) {
        return false;
    }

    sk_PasswordRecord_push(lib->records, record);

    return true;
}

struct string_PasswordRecord{
    std::string website;
    std::string username;
    std::string password;
    std::string description;
    std::string common_name;
};

struct string_PasswordLibrary {
    std::string create_time;
    std::string update_time;
    std::vector<string_PasswordRecord> records;
};

string_PasswordLibrary tpcs4_asn1_library_to_string(const PasswordLibrary* lib) {
    string_PasswordLibrary slib;
    slib.create_time = utc_timestamp_to_iso8601(asn1_get_uint64(lib->create_time));
    slib.update_time = utc_timestamp_to_iso8601(asn1_get_uint64(lib->update_time));

    for (size_t i = 0; i < sk_PasswordRecord_num(lib->records); ++i) {
        string_PasswordRecord srec;

        PasswordRecord* record = sk_PasswordRecord_value(lib->records, i);
        if (!record) {
            continue;
        }

        if (record->website) srec.website = (const char*)record->website->data;
        if (record->username) srec.username = (const char*)record->username->data;
        if (record->password) srec.password = (const char*)record->password->data;
        if (record->description) srec.description = (const char*)record->description->data;
        if (record->common_name) srec.common_name = (const char*)record->common_name->data;

        slib.records.push_back(srec);
    }

    return slib;
}

std::string tpcs4_get_create_time_string(const PasswordLibrary* lib) {
    return utc_timestamp_to_iso8601(asn1_get_uint64(lib->create_time));
}

std::string tpcs4_get_update_time_string(const PasswordLibrary* lib) {
    return utc_timestamp_to_iso8601(asn1_get_uint64(lib->update_time));
}

bool tpcs4_update_time(PasswordLibrary* lib) {
    return (ASN1_INTEGER_set_uint64(lib->update_time, get_utc_timestamp()) == 1);
}

// FIXME：OpenSSL的int溢出

int tpcs4_get_record_size(const PasswordLibrary* lib) {
    if (!lib) {
        return 0;
    }
    return sk_PasswordRecord_num(lib->records);
}

void tpcs4_delete_record(PasswordLibrary* lib, int idx) {
    if (!lib) {
        return;
    }
    sk_PasswordRecord_delete(lib->records, idx);
}

std::string tpcs4_get_common_name_string(const PasswordLibrary* lib, int idx) {
    if (!lib) {
        return "";
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->common_name || !record->common_name->data) {
        return "";
    }
    return (const char*)record->common_name->data;
}

bool tpcs4_update_common_name_string(const PasswordLibrary* lib, const std::string& common_name, int idx) {
    if (!lib) {
        return "";
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->common_name || !record->common_name->data) {
        return "";
    }
    return (ASN1_STRING_set(record->common_name, common_name.c_str(), common_name.length()) == 1);
}

std::string tpcs4_get_description_string(const PasswordLibrary* lib, int idx) {
    if (!lib) {
        return "";
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->description || !record->description->data) {
        return "";
    }
    return (const char*)record->description->data;
}

bool tpcs4_update_description_string(const PasswordLibrary* lib, const std::string& description, int idx) {
    if (!lib) {
        return false;
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->description || !record->description->data) {
        return "";
    }
    return (ASN1_STRING_set(record->description, description.c_str(), description.length()) == 1);
}

std::string tpcs4_get_website_string(const PasswordLibrary* lib, int idx) {
    if (!lib) {
        return "";
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->website || !record->website->data) {
        return "";
    }
    return (const char*)record->website->data;
}

bool tpcs4_update_website_string(const PasswordLibrary* lib, const std::string& website, int idx) {
    if (!lib) {
        return false;
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->website || !record->website->data) {
        return "";
    }
    return (ASN1_STRING_set(record->website, website.c_str(), website.length()) == 1);
}

std::string tpcs4_get_username_string(const PasswordLibrary* lib, int idx) {
    if (!lib) {
        return "";
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->username || !record->username->data) {
        return "";
    }
    return (const char*)record->username->data;
}

bool tpcs4_update_usernam_string(const PasswordLibrary* lib, const std::string& username, int idx) {
    if (!lib) {
        return false;
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->username || !record->username->data) {
        return "";
    }
    return (ASN1_STRING_set(record->username, username.c_str(), username.length()) == 1);
}

std::string tpcs4_get_password_string(const PasswordLibrary* lib, int idx) {
    if (!lib) {
        return "";
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->password || !record->password->data) {
        return "";
    }
    return (const char*)record->password->data;
}

bool tpcs4_update_password_string(const PasswordLibrary* lib, const std::string& password, int idx) {
    if (!lib) {
        return false;
    }
    PasswordRecord* record = sk_PasswordRecord_value(lib->records, idx);
    if (!record || !record->password || !record->password->data) {
        return "";
    }
    return (ASN1_STRING_set(record->password, password.c_str(), password.length()) == 1);
}

PasswordRecord* tpcs4_create_record(const std::string& website,const std::string& username,const std::string& password,const std::string& description,const std::string& common_name) {
    PasswordRecord* record = PasswordRecord_new();
    if (!record) {
        return nullptr;
    }

    ASN1_STRING_set(record->website, website.c_str(), website.length());
    ASN1_STRING_set(record->username, username.c_str(), username.length());
    ASN1_STRING_set(record->password, password.c_str(), password.length());

    if (!description.empty()) {
        record->description = ASN1_UTF8STRING_new();
        ASN1_STRING_set(record->description, description.c_str(), description.length());
    }

    if (!common_name.empty()) {
        record->common_name = ASN1_UTF8STRING_new();
        ASN1_STRING_set(record->common_name, common_name.c_str(), common_name.length());
    }

    return record;
}

bool tpcs4_save_library(const wchar_t* path_utf16, PasswordLibrary* lib, const uint8_t* in_key/*[64]*/, const uint8_t* in_salt/*[48]*/) {
    if (!path_utf16 || !lib || !in_key || !in_salt) {
        return false;
    }

    tpcs4_update_time(lib);

    uint8_t* der = 0;
    int der_size = i2d_PasswordLibrary(lib, &der);
    if (der_size <= 0) {
        return false;
    }

    byteptr tpcs2 = nullptr;
    size_t tpcs2_size = tpcs2_pack(tpcs2, der, der_size, in_key, in_salt);
    if (!tpcs2_size) {
        return false;
    }

    auto_HANDLE hFile(CreateFileW(path_utf16, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0));
    if (hFile.get() == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD dwWrite = 0;

    // FIXME：大文件长度溢出
    if (!WriteFile(hFile.get(), tpcs2.get(), tpcs2_size, &dwWrite, 0) || dwWrite != tpcs2_size) {
        return false;
    }

    return true;
}

bool tocs4_save_library_kdf(const wchar_t* path_utf16, PasswordLibrary* lib, uint8_t* out_key_opt/*[64]*/, const std::vector<std::string>& passfile_list_utf8, const std::string& password_utf8) {
    if (!path_utf16) {
        return false;
    }

    byteptr tpcs3 = nullptr;
    size_t tpcs3_size = tpcs3_encode(tpcs3, passfile_list_utf8, password_utf8);
    if (!tpcs3_size) {
        return false;
    }

    uint8_t key[64];
    uint8_t salt[48];
    if (!tpcs2_generate_salt_and_do_safekdf(tpcs3.get(), tpcs3_size, key, salt)) {
        return false;
    }

    bool success = tpcs4_save_library(path_utf16, lib, key, salt);
    memset(key, 0, 64);
    memset(salt, 0, 48);
    return success;
}

PasswordLibrary* tpcs4_read_library_kdf(const wchar_t* path_utf16, uint8_t* out_key_opt/*[64]*/, const std::vector<std::string>& passfile_list_utf8, const std::string& password_utf8) {
    if (!path_utf16) {
        return nullptr;
    }

    byteptr tpcs3 = nullptr;
    size_t tpcs3_size = tpcs3_encode(tpcs3, passfile_list_utf8, password_utf8);
    if (!tpcs3_size) {
        return nullptr;
    }

    auto_HANDLE hFile(CreateFileW(path_utf16, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0));
    if (hFile.get() == INVALID_HANDLE_VALUE) {
        return nullptr;
    }

    DWORD fileSize = GetFileSize(hFile.get(), 0);
    if (fileSize < least_tpcs2_size) {
        return nullptr;
    }

    std::unique_ptr<uint8_t[]> fileData = std::make_unique_for_overwrite<uint8_t[]>(fileSize);

    DWORD dwRead = 0;
    if (!ReadFile(hFile.get(), fileData.get(), fileSize, &dwRead, 0) || dwRead != fileSize) {
        return nullptr;
    }

    uint8_t key[64];
    if (!tpcs2_do_safekdf(tpcs3.get(), tpcs3_size, key, fileData.get())) {
        return nullptr;
    }

    byteptr der = nullptr;
    size_t der_size = tpcs1_decrypt(der, fileData.get() + 48, fileSize - 48, key);
    if (out_key_opt) {
        memcpy_s(out_key_opt, 64, key, 64);
    }
    memset(key, 0, 64);
    if (!der_size) {
        return nullptr;
    }

    uint8_t* ptr = der.get();
    // FIXME：这里也有溢出问题，这OpenSSL的问题让我怎么修啊（汗
    return d2i_PasswordLibrary(0, (const unsigned char**)&ptr, (long)der_size);
}

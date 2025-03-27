#pragma once
#include <vector>
#include <chrono>
#include <string>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include "literals.h"
#include "aead.h"
#include "safekdf.h"
#include "memsafe.h"
#include "utfcpp/utf8.h"

#pragma pack(push,4)

constexpr uint8_t tpcs_magic[3] = { 't', 'p', 'c' };

constexpr uint8_t version_tpcs1 = 1;
constexpr size_t sizeof_tpcs1_header = 40;
constexpr size_t sizeof_iv = 12;
constexpr size_t sizeof_authtag = 16;
constexpr size_t least_tpcs1_size = sizeof_iv + sizeof_authtag + sizeof_tpcs1_header + 1;
struct tpcs1_header {
    uint8_t magic[3];
    uint8_t version;
    // chacha20��iv
    uint8_t chacha20_iv[12];
    // poly1305����֤��ǩ
    uint8_t poly1305_authtag[16];
    // ���ݳ���
    uint64_t data_size;
    // chacha20���ܺ������
    // uint8_t chacha20_encrypted_data[data_size];
};

constexpr size_t sizeof_tpcs2_header = 48;
constexpr size_t least_tpcs2_size = sizeof_tpcs2_header + least_tpcs1_size;
struct tpcs2_header {
    uint8_t salt[48];
    // ���ܺ��TPCS1����
    // ...
};

constexpr size_t sizeof_tpcs3_encoded_char = 8;
struct tpcs3_encoded_char {
    // ��0��ʼ������ID�����������ν
    uint32_t id;
    // �ַ���utf32���룬��С�˿�ʼ�����С�˽����ֻ�
    uint32_t utf32;
};

#pragma pack(pop)

template<typename T, size_t ExpectedSize>
static constexpr bool check_sizeof() {
    return sizeof(T) == ExpectedSize;
}

static_assert(
    check_sizeof<tpcs1_header, sizeof_tpcs1_header>() &&
    check_sizeof<tpcs2_header, sizeof_tpcs2_header>() &&
    check_sizeof<tpcs3_encoded_char, sizeof_tpcs3_encoded_char>()
    , "�����ڼ�飺�ṹ���С��Ԥ�ڲ�ƥ��");


size_t tpcs1_encrypt(byteptr& out, const uint8_t* in_data, size_t data_size, const uint8_t* in_key/*[64]*/);
size_t tpcs1_decrypt(byteptr& out, const uint8_t* in_data, size_t data_size, const uint8_t* in_key/*[64]*/);

bool tpcs2_generate_salt_and_do_safekdf(const uint8_t* in_kdf_buffer, size_t kdf_buffer_size, uint8_t* out_key/*[64]*/, uint8_t* out_salt/*[48]*/);
bool tpcs2_do_safekdf(const uint8_t* in_kdf_buffer, size_t kdf_buffer_size, uint8_t* out_key/*[64]*/, const uint8_t* in_salt/*[48]*/);
size_t tpcs2_pack(byteptr& out, const uint8_t* in_data, size_t data_size, const uint8_t* in_key/*[64]*/, const uint8_t* in_salt/*[48]*/);

size_t tpcs3_encode(byteptr& out, const std::vector<std::string>& passfile_list_utf8, const std::string& password_utf8);

uint64_t get_utc_timestamp();
std::string winapi_get_last_error_utf8();
std::string openssl_get_last_error_utf8();



/*
PasswordRecord ::= SEQUENCE {
    website UTF8String,
    username UTF8String,
    password UTF8String,
    description UTF8String OPTIONAL,
    common_name UTF8String OPTIONAL
}

PasswordLibrary ::= SEQUENCE {
    create_time INTEGER,
    update_time INTEGER,
    records SEQUENCE OF PasswordRecord
}
*/

struct PasswordRecord {
    ASN1_UTF8STRING* website;
    ASN1_UTF8STRING* username;
    ASN1_UTF8STRING* password;
    ASN1_UTF8STRING* description;
    ASN1_UTF8STRING* common_name;
};
DECLARE_ASN1_FUNCTIONS(PasswordRecord)
DEFINE_STACK_OF(PasswordRecord)

struct PasswordLibrary {
    ASN1_INTEGER* create_time;
    ASN1_INTEGER* update_time;
    stack_st_PasswordRecord* records;
};
DECLARE_ASN1_FUNCTIONS(PasswordLibrary)

class RecordsTraverser
{
public:
    RecordsTraverser(const stack_st_PasswordRecord* record) { set_record(record); }
    ~RecordsTraverser() {}

    void set_record(const stack_st_PasswordRecord* record) {
        _record = record;
        _pos = -1;
        _totalsize = sk_PasswordRecord_num(_record);
    }

    int get_size() const {
        return _totalsize;
    }

    bool next() {
        if (!_record) {
            return false;
        }

        if (_pos + 1 >= _totalsize) {
            return false;
        }

        _pos++;
        return true;
    }

    bool check_pos() const {
        if (!_record) {
            return false;
        }

        if (_pos < 0 || _pos >= _totalsize) {
            return false;
        }
    }

    std::string get_website() const {
        if (!check_pos()) {
            return "";
        }

        PasswordRecord* record = sk_PasswordRecord_value(_record, _pos);
        if (!record || !record->website) {
            return "";
        }

        return (const char*)record->website->data;
    }

    std::string get_username() const {
        if (!check_pos()) {
            return "";
        }

        PasswordRecord* record = sk_PasswordRecord_value(_record, _pos);
        if (!record || !record->username) {
            return "";
        }

        return (const char*)record->username->data;
    }

    std::string get_password() const {
        if (!check_pos()) {
            return "";
        }

        PasswordRecord* record = sk_PasswordRecord_value(_record, _pos);
        if (!record || !record->password) {
            return "";
        }

        return (const char*)record->password->data;
    }

    std::string get_description() const {
        if (!check_pos()) {
            return "";
        }

        PasswordRecord* record = sk_PasswordRecord_value(_record, _pos);
        if (!record || !record->description) {
            return "";
        }

        return (const char*)record->description->data;
    }

    std::string get_common_name() const {
        if (!check_pos()) {
            return "";
        }

        PasswordRecord* record = sk_PasswordRecord_value(_record, _pos);
        if (!record || !record->common_name) {
            return "";
        }

        return (const char*)record->common_name->data;
    }

private:
    const stack_st_PasswordRecord* _record;
    // FIXME��ͬ�����������
    int _pos, _totalsize;
};

PasswordLibrary* tpcs4_create_library();
bool tpcs4_insert_record(PasswordLibrary* lib, PasswordRecord* record);
PasswordRecord* tpcs4_create_record(const std::string& website, const std::string& username, const std::string& password, const std::string& description = "", const std::string& common_name = "");

bool tpcs4_save_library(const wchar_t* path_utf16, PasswordLibrary* lib, const uint8_t* in_key/*[64]*/, const uint8_t* in_salt/*[48]*/);
bool tocs4_save_library_kdf(const wchar_t* path_utf16, PasswordLibrary* lib, uint8_t* out_key_opt/*[64]*/, const std::vector<std::string>& passfile_list_utf8, const std::string& password_utf8);
PasswordLibrary* tpcs4_read_library_kdf(const wchar_t* path_utf16, uint8_t* out_key_opt/*[64]*/, const std::vector<std::string>& passfile_list_utf8, const std::string& password_utf8);

uint64_t asn1_get_uint64(const ASN1_INTEGER* a);
std::string utc_timestamp_to_iso8601(uint64_t t);

int tpcs4_get_record_size(const PasswordLibrary* lib);
void tpcs4_delete_record(PasswordLibrary* lib, int idx);
std::string tpcs4_get_create_time_string(const PasswordLibrary* lib);
std::string tpcs4_get_update_time_string(const PasswordLibrary* lib);
bool tpcs4_update_time(PasswordLibrary* lib);
std::string tpcs4_get_common_name_string(const PasswordLibrary* lib, int idx);
bool tpcs4_update_common_name_string(const PasswordLibrary* lib, const std::string& common_name, int idx);
std::string tpcs4_get_description_string(const PasswordLibrary* lib, int idx);
bool tpcs4_update_description_string(const PasswordLibrary* lib, const std::string& description, int idx);
std::string tpcs4_get_website_string(const PasswordLibrary* lib, int idx);
bool tpcs4_update_website_string(const PasswordLibrary* lib, const std::string& website, int idx);
std::string tpcs4_get_username_string(const PasswordLibrary* lib, int idx);
bool tpcs4_update_usernam_string(const PasswordLibrary* lib, const std::string& username, int idx);
std::string tpcs4_get_password_string(const PasswordLibrary* lib, int idx);
bool tpcs4_update_password_string(const PasswordLibrary* lib, const std::string& password, int idx);


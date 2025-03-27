#pragma once

bool aes_gcm_generate_iv_and_encrypt(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, int key_size, uint8_t* out_iv, uint8_t* out_authtag_opt);
bool aes_gcm_decrypt_only(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, int key_size, const uint8_t* in_iv);
bool aes_gcm_decrypt_and_validate(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, int key_size, const uint8_t* in_iv, const uint8_t* in_authtag);
bool chacha20_poly1305_generate_iv_and_encrypt(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, uint8_t* out_iv, uint8_t* out_authtag_opt);
bool chacha20_poly1305_decrypt_only(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, const uint8_t* in_iv);
bool chacha20_poly1305_decrypt_and_validate(uint8_t* in_data, uint8_t* out_data_opt, size_t data_size, const uint8_t* in_key, const uint8_t* in_iv, const uint8_t* in_authtag);

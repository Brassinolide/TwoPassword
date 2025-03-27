#pragma once

bool safekdf(const uint8_t* in_data, size_t in_size, uint8_t* out_data, size_t out_size, const uint8_t* in_salt_1, const uint8_t* in_salt_2, const uint8_t* in_salt_3, size_t salt_size);

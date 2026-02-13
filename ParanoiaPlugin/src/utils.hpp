#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ParanoiaUtils{

    std::string encode_base64(const std::vector<uint8_t> &data);

    std::vector<uint8_t> decode_base64(const std::string &str);

    std::string sha256_hex(const std::string &input);

    std::string make_dialogue_id(const std::string &a, const std::string &b);

    bool verify_signature(const std::vector<uint8_t> &pubkey, const std::string &message,
                          const std::vector<uint8_t> &signature);
}
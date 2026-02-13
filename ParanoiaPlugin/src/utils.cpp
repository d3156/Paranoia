#include "utils.hpp"
#include <boost/beast/core/detail/base64.hpp>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

using namespace boost::beast::detail;

std::string ParanoiaUtils::encode_base64(const std::vector<uint8_t> &data)
{
    std::string encoded;
    encoded.resize(base64::encoded_size(data.size()));
    std::size_t written = base64::encode(encoded.data(), data.data(), data.size());
    encoded.resize(written);
    return encoded;
}

std::vector<uint8_t> ParanoiaUtils::decode_base64(const std::string &str)
{
    std::vector<uint8_t> decoded(base64::decoded_size(str.size()));
    auto result = base64::decode(reinterpret_cast<char *>(decoded.data()), str.data(), str.size());
    decoded.resize(result.first);
    return decoded;
}

std::string ParanoiaUtils::sha256_hex(const std::string &input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), hash);
    std::ostringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string ParanoiaUtils::make_dialogue_id(const std::string &a, const std::string &b)
{
    return (a < b) ? sha256_hex(a + ":" + b) : sha256_hex(b + ":" + a);
}

bool ParanoiaUtils::verify_signature(const std::vector<uint8_t> &pubkey, const std::string &message,
                                     const std::vector<uint8_t> &signature)
{
    EVP_PKEY *evp_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());
    if (!evp_pub) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(evp_pub);
        return false;
    }
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, evp_pub) == 1)
        ok = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                              reinterpret_cast<const unsigned char *>(message.data()), message.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(evp_pub);
    return ok;
}

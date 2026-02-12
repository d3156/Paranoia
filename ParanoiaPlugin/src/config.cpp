#include "config.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/beast/core/detail/base64.hpp>
#include <filesystem>
#include <Logger/Log.hpp>

using boost::property_tree::ptree;
using namespace boost::beast::detail;
std::string Config::encode_base64(const std::vector<uint8_t> &data)
{
    std::string encoded;
    encoded.resize(base64::encoded_size(data.size()));
    std::size_t written = base64::encode(encoded.data(), data.data(), data.size());
    encoded.resize(written);
    return encoded;
}

std::vector<uint8_t> Config::decode_base64(const std::string &str)
{
    std::vector<uint8_t> decoded(base64::decoded_size(str.size()));
    auto result = base64::decode(reinterpret_cast<char *>(decoded.data()), str.data(), str.size());
    decoded.resize(result.first);
    return decoded;
}

void Config::save(const std::string &filename)
{
    ptree pt;
    pt.put("port", port);
    pt.put("store_path", store_path);
    pt.put("admin_key", encode_base64(admin_pubkey));
    ptree users_node;
    for (const auto &[name, key] : users) {
        ptree user_node;
        user_node.put("username", name);
        user_node.put("pubkey", encode_base64(key));
        users_node.push_back(std::make_pair("", user_node));
    }
    pt.add_child("users", users_node);
    write_json(filename, pt);
}

void Config::load(const std::string &filename)
{
    if (!std::filesystem::exists(filename)) {
        save(filename);
        return;
    }
    ptree pt;
    read_json(filename, pt);
    port         = pt.get("port", 1455);
    store_path   = pt.get("store_path", "store");
    admin_pubkey = decode_base64(pt.get<std::string>("admin_key", ""));
    if (admin_pubkey.size() != 32) {
        R_LOG(1, "Admin public key has invalid length: " << admin_pubkey.size() << " bytes");
        admin_pubkey.clear();
    }
    users.clear();
    for (auto &[item, node] : pt.get_child("users")) {
        auto username = node.get<std::string>("username", "");
        auto key      = decode_base64(node.get<std::string>("pubkey", ""));
        if (key.size() != 32) {
            Y_LOG(1, "User " << username << " has invalid public key length: " << key.size() << " bytes. Skipping.");
            continue;
        }
        users[username] = std::move(key);
    }
}

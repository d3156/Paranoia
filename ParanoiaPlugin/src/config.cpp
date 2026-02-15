#include "config.hpp"
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <filesystem>
#include <PluginCore/Logger/Log>
#include "utils.hpp"

using boost::property_tree::ptree;
using namespace ParanoiaUtils;

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

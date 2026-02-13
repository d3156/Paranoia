
#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>

class Config
{
public:
    unsigned short port    = 1455;
    std::string store_path = "store";
    std::vector<uint8_t> admin_pubkey;
    std::unordered_map<std::string, std::vector<uint8_t>> users;
    std::mutex mtx;

    Config() = default;

    void save(const std::string &filename);

    void load(const std::string &filename);
};

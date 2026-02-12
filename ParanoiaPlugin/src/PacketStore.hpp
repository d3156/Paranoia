#pragma once
#include <rocksdb/db.h>
#include <rocksdb/options.h>
#include <string>
#include <vector>
#include <mutex>

class PacketStore
{
public:
    PacketStore(const std::string &db_path);
    ~PacketStore();

    void push(const std::string &user_id, uint64_t seq, const std::vector<uint8_t> &data);

    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> pull(const std::string &user_id, uint64_t after_seq);

    void removeUser(const std::string &user_id);

private:
    rocksdb::DB *db_;
    std::mutex mtx_; // защита push/pull
};

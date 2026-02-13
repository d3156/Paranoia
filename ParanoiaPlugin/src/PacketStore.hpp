#pragma once
#include <cstdint>
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

    void push(const std::string &dialogue_id, uint64_t seq, const std::vector<uint8_t> &data);

    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> pull(const std::string &dialogue_id, uint64_t after_seq);

    void removeUntil(const std::string &dialogue_id, uint64_t cut_seq);

private:
    rocksdb::DB *db_;
    std::mutex mtx_; // защита push/pull
};

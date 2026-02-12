#include "PacketStore.hpp"
#include <Logger/Log.hpp>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <rocksdb/status.h>

PacketStore::PacketStore(const std::string &db_path)
{
    rocksdb::Options options;
    options.create_if_missing = true;
    rocksdb::Status status    = rocksdb::DB::Open(options, db_path, &db_);
    if (!status.ok()) { throw std::runtime_error("Cannot open RocksDB: " + status.ToString()); }
}

PacketStore::~PacketStore() { delete db_; }

static std::string makeKey(const std::string &user_id, uint64_t seq)
{
    std::ostringstream key;
    key << user_id << ":" << std::setw(20) << std::setfill('0') << seq;
    return key.str();
}

void PacketStore::push(const std::string &user_id, uint64_t seq, const std::vector<uint8_t> &data)
{
    std::lock_guard<std::mutex> lock(mtx_);
    std::string key = makeKey(user_id, seq);
    rocksdb::Slice val(reinterpret_cast<const char *>(data.data()), data.size());
    rocksdb::Status s = db_->Put(rocksdb::WriteOptions(), key, val);
    if (!s.ok()) { throw std::runtime_error("RocksDB put failed: " + s.ToString()); }
}

std::vector<std::pair<uint64_t, std::vector<uint8_t>>> PacketStore::pull(const std::string &user_id, uint64_t after_seq)
{

    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> result;

    rocksdb::Iterator *it = db_->NewIterator(rocksdb::ReadOptions());
    std::string start_key = makeKey(user_id, after_seq + 1);

    for (it->Seek(start_key); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find(user_id + ":") != 0) break;
        uint64_t seq             = std::stoull(key.substr(user_id.size() + 1));
        const rocksdb::Slice val = it->value();
        std::vector<uint8_t> data(val.data(), val.data() + val.size());
        result.emplace_back(seq, std::move(data));
    }
    delete it;
    return result;
}

void PacketStore::removeUser(const std::string &user_id)
{
    std::lock_guard<std::mutex> lock(mtx_);
    rocksdb::WriteBatch batch;

    rocksdb::Iterator *it = db_->NewIterator(rocksdb::ReadOptions());
    std::string prefix    = user_id + ":";
    for (it->Seek(prefix); it->Valid(); it->Next()) {
        std::string key = it->key().ToString();
        if (key.find(prefix) != 0) break;
        batch.Delete(key);
    }
    delete it;

    rocksdb::Status s = db_->Write(rocksdb::WriteOptions(), &batch);
    if (!s.ok()) throw std::runtime_error("Failed to remove user " + user_id + ": " + s.ToString()); 
}

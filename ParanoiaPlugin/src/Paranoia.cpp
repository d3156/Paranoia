#include "Paranoia.hpp"
#include "PacketStore.hpp"
#include "config.hpp"
#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/value.hpp>
#include <linux/prctl.h>
#include <string>
#include <sys/prctl.h>

void Paranoia::registerArgs(d3156::Args::Builder &bldr)
{
    bldr.setVersion(FULL_NAME).addOption(config_path, "Paranoia config", "Paranoia config default:" + config_path);
}

void Paranoia::registerModels(d3156::PluginCore::ModelsStorage &models)
{
    auto model = models.registerModel<ParanoiaModel>();
}

void Paranoia::postInit()
{
    config.load(config_path);
    thread_ = boost::thread([this]() { this->runIO(); });
}

std::vector<uint8_t> base64_decode(const std::string &input)
{
    using namespace boost::beast::detail;
    std::vector<uint8_t> decoded(base64::decoded_size(input.size()));
    auto result = base64::decode(decoded.data(), input.data(), input.size());
    decoded.resize(result.first);
    return decoded;
}

std::string base64_encode(const std::vector<uint8_t> &data)
{
    using namespace boost::beast::detail;
    std::string encoded(base64::encoded_size(data.size()), '\0');
    std::size_t written = base64::encode(encoded.data(), data.data(), data.size());
    encoded.resize(written); // обрезаем до реально записанных символов
    return encoded;
}

#include <openssl/evp.h>
#include <vector>
#include <string>

bool verify_signature(const std::vector<uint8_t> &pubkey, const std::string &message,
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

void Paranoia::runIO()
{
    prctl(PR_SET_NAME, "MetricsModel", 0, 0, 0);
    server = std::make_unique<d3156::EasyWebServer>(io, config.port);
    store  = std::make_unique<PacketStore>(config.store_path);
    server->addPath("/reg",
                    [this](const boost::beast::http::request<boost::beast::http::string_body> &req,
                           const boost::asio::ip::address &client_ip) -> std::pair<bool, std::string> {
                        try {
                            auto obj         = boost::json::parse(req.body()).as_object();
                            auto username    = boost::json::value_to<std::string>(obj["username"]);
                            auto pub_key_b64 = boost::json::value_to<std::string>(obj["pub_key"]);
                            auto admin_sig =
                                Config::decode_base64(boost::json::value_to<std::string>(obj["admin_sig"]));
                            auto user_pub = Config::decode_base64(pub_key_b64);
                            if (!verify_signature(config.admin_pubkey, username + pub_key_b64, admin_sig))
                                return {false, "Invalid signature"};
                            {
                                std::lock_guard<std::mutex> lock(config.mtx);
                                config.users[username] = std::move(user_pub);
                                config.save(config_path);
                            }
                            return {true, "Registered successfully"};
                        } catch (const std::exception &e) {
                            return {false, std::string("Exception: ") + e.what()};
                        }
                    });

    server->addPath("/push",
                    [this](const boost::beast::http::request<boost::beast::http::string_body> &req,
                           const boost::asio::ip::address &) -> std::pair<bool, std::string> {
                        try {
                            auto obj             = boost::json::parse(req.body()).as_object();
                            std::string username = boost::json::value_to<std::string>(obj["username"]);
                            uint64_t seq         = boost::json::value_to<uint64_t>(obj["seq"]);
                            std::vector<uint8_t> payload =
                                base64_decode(boost::json::value_to<std::string>(obj["payload"]));
                            std::vector<uint8_t> sig = base64_decode(boost::json::value_to<std::string>(obj["sig"]));

                            std::vector<uint8_t> pubkey;
                            {
                                std::lock_guard<std::mutex> lock(config.mtx);
                                auto it = config.users.find(username);
                                if (it == config.users.end()) return {false, "Not registered"};
                                pubkey = it->second;
                            }

                            std::string hash_input =
                                username + std::to_string(seq) + std::string(payload.begin(), payload.end());
                            if (!verify_signature(pubkey, hash_input, sig)) return {false, "Invalid signature"};
                            store->push(username, seq, payload); // RocksDB или другой PacketStore
                            return {true, "OK"};
                        } catch (const std::exception &e) {
                            return {false, std::string("Exception: ") + e.what()};
                        }
                    });
    server->addPath("/pull",
                    [this](const boost::beast::http::request<boost::beast::http::string_body> &req,
                           const boost::asio::ip::address &) -> std::pair<bool, std::string> {
                        try {
                            auto obj                 = boost::json::parse(req.body()).as_object();
                            std::string username     = boost::json::value_to<std::string>(obj["username"]);
                            uint64_t after_seq       = boost::json::value_to<uint64_t>(obj["after_seq"]);
                            std::vector<uint8_t> sig = base64_decode(boost::json::value_to<std::string>(obj["sig"]));
                            std::vector<uint8_t> pubkey;
                            {
                                std::lock_guard<std::mutex> lock(config.mtx);
                                auto it = config.users.find(username);
                                if (it == config.users.end()) return {false, "Not registered"};
                                pubkey = it->second;
                            }
                            std::string hash_input = username + std::to_string(after_seq);
                            if (!verify_signature(pubkey, hash_input, sig)) return {false, "Invalid user signature"};
                            boost::json::array response;
                            for (auto &p : store->pull(username, after_seq)) {
                                boost::json::object packet;
                                packet["seq"]     = p.first;
                                packet["payload"] = base64_encode(p.second);
                                response.push_back(std::move(packet));
                            }
                            return {true, boost::json::serialize(response)};
                        } catch (const std::exception &e) {
                            return {false, std::string("Exception: ") + e.what()};
                        }
                    });
    io.run();
    G_LOG(1, "Io-context canceled");
}

Paranoia::~Paranoia()
{
    constexpr boost::chrono::milliseconds stopThreadTimeout = boost::chrono::milliseconds(200);
    try {
        stopToken = true;
        io_guard.reset();
        G_LOG(1, "Io-context guard canceled");
        if (!thread_.joinable()) return;
        G_LOG(1, "Thread joinable, try join in " << stopThreadTimeout.count() << " milliseconds");
        if (thread_.timed_join(stopThreadTimeout)) return;
        Y_LOG(1, "Thread was not terminated, attempting to force stop io_context...");
        io.stop();
        if (thread_.timed_join(stopThreadTimeout)) {
            G_LOG(1, "io_context force stopped successfully");
            return;
        }
        R_LOG(1, "WARNING: Thread cannot be stopped. Thread will be detached (potential resource leak)");
        thread_.detach();
    } catch (std::exception &e) {
        R_LOG(1, "Exception throwed in exit: " << e.what());
    }
}

// ABI required by d3156::PluginCore::Core (dlsym uses exact names)
extern "C" d3156::PluginCore::IPlugin *create_plugin() { return new Paranoia(); }

extern "C" void destroy_plugin(d3156::PluginCore::IPlugin *p) { delete p; }

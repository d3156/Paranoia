#include "Paranoia.hpp"
#include "PacketStore.hpp"
#include "config.hpp"
#include <MetricsModel/MetricsModel>
#include <boost/json/src.hpp>
#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/value.hpp>
#include <linux/prctl.h>
#include <string>
#include <sys/prctl.h>
#include <memory>

void Paranoia::registerArgs(d3156::Args::Builder &bldr)
{
    bldr.setVersion(FULL_NAME).addOption(config_path, "Paranoia config", "Paranoia config default:" + config_path);
}

void Paranoia::registerModels(d3156::PluginCore::ModelsStorage &models)
{
    MetricsModel::instance()  = models.registerModel<MetricsModel>();
    auto model                = models.registerModel<ParanoiaModel>();
    reg_success_total         = std::make_unique<Metrics::Counter>("paranoia_reg_success_total");
    reg_fail_total            = std::make_unique<Metrics::Counter>("paranoia_reg_fail_total");
    push_success_total        = std::make_unique<Metrics::Counter>("paranoia_push_success_total");
    push_fail_total           = std::make_unique<Metrics::Counter>("paranoia_push_fail_total");
    pull_success_total        = std::make_unique<Metrics::Counter>("paranoia_pull_success_total");
    pull_fail_total           = std::make_unique<Metrics::Counter>("paranoia_pull_fail_total");
    determinate_success_total = std::make_unique<Metrics::Counter>("paranoia_determinate_success_total");
    determinate_fail_total    = std::make_unique<Metrics::Counter>("paranoia_determinate_fail_total");
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
                            if (user_pub.size() != 32 || admin_sig.size() != 64 ||
                                !verify_signature(config.admin_pubkey, username + pub_key_b64, admin_sig)) {
                                (*reg_fail_total)++;
                                R_LOG(1, "Rejected registration for user '" << username << "'");
                                return {false, "Bad pubkey or signature"};
                            }
                            {
                                std::lock_guard<std::mutex> lock(config.mtx);
                                config.users[username] = std::move(user_pub);
                                config.save(config_path);
                            }
                            (*reg_success_total)++;
                            G_LOG(1, "User '" << username << "' registered successfully");
                            return {true, "OK"};
                        } catch (const std::exception &e) {
                            (*reg_fail_total)++;
                            R_LOG(1, "Exception in /reg: " << e.what());
                            return {false, std::string("Exception: ") + e.what()};
                        }
                    });

    server->addPath(
        "/push",
        [this](const boost::beast::http::request<boost::beast::http::string_body> &req,
               const boost::asio::ip::address &) -> std::pair<bool, std::string> {
            try {
                auto obj                     = boost::json::parse(req.body()).as_object();
                std::string username         = boost::json::value_to<std::string>(obj["username"]);
                uint64_t seq                 = boost::json::value_to<uint64_t>(obj["seq"]);
                std::vector<uint8_t> payload = base64_decode(boost::json::value_to<std::string>(obj["payload"]));
                std::vector<uint8_t> sig     = base64_decode(boost::json::value_to<std::string>(obj["sig"]));
                if (sig.size() != 64) {
                    (*push_fail_total)++;
                    R_LOG(1, "Push rejected for user '" << username << "': invalid signature length " << sig.size());
                    return {false, "Bad sig len"};
                }

                std::vector<uint8_t> pubkey;
                {
                    std::lock_guard<std::mutex> lock(config.mtx);
                    auto it = config.users.find(username);
                    if (it == config.users.end()) {
                        (*push_fail_total)++;
                        return {false, "Not registered"};
                    }
                    pubkey = it->second;
                }

                std::string hash_input = username + std::to_string(seq) + std::string(payload.begin(), payload.end());
                if (!verify_signature(pubkey, hash_input, sig)) return {false, "Invalid signature"};
                store->push(username, seq, payload);
                (*push_success_total)++;
                return {true, "OK"};
            } catch (const std::exception &e) {
                (*push_fail_total)++;
                R_LOG(1, "Error on /push data " << e.what());
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
                            if (sig.size() != 64) {
                                R_LOG(1, "Push rejected for user '" << username << "': invalid signature length "
                                                                    << sig.size());
                                (*pull_fail_total)++;
                                return {false, "Bad sig len"};
                            }
                            std::vector<uint8_t> pubkey;
                            {
                                std::lock_guard<std::mutex> lock(config.mtx);
                                auto it = config.users.find(username);
                                if (it == config.users.end()) {
                                    (*pull_fail_total)++;
                                    return {false, "Not registered"};
                                }
                                pubkey = it->second;
                            }
                            std::string hash_input = username + std::to_string(after_seq);
                            if (!verify_signature(pubkey, hash_input, sig)) {
                                (*pull_fail_total)++;
                                return {false, "Invalid user signature"};
                            }
                            boost::json::array response;
                            for (auto &p : store->pull(username, after_seq)) {
                                boost::json::object packet;
                                packet["seq"]     = p.first;
                                packet["payload"] = base64_encode(p.second);
                                response.push_back(std::move(packet));
                            }
                            (*pull_success_total)++;
                            return {true, boost::json::serialize(response)};
                        } catch (const std::exception &e) {
                            (*pull_fail_total)++;
                            R_LOG(1, "Error on /pull data " << e.what());
                            return {false, std::string("Exception: ") + e.what()};
                        }
                    });

    server->addPath("/determinate",
                    [this](const boost::beast::http::request<boost::beast::http::string_body> &req,
                           const boost::asio::ip::address &) -> std::pair<bool, std::string> {
                        try {
                            auto obj                 = boost::json::parse(req.body()).as_object();
                            std::string username     = boost::json::value_to<std::string>(obj["username"]);
                            uint64_t after_seq       = boost::json::value_to<uint64_t>(obj["after_seq"]);
                            std::vector<uint8_t> sig = base64_decode(boost::json::value_to<std::string>(obj["sig"]));
                            if (sig.size() != 64) {
                                R_LOG(1, "Push rejected for user '" << username << "': invalid signature length "
                                                                    << sig.size());
                                (*determinate_fail_total)++;
                                return {false, "Bad sig len"};
                            }
                            std::vector<uint8_t> pubkey;
                            {
                                std::lock_guard<std::mutex> lock(config.mtx);
                                auto it = config.users.find(username);
                                if (it == config.users.end()) {
                                    (*determinate_fail_total)++;
                                    return {false, "Not registered"};
                                }
                                pubkey = it->second;
                            }
                            std::string hash_input = username + std::to_string(after_seq);
                            if (!verify_signature(pubkey, hash_input, sig)) {
                                (*determinate_fail_total)++;
                                return {false, "Invalid user signature"};
                            }
                            store->removeUser(username);
                            G_LOG(1, "All packets for user '" << username << "' have been deleted");
                            (*determinate_success_total)++;
                            return {true, "OK"};
                        } catch (const std::exception &e) {
                            (*determinate_fail_total)++;
                            R_LOG(1, "Error on /determinate data " << e.what());
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

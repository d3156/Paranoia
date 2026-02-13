#include "Paranoia.hpp"
#include "PacketStore.hpp"
#include "config.hpp"
#include "utils.hpp"
#include <MetricsModel/MetricsModel>
#include <boost/json/src.hpp>
#include <boost/json/parse.hpp>
#include <boost/json/serialize.hpp>
#include <boost/json/value.hpp>
#include <linux/prctl.h>
#include <string>
#include <sys/prctl.h>
#include <memory>

using namespace ParanoiaUtils;

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

void Paranoia::runIO()
{
    prctl(PR_SET_NAME, "MetricsModel", 0, 0, 0);
    server = std::make_unique<d3156::EasyWebServer>(io, config.port);
    store  = std::make_unique<PacketStore>(config.store_path);
    G_LOG(0, "Paranoia server started at http://0.0.0.0:" << config.port);
    server->addPath("/reg", [this](const d3156::string_req &req, const d3156::address &a) -> d3156::Answer {
        return this->reg(req, a);
    });
    server->addPath("/push", [this](const d3156::string_req &req, const d3156::address &a) -> d3156::Answer {
        return this->push(req, a);
    });
    server->addPath("/pull", [this](const d3156::string_req &req, const d3156::address &a) -> d3156::Answer {
        return this->pull(req, a);
    });
    server->addPath("/determinate", [this](const d3156::string_req &req, const d3156::address &a) -> d3156::Answer {
        return this->determinate(req, a);
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

d3156::Answer Paranoia::reg(const d3156::string_req &req, const d3156::address &)
{
    try {
        auto obj         = boost::json::parse(req.body()).as_object();
        auto username    = boost::json::value_to<std::string>(obj["username"]);
        auto pub_key_b64 = boost::json::value_to<std::string>(obj["pub_key"]);
        auto admin_sig   = decode_base64(boost::json::value_to<std::string>(obj["admin_sig"]));
        auto user_pub    = decode_base64(pub_key_b64);
        if (user_pub.size() != 32 || admin_sig.size() != 64 ||
            !verify_signature(config.admin_pubkey, username + pub_key_b64, admin_sig)) {
            (*reg_fail_total)++;
            R_LOG(10, "Rejected registration for user '" << username << "'");
            return {false, "Bad pubkey or signature"};
        }
        {
            std::lock_guard<std::mutex> lock(config.mtx);
            if (config.users.contains(username)) {
                R_LOG(10, "User '" << username << "' already registred: ");
                return {false, "User already registred"};
            }
            config.users[username] = std::move(user_pub);
            config.save(config_path);
        }
        (*reg_success_total)++;
        G_LOG(10, "User '" << username << "' registered successfully");
        return {true, "OK"};
    } catch (const std::exception &e) {
        (*reg_fail_total)++;
        R_LOG(10, "Exception in /reg: " << e.what());
        return {false, std::string("Exception: ") + e.what()};
    }
}

d3156::Answer Paranoia::push(const d3156::string_req &req, const d3156::address &)
{
    try {
        auto obj                     = boost::json::parse(req.body()).as_object();
        std::string sender           = boost::json::value_to<std::string>(obj["sender"]);
        std::string recver           = boost::json::value_to<std::string>(obj["recver"]);
        uint64_t seq                 = boost::json::value_to<uint64_t>(obj["seq"]);
        // Тут возможна атака перепосылкой, т.к. не проверяется seq но будет owerwrite сообщения а на сообщение а. 
        // Критично будет, если добавим изменения старых сообщений по seq. Тогда MITM может перезаписать новое старым
        std::vector<uint8_t> payload = decode_base64(boost::json::value_to<std::string>(obj["payload"]));
        std::vector<uint8_t> sig     = decode_base64(boost::json::value_to<std::string>(obj["sig"]));
        if (!checkSigSize(sig, *push_fail_total)) return {false, "Bad sig len"};
        auto pubkey = checkRegister(sender, recver, *push_fail_total);
        if (!pubkey) return {false, "One user in pair not registered"};
        std::string hash_input = sender + recver + std::to_string(seq) + std::string(payload.begin(), payload.end());
        if (!verify_signature(*pubkey, hash_input, sig)) return {false, "Invalid signature"};
        store->push(make_dialogue_id(sender, recver), seq, payload);
        (*push_success_total)++;
        return {true, "OK"};
    } catch (const std::exception &e) {
        (*push_fail_total)++;
        R_LOG(10, "Error on /push data " << e.what());
        return {false, std::string("Exception: ") + e.what()};
    }
}

d3156::Answer Paranoia::determinate(const d3156::string_req &req, const d3156::address &)
{
    try {
        auto obj                 = boost::json::parse(req.body()).as_object();
        std::string sender       = boost::json::value_to<std::string>(obj["sender"]);
        std::string recver       = boost::json::value_to<std::string>(obj["recver"]);
        uint64_t cut_seq           = boost::json::value_to<uint64_t>(obj["cut_seq"]);
        std::vector<uint8_t> sig = decode_base64(boost::json::value_to<std::string>(obj["sig"]));
        if (!checkSigSize(sig, *determinate_fail_total)) return {false, "Bad sig len"};
        auto pubkey = checkRegister(sender, recver, *determinate_fail_total);
        if (!pubkey) return {false, "One user in pair not registered"};
        std::string hash_input = sender + recver + std::to_string(cut_seq);
        if (!verify_signature(*pubkey, hash_input, sig)) {
            (*determinate_fail_total)++;
            return {false, "Invalid user signature"};
        }
        store->removeUntil(make_dialogue_id(sender, recver), cut_seq);
        G_LOG(10, "All packets for dialogue '" << sender << "->" << recver << "' have been deleted");
        (*determinate_success_total)++;
        return {true, "OK"};
    } catch (const std::exception &e) {
        (*determinate_fail_total)++;
        R_LOG(10, "Error on /determinate data " << e.what());
        return {false, std::string("Exception: ") + e.what()};
    }
}

d3156::Answer Paranoia::pull(const d3156::string_req &req, const d3156::address &)
{
    try {
        auto obj                 = boost::json::parse(req.body()).as_object();
        std::string sender       = boost::json::value_to<std::string>(obj["sender"]);
        std::string recver       = boost::json::value_to<std::string>(obj["recver"]);
        uint64_t after_seq       = boost::json::value_to<uint64_t>(obj["after_seq"]);
        std::vector<uint8_t> sig = decode_base64(boost::json::value_to<std::string>(obj["sig"]));
        if (!checkSigSize(sig, *pull_fail_total)) return {false, "Bad sig len"};
        auto pubkey = checkRegister(sender, recver, *pull_fail_total);
        if (!pubkey) return {false, "One user in pair not registered"};
        std::string hash_input = sender + recver + std::to_string(after_seq);
        if (!verify_signature(*pubkey, hash_input, sig)) {
            (*pull_fail_total)++;
            return {false, "Invalid user signature"};
        }
        boost::json::array response;
        for (auto &p : store->pull(make_dialogue_id(sender, recver), after_seq)) {
            boost::json::object packet;
            packet["seq"]     = p.first;
            packet["payload"] = encode_base64(p.second);
            response.push_back(std::move(packet));
        }
        (*pull_success_total)++;
        return {true, boost::json::serialize(response)};
    } catch (const std::exception &e) {
        (*pull_fail_total)++;
        R_LOG(10, "Error on /pull data " << e.what());
        return {false, std::string("Exception: ") + e.what()};
    }
}

std::optional<std::vector<uint8_t>> Paranoia::checkRegister(const std::string &sender, const std::string &recver,
                                                            Metrics::Counter&fails)
{
    std::lock_guard<std::mutex> lock(config.mtx);
    auto it = config.users.find(sender);
    if (!config.users.contains(recver) || it == config.users.end()) {
        fails++;
        return {};
    }
    return it->second;
}

bool Paranoia::checkSigSize(const std::vector<uint8_t> &sig, Metrics::Counter &fails)
{
    if (sig.size() == 64) return true;
    R_LOG(10, "Rejected for dialogue invalid signature length " << sig.size());
    fails++;
    return false;
}

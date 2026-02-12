#pragma once
#include <PluginCore/IPlugin.hpp>
#include <PluginCore/IModel.hpp>
#include <memory>
#include <ParanoiaModel>
#include <boost/thread/thread.hpp>
#include <EasyHttpLib/EasyWebServer>
#include <MetricsModel/Metrics>
#include <string>
#include "PacketStore.hpp"
#include "config.hpp"

class Paranoia final : public d3156::PluginCore::IPlugin
{
    std::string config_path = "./configs/Paranoia.json";

    Config config;

    std::unique_ptr<PacketStore> store{};
    std::unique_ptr<d3156::EasyWebServer> server;

public:
    void registerArgs(d3156::Args::Builder &bldr) override;
    void registerModels(d3156::PluginCore::ModelsStorage &models) override;
    void postInit() override;
    void runIO();

    ~Paranoia();

private:
    boost::asio::io_context io;
    boost::thread thread_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> io_guard =
        boost::asio::make_work_guard(io);
    std::atomic<bool> stopToken = false;

    std::unique_ptr<Metrics::Counter> reg_success_total;
    std::unique_ptr<Metrics::Counter> reg_fail_total;

    std::unique_ptr<Metrics::Counter> push_success_total;
    std::unique_ptr<Metrics::Counter> push_fail_total;

    std::unique_ptr<Metrics::Counter> pull_success_total;
    std::unique_ptr<Metrics::Counter> pull_fail_total;

    std::unique_ptr<Metrics::Counter> determinate_success_total;
    std::unique_ptr<Metrics::Counter> determinate_fail_total;
};

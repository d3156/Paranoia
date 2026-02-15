#pragma once
#include <PluginCore/IModel>

class ParanoiaModel final : public d3156::PluginCore::IModel {
    std::string configPath = "./configs/ParanoiaModel.json";
public:
    static std::string name();
    void registerArgs(d3156::Args::Builder &bldr) override;
    int deleteOrder() override { return 0; }
    void init() override;
    void postInit() override;
};
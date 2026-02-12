#include "ParanoiaModel.hpp"

void ParanoiaModel::init(){
    // TODO: allocate/init resources here
}

void ParanoiaModel::postInit(){
    // TODO: optional
}

void ParanoiaModel::registerArgs(d3156::Args::Builder &bldr)
{
    bldr.setVersion(FULL_NAME).addOption(configPath, "ParanoiaModelPath", "path to config for ParanoiaModel.json");
}

std::string ParanoiaModel::name() { return FULL_NAME; }
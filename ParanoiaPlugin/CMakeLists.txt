cmake_minimum_required(VERSION 3.16)
project(Paranoia VERSION 1.0.0 LANGUAGES CXX)
include("${CMAKE_CURRENT_SOURCE_DIR}/../../../tools/workspace.cmake")
create_target(plugin)

dependency("../.." ParanoiaModel "https://gitlab.bubki.zip/d3156/Paranoia.git")
dependency("../.." EasyHttpLib "https://gitlab.bubki.zip/d3156/EasyHttpLib.git")
dependency("../.." MetricsModel "https://gitlab.bubki.zip/d3156/MetricsModel.git")
dependency("../.." ConfiguratorModel "https://gitlab.bubki.zip/d3156/PluginConfigurator")

find_package(Boost 1.8 REQUIRED COMPONENTS json thread system url)
target_link_libraries(Paranoia PRIVATE Boost::json Boost::system Boost::thread Boost::url)

find_package(OpenSSL REQUIRED COMPONENTS SSL Crypto)
target_link_libraries(Paranoia PUBLIC OpenSSL::SSL OpenSSL::Crypto)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ROCKSDB REQUIRED rocksdb)

target_include_directories(Paranoia PRIVATE ${ROCKSDB_INCLUDE_DIRS})
target_link_libraries(Paranoia PRIVATE ${ROCKSDB_LIBRARIES})
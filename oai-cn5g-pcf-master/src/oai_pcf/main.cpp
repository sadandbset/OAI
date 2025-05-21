/*
 * Copyright (c) 2019 EURECOM
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "logger.hpp"
#include "pcf-api-server.hpp"
#include "pcf-http2-server.hpp"
#include "pcf_app.hpp"
#include "pcf_config.hpp"
#include "options.hpp"
#include "pistache/http.h"
#include "nf_launch.hpp"
#include "conversions.hpp"
#include "http_client.hpp"

#include <iostream>
#include <csignal>
#include <thread>
#include <chrono>

using namespace std;
using namespace oai::pcf::app;
using namespace oai::config::pcf;
using namespace oai::utils;
using namespace oai::pcf::api;

using namespace oai::config;

std::unique_ptr<pcf_app> pcf_app_inst                    = nullptr;
std::unique_ptr<pcf_config> pcf_cfg                      = nullptr;
std::unique_ptr<PCFApiServer> pcf_api_server_1           = nullptr;
std::unique_ptr<pcf_http2_server> pcf_api_server_2       = nullptr;
std::shared_ptr<oai::http::http_client> http_client_inst = nullptr;

//------------------------------------------------------------------------------
void signal_handler_sigint(int s) {
  auto shutdown_start = std::chrono::system_clock::now();
  // Setting log level arbitrarly to debug to show the whole
  // shutdown procedure in the logs even in case of off-logging
  Logger::set_level(spdlog::level::debug);
  Logger::system().info("Exiting: caught signal %d", s);

  Logger::system().debug("Shutting down HTTP servers...");
  if (pcf_api_server_1) {
    pcf_api_server_1->shutdown();
  }
  if (pcf_api_server_2) {
    pcf_api_server_2->stop();
  }
  if (pcf_app_inst) {
    pcf_app_inst->stop();
  }
  // TODO exit is not always clean, check again after complete refactor
  // Ensure that objects are destructed before static libraries (e.g. Logger)
  Logger::system().debug("Freeing Allocated memory...");
  pcf_api_server_1 = nullptr;
  pcf_api_server_2 = nullptr;
  pcf_app_inst     = nullptr;
  pcf_cfg          = nullptr;

  Logger::system().debug("PCF APP memory done");
  Logger::system().debug("Freeing allocated memory done");
  auto elapsed = std::chrono::system_clock::now() - shutdown_start;
  auto ms_diff = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
  Logger::system().info("Bye. Shutdown Procedure took %d ms", ms_diff.count());
  exit(0);
}

//------------------------------------------------------------------------------
int main(int argc, char** argv) {
  if (nf_launch::already_running()) {
    std::cout << "NF instance already running. Exiting" << std::endl;
    return 1;
  }

  // Command line options
  if (!oai::utils::options::parse(argc, argv)) {
    std::cout << "Options::parse() failed" << std::endl;
    return 1;
  }

  // Logger
  Logger::init(
      "pcf", oai::utils::options::getlogStdout(),
      oai::utils::options::getlogRotFilelog());

  std::signal(SIGTERM, signal_handler_sigint);
  std::signal(SIGINT, signal_handler_sigint);

  pcf_cfg = std::make_unique<pcf_config>(
      oai::utils::options::getlibconfigConfig(),
      oai::utils::options::getlogStdout(),
      oai::utils::options::getlogRotFilelog());
  if (!pcf_cfg->init()) {
    pcf_cfg->display();
    Logger::system().error("Reading the configuration failed. Exiting.");
    return 1;
  }
  pcf_cfg->display();

  // HTTP Client
  http_client_inst = oai::http::http_client::create_instance(
      Logger::pcf_client(), oai::common::sbi::kNfDefaultHttpRequestTimeout,
      pcf_cfg->local().get_sbi().get_if_name(), pcf_cfg->get_http_version());

  // Event subsystem
  pcf_event ev;

  // PCF application layer
  pcf_app_inst = std::make_unique<pcf_app>(ev);

  std::string v4_address =
      oai::utils::conv::toString(pcf_cfg->local().get_sbi().get_addr4());

  if (pcf_cfg->get_http_version() == 1) {
    // PCF Pistache API server (HTTP1)
    Pistache::Address addr(
        v4_address, Pistache::Port(pcf_cfg->local().get_sbi().get_port()));

    pcf_api_server_1 = std::make_unique<PCFApiServer>(addr, pcf_app_inst);
    pcf_api_server_1->init(2);
    std::thread pcf_http1_manager(&PCFApiServer::start, pcf_api_server_1.get());
    pcf_http1_manager.join();
  } else if (pcf_cfg->get_http_version() == 2) {
    // PCF NGHTTP API server (HTTP2)
    pcf_api_server_2 = std::make_unique<pcf_http2_server>(
        v4_address, pcf_cfg->local().get_sbi().get_port(), pcf_app_inst);
    std::thread pcf_http2_manager(
        &pcf_http2_server::start, pcf_api_server_2.get());
    pcf_http2_manager.join();
  }

  Logger::pcf_app().info("HTTP servers successfully stopped. Exiting");

  return 0;
}

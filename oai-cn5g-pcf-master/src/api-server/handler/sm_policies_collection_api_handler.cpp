/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 * file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

/*! \file sm_policies_collection_api_handler.cpp
 \brief
 \author  Stefan Spettel
 \company phine.tech
 \date 2023
 \email: stefan.spettel@phine.tech
 */

#include "api_response.h"
#include "sm_policies_collection_api_handler.h"

#include "ProblemDetails.h"
#include "SmPolicyDecision.h"
#include "SMPoliciesCollectionApi.h"
#include "logger.hpp"
#include "api_defs.h"
#include "pcf_config.hpp"

namespace oai::pcf::api {

using namespace oai::model::pcf;
using namespace oai::model::common;
using namespace oai::pcf::app::sm_policy;
using namespace oai::common::sbi;

api_response sm_policies_collection_api_handler::create_sm_policy(
    const SmPolicyContextData& sm_policy_context_data) {
  uint16_t http_code;
  std::string cause;
  ProblemDetails problem_details;
  SmPolicyDecision decision;
  std::string details_string;
  std::string association_id;
  std::string location;
  std::string content_type = "application/problem+json";
  api_response response;

  status_code res = m_smpc_service->create_sm_policy_handler(
      sm_policy_context_data, decision, association_id, details_string);
  nlohmann::json json_data;

  switch (res) {
    case status_code::CREATED:
      http_code = http_status_code::CREATED;
      location  = m_address + sm_policies::get_route() + "/" + association_id;
      content_type = "application/json";
      break;

    case status_code::USER_UNKOWN:
      problem_details.setCause("USER_UNKOWN");
      problem_details.setDetail(details_string);
      http_code = http_status_code::BAD_REQUEST;
      break;

    case status_code::INVALID_PARAMETERS:
      problem_details.setCause("ERROR_INITIAL_PARAMETERS");
      problem_details.setDetail(details_string);
      http_code = http_status_code::BAD_REQUEST;
      break;

    case status_code::CONTEXT_DENIED:
      problem_details.setCause("POLICY_CONTEXT_DENIED");
      problem_details.setDetail(details_string);
      http_code = http_status_code::FORBIDDEN;
      break;

    default:
      Logger::pcf_app().error("Unknown error code");
      http_code = http_status_code::INTERNAL_SERVER_ERROR;
      problem_details.setCause("INTERNAL_ERROR");
      problem_details.setDetail("Internal Service Error: Unknown return code.");
  }

  if (http_code != http_status_code::CREATED) {
    to_json(json_data, problem_details);
  } else {
    to_json(json_data, decision);
    response.headers.add<Pistache::Http::Header::Location>(location);
  }
  response.headers.add<Pistache::Http::Header::ContentType>(
      Pistache::Http::Mime::MediaType(content_type));
  response.body        = json_data.dump();
  response.status_code = http_code;
  return response;
}

}  // namespace oai::pcf::api

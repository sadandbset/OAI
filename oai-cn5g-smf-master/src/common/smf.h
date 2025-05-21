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

#ifndef FILE_SMF_SEEN
#define FILE_SMF_SEEN

#include <boost/algorithm/string.hpp>
#include <map>
#include <nlohmann/json.hpp>
#include <unordered_set>
#include <vector>

#include "3gpp_24.501.h"
#include "3gpp_29.274.h"
#include "3gpp_29.571.h"
#include "Snssai.h"

typedef uint64_t supi64_t;
#define SUPI_64_FMT "%" SCNu64

#define SUPI_DIGITS_MAX 15

typedef struct {
  uint32_t length;
  char data[SUPI_DIGITS_MAX + 1];
} supi_t;

// TODO: Move to conversions
static void smf_string_to_supi(supi_t* const supi, char const* const supi_str) {
  // strncpy(supi->data, supi_str, SUPI_DIGITS_MAX + 1);
  memcpy((void*) supi->data, (void*) supi_str, SUPI_DIGITS_MAX + 1);
  supi->length = strlen(supi->data);
  return;
}

static std::string smf_supi_to_string(supi_t const supi) {
  std::string supi_str;
  supi_str.assign(supi.data, SUPI_DIGITS_MAX + 1);
  return supi_str;
}

static std::string smf_get_supi_with_prefix(
    const std::string& prefix, const std::string& supi) {
  std::string supi_str = {};
  if (!prefix.empty()) {
    supi_str = prefix + "-" + supi;
  } else {
    supi_str = supi;
  }
  return supi_str;
}

// TODO should we just replace the other function? Because this null chars are
// annoying
static std::string smf_supi_to_string_without_nulls(supi_t const supi) {
  std::string supi_str;
  for (char c : supi.data) {
    if (c != '\u0000') {
      supi_str += c;
    }
  }
  return supi_str;
}

static uint64_t smf_supi_to_u64(supi_t supi) {
  uint64_t uint_supi;
  sscanf(supi.data, "%" SCNu64, &uint_supi);
  return uint_supi;
}

static std::string smf_supi64_to_string(const supi64_t& supi) {
  std::string supi_str = std::to_string(supi);
  uint8_t padded_len   = SUPI_DIGITS_MAX - supi_str.length();
  for (int i = 0; i < padded_len; i++) supi_str = "0" + supi_str;
  return supi_str;
}

// From 23.502
enum class session_management_procedures_type_e {
  PROCEDURE_TYPE_UNKNOWN                      = 0,
  PDU_SESSION_ESTABLISHMENT_UE_REQUESTED      = 1,
  SERVICE_REQUEST_UE_TRIGGERED_STEP1          = 2,
  SERVICE_REQUEST_UE_TRIGGERED_STEP2          = 3,
  SERVICE_REQUEST_NETWORK_TRIGGERED           = 4,
  PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1 = 5,
  PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2 = 6,
  PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3 = 7,
  PDU_SESSION_MODIFICATION_SMF_REQUESTED      = 8,
  PDU_SESSION_MODIFICATION_AN_REQUESTED       = 9,
  PDU_SESSION_RELEASE_UE_REQUESTED_STEP1      = 10,
  PDU_SESSION_RELEASE_UE_REQUESTED_STEP2      = 11,
  PDU_SESSION_RELEASE_UE_REQUESTED_STEP3      = 12,
  PDU_SESSION_RELEASE_SMF_INITIATED           = 13,
  PDU_SESSION_RELEASE_AMF_INITIATED           = 14,
  PDU_SESSION_RELEASE_AN_INITIATED            = 15,
  HO_PATH_SWITCH_REQ                          = 16,
  N2_HO_PREPARATION_PHASE_STEP1               = 17,
  N2_HO_PREPARATION_PHASE_STEP2               = 18,
  N2_HO_EXECUTION_PHASE                       = 19,
  N2_HO_CANCELLATION_PHASE                    = 20,
  PDU_SESSION_TEST                            = 21
};

static const std::vector<std::string> session_management_procedures_type_e2str =
    {"PROCEDURE_TYPE_UNKNOWN",
     "PDU_SESSION_ESTABLISHMENT_UE_REQUESTED",
     "SERVICE_REQUEST_UE_TRIGGERED_STEP1",
     "SERVICE_REQUEST_UE_TRIGGERED_STEP2",
     "SERVICE_REQUEST_NETWORK_TRIGGERED",
     "PDU_SESSION_MODIFICATION_UE_INITIATED_STEP1",
     "PDU_SESSION_MODIFICATION_UE_INITIATED_STEP2",
     "PDU_SESSION_MODIFICATION_UE_INITIATED_STEP3",
     "PDU_SESSION_MODIFICATION_SMF_REQUESTED",
     "PDU_SESSION_MODIFICATION_AN_REQUESTED",
     "PDU_SESSION_RELEASE_UE_REQUESTED_STEP1",
     "PDU_SESSION_RELEASE_UE_REQUESTED_STEP2",
     "PDU_SESSION_RELEASE_UE_REQUESTED_STEP3",
     "PDU_SESSION_RELEASE_SMF_INITIATED",
     "PDU_SESSION_RELEASE_AMF_INITIATED",
     "PDU_SESSION_RELEASE_AN_INITIATED",
     "HO_PATH_SWITCH_REQ",
     "N2_HO_PREPARATION_PHASE_STEP1",
     "N2_HO_PREPARATION_PHASE_STEP2",
     "N2_HO_EXECUTION_PHASE",
     "PDU_SESSION_TEST"

};

typedef struct qos_profile_gbr_s {
  gfbr_t gfbr;  // Guaranteed Flow Bit Rate
  mfbr_t mfbr;  // Maximum Flow Bit Rate
  // Notification Control
  // Maximum Packet Loss Rate (UL/DL)
} qos_profile_gbr_t;

enum class qos_profile_type_e { NON_GBR = 0, GBR = 1 };

// See Section 5.7.2@3GPP TS 23.501
typedef struct qos_profile_s {
  uint8_t _5qi;
  arp_5gc_t arp;
  uint8_t priority_level;
  qos_profile_type_e profile_type;
  union {
    reflective_qos_attribute_e rqa;     // Reflective QoS Attribute (RQA)
    qos_profile_gbr_t qos_profile_gbr;  // Attributes for GBR
  } parameter;
} qos_profile_t;

// URL, N1, N2 (may get from configuration file)
#define NAMF_COMMUNICATION_BASE "/namf-comm/"
#define NAMF_COMMUNICATION_N1N2_MESSAGE_TRANSFER_URL                           \
  "/ue-contexts/{}/n1-n2-messages"  // context id
#define NUDM_SDM_BASE "/nudm-sdm/"
#define NUDM_SDM_GET_SM_DATA_URL "/{}/sm-data"  // ue Id
#define N1_SM_CONTENT_ID "n1SmMsg"
#define N1N2_MESSAGE_CLASS "SM"
#define N2_SM_CONTENT_ID "n2msg"
#define NSMF_PDU_SESSION_BASE "/nsmf-pdusession/"
#define NSMF_CALLBACK_N1N2_MESSAGE_TRANSFER_FAILURE                            \
  "/callback/N1N2MsgTxfrFailureNotification/{}"  // UE Id
#define NSMF_PDU_SESSION_SM_CONTEXT_CREATE_URL "/sm-contexts"
#define NSMF_PDU_SESSION_SM_CONTEXT_UPDATE_URL "/sm-contexts/"
#define NSMF_SMF_CONFIGURATION_BASE "/nsmf-configuration/"
#define NSMF_SMF_CONFIGURATION_CREATE_DNN "/dnn-configurations"

#define NSMF_CUSTOMIZED_API_BASE "/nsmf-oai/"
#define NSMF_CUSTOMIZED_API_CONFIGURATION_URL "/configuration"

// Event Exposure
#define NSMF_EVENT_EXPOSURE_API_BASE "/nsmf_event-exposure/"
#define NSMF_EVENT_EXPOSURE_SUBSCRIBE_URL "/subscriptions"
// NRF
#define NNRF_NFM_BASE "/nnrf-nfm/"
#define NNRF_NF_REGISTER_URL "/nf-instances/"
#define NNRF_NF_STATUS_SUBSCRIBE_URL "/subscriptions"
#define NNRF_NF_STATUS_NOTIFY_BASE "/nsmf-nfstatus-notify/"

// for CURL
#define NF_CURL_TIMEOUT_MS 3000L
#define MAX_WAIT_MSECS 10000  // 1 second
#define AMF_NUMBER_RETRIES 3
#define UDM_NUMBER_RETRIES 3

// for N1N2
#define BUF_LEN 512

// FOR FUTURE PROMISE
#define FUTURE_STATUS_TIMEOUT_MS 100

// for PFCP
constexpr uint64_t SECONDS_SINCE_FIRST_EPOCH = 2208988800;
// 8.22  Fully Qualified TEID (F-TEID) - 3GPP TS 29.274 V16.0.0
#define TEID_GRE_KEY_LENGTH 4

#define DEFAULT_QFI 1
#define DEFAULT_5QI 9  // TODO: from conf file

#endif

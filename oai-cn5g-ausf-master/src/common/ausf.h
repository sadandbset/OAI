/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this
 *file except in compliance with the License. You may obtain a copy of the
 *License at
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

#ifndef FILE_AUSF_SEEN
#define FILE_AUSF_SEEN

#include "sbi_helper.hpp"

#define HEART_BEAT_TIMER 10

#define NRF_REGISTRATION_RETRY_TIMER 5

#define _unused(x) ((void) (x))

typedef enum nf_type_s {
  NF_TYPE_NRF     = 0,
  NF_TYPE_AMF     = 1,
  NF_TYPE_SMF     = 2,
  NF_TYPE_AUSF    = 3,
  NF_TYPE_NEF     = 4,
  NF_TYPE_PCF     = 5,
  NF_TYPE_SMSF    = 6,
  NF_TYPE_NSSF    = 7,
  NF_TYPE_UDR     = 8,
  NF_TYPE_LMF     = 9,
  NF_TYPE_GMLC    = 10,
  NF_TYPE_5G_EIR  = 11,
  NF_TYPE_SEPP    = 12,
  NF_TYPE_UPF     = 13,
  NF_TYPE_N3IWF   = 14,
  NF_TYPE_AF      = 15,
  NF_TYPE_UDSF    = 16,
  NF_TYPE_BSF     = 17,
  NF_TYPE_CHF     = 18,
  NF_TYPE_NWDAF   = 19,
  NF_TYPE_UNKNOWN = 20
} nf_type_t;

static const std::vector<std::string> nf_type_e2str = {
    "NRF",   "AMF", "SMF",  "AUSF", "NEF",    "PCF",   "SMSF",
    "NSSF",  "UDR", "LMF",  "GMLC", "5G_EIR", "SEPP",  "UPF",
    "N3IWF", "AF",  "UDSF", "BSF",  "CHF",    "NWDAF", "UNKNOWN"};

typedef struct {
  uint8_t rand[16];
  uint8_t autn[16];
  uint8_t hxresStar[16];
  uint8_t kseaf[32];
} AUSF_AV_s;

typedef uint64_t supi64_t;

#define NAUSF_RG_AUTH "/rg-authentications"

#endif

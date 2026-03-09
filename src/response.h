#ifndef SRC_RESPONSE_H_
#define SRC_RESPONSE_H_

// Copyright [2017-2026] Orpheus

#include <string>

#include "ocelot.h"

const std::string http_response(const std::string &body, const client_opts_t &client_opts);
const std::string error(const std::string &message, const client_opts_t &client_opts);

#endif  // SRC_RESPONSE_H_

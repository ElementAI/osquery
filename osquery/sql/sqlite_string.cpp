/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <assert.h>

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <functional>
#include <string>
#include <vector>

#include <boost/algorithm/string/regex.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/regex.hpp>

#include "osquery/core/conversions.h"

#include <sqlite3.h>

namespace osquery {

using SplitResult = std::vector<std::string>;
using StringSplitFunction = std::function<SplitResult(
    const std::string& input, const std::string& tokens)>;
using StringReplaceFunction =
    std::function<std::string(const std::string& input,
                              const std::string& find_string,
                              const std::string& replace_with)>;

/**
 * @brief A simple SQLite column string split implementation.
 *
 * Split a column value using a single token and select an expected index.
 * If multiple characters are given to the token parameter, each is used to
 * split, similar to boost::is_any_of.
 *
 * Example:
 *   1. SELECT ip_address from addresses;
 *      192.168.0.1
 *   2. SELECT SPLIT(ip_address, ".", 1) from addresses;
 *      168
 *   3. SELECT SPLIT(ip_address, ".0", 0) from addresses;
 *      192
 */
static SplitResult tokenSplit(const std::string& input,
                              const std::string& tokens) {
  return osquery::split(input, tokens);
}

/**
 * @brief A regex SQLite column string split implementation.
 *
 * Split a column value using a single or multi-character token and select an
 * expected index. The token input is considered a regex.
 *
 * Example:
 *   1. SELECT ip_address from addresses;
 *      192.168.0.1
 *   2. SELECT SPLIT(ip_address, "\.", 1) from addresses;
 *      168
 *   3. SELECT SPLIT(ip_address, "\.0", 0) from addresses;
 *      192.168
 */
static SplitResult regexSplit(const std::string& input,
                              const std::string& token) {
  // Split using the token as a regex to support multi-character tokens.
  std::vector<std::string> result;
  boost::algorithm::split_regex(result, input, boost::regex(token));
  return result;
}

/**
 * @brief A regex SQLite column string replace implementation.
 *
 * Search into a column value using a single or multi-character pattern and
 * replace with a new substring. The pattern input is considered a regex.
 *
 * Example:
 *   1. SELECT path FROM processes WHERE name='osqueryi' LIMIT 1;
 *      /Users/osquery_dev/workspace/osquery/build/darwin/osquery/osqueryi
 *   2. SELECT regex_replace(path, '/Users/[^/]+/', './') FROM processes WHERE
 * name='osqueryi' LIMIT 1;
 *      ./workspace/osquery/build/darwin/osquery/osqueryi
 */
static std::string regexReplace(const std::string& input,
                                const std::string& pattern,
                                const std::string& replace_with) {
  return boost::regex_replace(input, boost::regex(pattern), replace_with);
}

static void callStringSplitFunc(sqlite3_context* context,
                                int argc,
                                sqlite3_value** argv,
                                StringSplitFunction f) {
  assert(argc == 3);
  if (SQLITE_NULL == sqlite3_value_type(argv[0]) ||
      SQLITE_NULL == sqlite3_value_type(argv[1]) ||
      SQLITE_NULL == sqlite3_value_type(argv[2])) {
    sqlite3_result_null(context);
    return;
  }

  // Parse and verify the split input parameters.
  std::string input((char*)sqlite3_value_text(argv[0]));
  std::string token((char*)sqlite3_value_text(argv[1]));
  auto index = static_cast<size_t>(sqlite3_value_int(argv[2]));
  if (token.empty()) {
    // Allow the input string to be empty.
    sqlite3_result_error(context, "Invalid input to split function", -1);
    return;
  }

  auto result = f(input, token);
  if (index >= result.size()) {
    // Could emit a warning about a selected index that is out of bounds.
    sqlite3_result_null(context);
    return;
  }

  // Yield the selected index.
  const auto& selected = result[index];
  sqlite3_result_text(context,
                      selected.c_str(),
                      static_cast<int>(selected.size()),
                      SQLITE_TRANSIENT);
}

static void tokenStringSplitFunc(sqlite3_context* context,
                                 int argc,
                                 sqlite3_value** argv) {
  callStringSplitFunc(context, argc, argv, tokenSplit);
}

static void regexStringSplitFunc(sqlite3_context* context,
                                 int argc,
                                 sqlite3_value** argv) {
  callStringSplitFunc(context, argc, argv, regexSplit);
}

static void callStringReplaceFunc(sqlite3_context* context,
                                  int argc,
                                  sqlite3_value** argv,
                                  StringReplaceFunction f) {
  assert(argc == 3);
  if (SQLITE_NULL == sqlite3_value_type(argv[0]) ||
      SQLITE_NULL == sqlite3_value_type(argv[1]) ||
      SQLITE_NULL == sqlite3_value_type(argv[2])) {
    sqlite3_result_null(context);
    return;
  }

  // Parse and verify the replace input parameters.
  std::string input((char*)sqlite3_value_text(argv[0]));
  std::string find_string((char*)sqlite3_value_text(argv[1]));
  std::string replace_with((char*)sqlite3_value_text(argv[2]));
  if (find_string.empty()) {
    // Check if the substring to find is empty.
    sqlite3_result_error(context, "Invalid substring to find in replace function", -1);
    return;
  }

  auto result = f(input, find_string, replace_with);

  sqlite3_result_text(context,
                      result.c_str(),
                      static_cast<int>(result.size()),
                      SQLITE_TRANSIENT);
}

static void regexStringReplaceFunc(sqlite3_context* context,
                                   int argc,
                                   sqlite3_value** argv) {
  callStringReplaceFunc(context, argc, argv, regexReplace);
}

/**
 * @brief Convert an IPv4 string address to decimal.
 */
static void ip4StringToDecimalFunc(sqlite3_context* context,
                                   int argc,
                                   sqlite3_value** argv) {
  assert(argc == 1);

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(context);
    return;
  }

  struct sockaddr sa;
  std::string address((char*)sqlite3_value_text(argv[0]));
  if (address.find(':') != std::string::npos) {
    // Assume this is an IPv6 address.
    sqlite3_result_null(context);
  } else {
    auto in4 = (struct sockaddr_in*)&sa;
    if (inet_pton(AF_INET, address.c_str(), &(in4->sin_addr)) == 1) {
      sqlite3_result_int64(context, ntohl(in4->sin_addr.s_addr));
    } else {
      sqlite3_result_null(context);
    }
  }
}

void registerStringExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "split",
                          3,
                          SQLITE_UTF8,
                          nullptr,
                          tokenStringSplitFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "regex_split",
                          3,
                          SQLITE_UTF8,
                          nullptr,
                          regexStringSplitFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "regex_replace",
                          3,
                          SQLITE_UTF8,
                          nullptr,
                          regexStringReplaceFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "inet_aton",
                          1,
                          SQLITE_UTF8,
                          nullptr,
                          ip4StringToDecimalFunc,
                          nullptr,
                          nullptr);
}
}

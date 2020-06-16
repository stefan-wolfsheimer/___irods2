#pragma once
#include <json.hpp>
#include <iostream>
#define PAMLOG_DEBUG 2
#define PAMLOG_INFO 1

#define PAM_CLIENT_LOG(LEVEL, X)                                      \
  {                                                                   \
    if(VERBOSE_LEVEL >= LEVEL)                                        \
    {                                                                 \
      std::cout << "PAM: " << __FILE__ << ":" << __LINE__ << " ";     \
      std::cout << X;                                                 \
      std::cout << std::endl;                                         \
    }                                                                 \
  }

namespace PamHandshake
{
  std::string get_conversation_file();
  std::string pam_input(const std::string & message, nlohmann::json & j, bool do_echo=true);
  std::string pam_input_password(const std::string & message, nlohmann::json & j, bool do_echo=true);
  void save_conversation(const nlohmann::json & json_conversation, int VERBOSE_LEVEL);
  nlohmann::json load_conversation(int VERBOSE_LEVEL);
}

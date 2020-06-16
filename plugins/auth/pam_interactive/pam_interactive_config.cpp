#include <string>
#include <iostream>
#include <fstream>
#include <json.hpp>
#include <termios.h>
#include "getRodsEnv.h"
#include "pam_interactive_config.h"
#include "authenticate.h"
#include "obf.h"
#include "rodsErrorTable.h"

//@todo make configurable and share between client and server
#define OBF_KEY "1234567890"

static std::string extract_default_value(const std::string & message,
                                         nlohmann::json & j)
{
  if(j.contains(message))
  {
    if(j[message].is_string())
    {
      return j[message].get<std::string>();
    }
    else if(j[message].is_object() &&
            j[message].contains("answer") &&
            j[message]["answer"].is_string())
    {
      if(j[message].contains("scrambled") &&
         j[message]["scrambled"].get<bool>())
      {
        //@todo length check!
        std::string answer(j[message]["answer"].get<std::string>());
        if(answer.size() > MAX_PASSWORD_LEN + 9)
        {
          throw std::runtime_error("password too long");
        }
        char * pw = new char[answer.size() + 1];
        obfDecodeByKey(answer.c_str(),
                       OBF_KEY,
                       pw);
        std::string ret(pw);
        delete [] pw;
        return ret;
      }
      else
      {
        return j[message]["answer"].get<std::string>();
      }
    }
  }
  return std::string("");
}

std::string PamHandshake::pam_input(const std::string & message,
                                    nlohmann::json & j,
                                    bool do_echo)
{
  std::string default_value;
  try
  {
    default_value = extract_default_value(message, j);
  }
  catch(const std::exception & ex)
  {
  }
  std::string answer;
  if(default_value.empty() || do_echo)
  {
    std::cout << message;
    if(!default_value.empty())
    {
      std::cout << "[" << default_value << "]";
    }
    std::getline(std::cin, answer);
  }
  if(answer.empty())
  {
    answer = default_value;
  }
  j[message] = {{"answer", answer},
                {"scrambled", false}};
  return answer;
}

std::string PamHandshake::pam_input_password(const std::string & message,
                                             nlohmann::json & j,
                                             bool do_echo)
{
  std::string default_value;
  try
  {
    default_value = extract_default_value(message, j);
  }
  catch(const std::exception & ex)
  {
  }
  std::string answer;
  if(default_value.empty() || do_echo)
  {
    std::cout << message;
    if(!default_value.empty())
    {
      std::cout << "[****]";
    }
  }
#ifdef WIN32
  HANDLE hStdin = GetStdHandle( STD_INPUT_HANDLE );
  DWORD mode;
  GetConsoleMode( hStdin, &mode );
  DWORD lastMode = mode;
  mode &= ~ENABLE_ECHO_INPUT;
  BOOL error = !SetConsoleMode( hStdin, mode );
  int errsv = -1;
#else
  struct termios tty;
  tcgetattr( STDIN_FILENO, &tty );
  tcflag_t oldflag = tty.c_lflag;
  tty.c_lflag &= ~ECHO;
  int error = tcsetattr( STDIN_FILENO, TCSANOW, &tty );
  int errsv = errno;
  if(error)
  {
    printf( "WARNING: Error %d disabling echo mode. Password will be displayed in plaintext.", errsv );
  }
#endif
  if(default_value.empty() || do_echo)
  {
    std::getline(std::cin, answer);
  }
#ifdef WIN32
  if (!SetConsoleMode(hStdin, lastMode))
  {
    printf( "Error reinstating echo mode." );
  }
#else
  tty.c_lflag = oldflag;
  if ( tcsetattr( STDIN_FILENO, TCSANOW, &tty ) )
  {
    printf( "Error reinstating echo mode." );
  }
#endif
  if(default_value.empty() || do_echo)
  {
    std::cout << std::endl << std::flush;
  }
  if(answer.empty())
  {
    answer = default_value;
  }
  if(answer.size() > MAX_PASSWORD_LEN)
  {
    answer.erase(MAX_PASSWORD_LEN);
  }
  char * pw = new char[answer.size() + 10];
  obfEncodeByKey(answer.c_str(),
                 OBF_KEY,
                 pw);
  j[message] = {{"answer", std::string(pw)},
                {"scrambled", true}};
  delete [] pw;
  return answer;
}

std::string PamHandshake::get_conversation_file()
{
  char *envVar = getRodsEnvAuthFileName();
  if(envVar && *envVar != '\0')
  {
    return std::string(envVar);
  }
  else
  {
    return std::string(getenv( "HOME" )) + "/.irods/.irodsA.json";
  }
}

void PamHandshake::save_conversation(const nlohmann::json & json_conversation, int VERBOSE_LEVEL)
{
  std::string file_name(get_conversation_file());
  PAM_CLIENT_LOG(PAMLOG_INFO, "SAVE conversation: " << file_name);
  std::ofstream file(file_name.c_str());
  if (file.is_open())
  {
    file << json_conversation;
    file.close();
  }
  else
  {
    throw std::runtime_error((std::string("cannot write to  file ") + file_name).c_str());
  }
}

nlohmann::json PamHandshake::load_conversation(int VERBOSE_LEVEL)
{
  nlohmann::json json_conversation;
  std::string file_name(get_conversation_file());
  PAM_CLIENT_LOG(PAMLOG_INFO, "LOAD  conversation: " << file_name);
  std::ifstream file(file_name.c_str());
  if (file.is_open())
  {
    file >> json_conversation;
    file.close();
    return json_conversation;
  }
  else
  {
    return "{}"_json;
  }
}


  

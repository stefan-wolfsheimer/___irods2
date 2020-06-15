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

std::string pam_input(const std::string & message, nlohmann::json & j)
{
  std::string answer;
  std::cout << message;
  std::getline(std::cin, answer);
  j[message] = {{"answer", answer},
                {"scrambled", false}};
  return answer;
}

std::string pam_input_password(const std::string & message, nlohmann::json & j)
{
  std::string answer;
  std::cout << message;
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

  std::getline(std::cin, answer);

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
  std::cout << std::endl << std::flush;
  ///@todo :move obfi to external module
  //update_pam_message(message, answer, true);
  if(answer.size() > MAX_PASSWORD_LEN)
  {
    answer.erase(MAX_PASSWORD_LEN);
  }
  char myPw[MAX_PASSWORD_LEN + 10];
  int envVal = obfiGetEnvKey();
  obfiEncode(answer.c_str(),  myPw, envVal);
  j[message] = {{"answer", std::string(myPw)},
                {"scrambled", true}};
  return answer;
}

static std::string get_conversation_file()
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

int save_conversation(const nlohmann::json & json_conversation, int VERBOSE_LEVEL)
{
  std::string file_name(get_conversation_file());
  PAM_CLIENT_LOG(PAMLOG_INFO, "SAVE conversation: " << file_name);
  std::ofstream file(file_name.c_str());
  if (file.is_open())
  {
    file << json_conversation;
    file.close();
    return 0;
  }
  else
  {
    return SYS_INVALID_INPUT_PARAM;
  }
}


  

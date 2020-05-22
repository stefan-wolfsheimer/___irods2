// =-=-=-=-=-=-=-
// irods includes
#define USE_SSL 1
#include "sslSockComm.h"

#include "rodsDef.h"
#include "msParam.h"
#include "rcConnect.h"
#include "authRequest.h"
#include "authResponse.h"
#include "authCheck.h"
#include "miscServerFunct.hpp"
#include "authPluginRequest.h"
#include "icatHighLevelRoutines.hpp"

// =-=-=-=-=-=-=-
#include "irods_auth_plugin.hpp"
#include "irods_auth_constants.hpp"
#include "irods_pam_interactive_auth_object.hpp"
#include "irods_stacktrace.hpp"
#include "irods_kvp_string_parser.hpp"
#include "irods_client_server_negotiation.hpp"

// =-=-=-=-=-=-=-
// boost includes
#include "boost/lexical_cast.hpp"

// =-=-=-=-=-=-=-
// stl includes
#include <sstream>
#include <string>
#include <iostream>
#include <termios.h>
#include <unistd.h>

// =-=-=-=-=-=-=-
// system includes
#include <sys/types.h>
#include <sys/wait.h>

#ifdef RODS_SERVER
#include <curl/curl.h>
#include "handshake_client.h"
#endif

int get64RandomBytes( char *buf );

irods::error pam_auth_client_start(irods::plugin_context& _ctx, rcComm_t* _comm, const char* _context )
{
  irods::error result = SUCCESS();
  irods::error ret;
  // =-=-=-=-=-=-=-
  // validate incoming parameters
  ret = _ctx.valid< irods::pam_interactive_auth_object >();
  if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() ) {
    if ( ( result = ASSERT_ERROR( _comm, SYS_INVALID_INPUT_PARAM, "Null comm pointer." ) ).ok() ) {
#if 0
      if ( ( result = ASSERT_ERROR( _context, SYS_INVALID_INPUT_PARAM, "Null context pointer." ) ).ok() ) {
        // =-=-=-=-=-=-=-
        // parse the kvp out of the _resp->username string

        irods::kvp_map_t kvp;
        irods::error ret = irods::parse_escaped_kvp_string( _context, kvp );
        if ( ( result = ASSERT_PASS( ret, "Failed to parse the key-value pairs." ) ).ok() ) {
          // =-=-=-=-=-=-=-
          // simply cache the context string for a rainy day...
          // or to pass to the auth client call later.
          irods::pam_interactive_auth_object_ptr ptr = boost::dynamic_pointer_cast<
            irods::pam_interactive_auth_object>(
                                                _ctx.fco() );
          ptr->context(_context);

          std::string password = kvp[ irods::AUTH_PASSWORD_KEY ];
          std::string ttl_str  = kvp[ irods::AUTH_TTL_KEY ];

          // =-=-=-=-=-=-=-
          // prompt for a password if necessary
          char new_password[ MAX_PASSWORD_LEN + 2 ];
          if ( password.empty() ) {
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
#endif
            if ( error ) {
              printf( "WARNING: Error %d disabling echo mode. Password will be displayed in plaintext.", errsv );
            }
            printf( "Enter your current PAM password:" );
            std::string password = "";
            getline( std::cin, password );
            strncpy( new_password, password.c_str(), MAX_PASSWORD_LEN );
            printf( "\n" );
#ifdef WIN32
            if ( !SetConsoleMode( hStdin, lastMode ) ) {
              printf( "Error reinstating echo mode." );
            }
#else
            tty.c_lflag = oldflag;
            if ( tcsetattr( STDIN_FILENO, TCSANOW, &tty ) ) {
              printf( "Error reinstating echo mode." );
            }
#endif

            // =-=-=-=-=-=-=-
            // rebuilt and reset context string
            irods::kvp_map_t ctx_map;
            ctx_map[irods::AUTH_TTL_KEY] = ttl_str;
            ctx_map[irods::AUTH_PASSWORD_KEY] = new_password;
            std::string ctx_str = irods::escaped_kvp_string(
                                                            ctx_map);
            ptr->context( ctx_str );

          }

          // =-=-=-=-=-=-=-
          // set the user name from the conn
          ptr->user_name( _comm->proxyUser.userName );

          // =-=-=-=-=-=-=-
          // set the zone name from the conn
          ptr->zone_name( _comm->proxyUser.rodsZone );
        }
      }
#endif
    }
  }
  return result;
} // pam_auth_client_start


static std::tuple<int, std::string> pam_auth_get_session(rcComm_t* _comm)
{
  authPluginReqInp_t req_in;
  authPluginReqOut_t* req_out = 0;
  std::string res;
  std::string ctx_str = irods::escaped_kvp_string(irods::kvp_map_t{{"METHOD", "POST"}});
  strncpy(req_in.context_, ctx_str.c_str(), ctx_str.size() + 1 );
  strncpy(req_in.auth_scheme_, irods::AUTH_PAM_INTERACTIVE_SCHEME.c_str(), irods::AUTH_PAM_INTERACTIVE_SCHEME.size() + 1 );
  int status = rcAuthPluginRequest( _comm, &req_in, &req_out );
  if(req_out)
  {
    res = req_out->result_;
    free(req_out);
  }
  if(status == 0)
  {
    irods::kvp_map_t kvp;
    irods::error ret = irods::parse_escaped_kvp_string(res, kvp);
    if ( !ret.ok() )
    {
      return std::make_tuple(SYS_INVALID_INPUT_PARAM, "cannot decode kvp");
    }
    {
      auto itr = kvp.find("CODE");
      if(itr == kvp.end())
      {
        return std::make_tuple(SYS_INVALID_INPUT_PARAM, "SESSION key missing");
      }
      if(itr->second != "200")
      {
        std::string msg = std::string("http code:") + itr->second;
        return std::make_tuple(-1, msg);
      }
    }
    {
      auto itr = kvp.find("SESSION");
      if(itr == kvp.end())
      {
        return std::make_tuple(SYS_INVALID_INPUT_PARAM, "SESSION key missing");
      }
      else
      {
        return std::make_tuple(0, itr->second);
      }
    }
  }
  else
  {
    return std::make_tuple(status, "request failed");
  }
}

static bool pam_auth_delete_session(rcComm_t* _comm, const std::string & session)
{
  authPluginReqInp_t req_in;
  authPluginReqOut_t* req_out = 0;
  std::string res;
  std::string ctx_str = irods::escaped_kvp_string(irods::kvp_map_t{
      {"METHOD", "DELETE"},
      {"SESSION", session}});
  strncpy(req_in.context_, ctx_str.c_str(), ctx_str.size() + 1 );
  strncpy(req_in.auth_scheme_, irods::AUTH_PAM_INTERACTIVE_SCHEME.c_str(), irods::AUTH_PAM_INTERACTIVE_SCHEME.size() + 1 );
  int status = rcAuthPluginRequest( _comm, &req_in, &req_out );
  if(req_out)
  {
    res = req_out->result_;
    free(req_out);
  }
  if(status == 0)
  {
     irods::kvp_map_t kvp;
     irods::error ret = irods::parse_escaped_kvp_string(res, kvp);
     if ( !ret.ok() )
     {
       return false; 
     }
     auto itr = kvp.find("CODE");
     if(itr == kvp.end() || itr->second != "200")
     {
       return false;
     }
  }
  else
  {
    return false;
  }
  return true;
}

#define PATH_CLIENT_LOG(X) { std::cout << X; std::cout << std::endl; }
//#define PATH_CLIENT_LOG(X)
std::string pam_input(const std::string & message)
{
  std::string answer;
  std::cout << message;
  std::getline(std::cin, answer);
  return answer;
}

std::string pam_input_password(const std::string & message)
{
  std::string answer;
  std::cout << message;
  std::getline(std::cin, answer);
  return answer;
}

irods::error pam_auth_client_request(irods::plugin_context& _ctx, rcComm_t* _comm )
{
    if(!_ctx.valid< irods::pam_interactive_auth_object >().ok())
    {
      return ERROR(SYS_INVALID_INPUT_PARAM, "invalid plugin context" );
    }
    else if(!_comm)
    {
      return ERROR(SYS_INVALID_INPUT_PARAM, "null comm ptr" );
    }
    irods::pam_interactive_auth_object_ptr ptr = boost::dynamic_pointer_cast <irods::pam_interactive_auth_object >(_ctx.fco());
    bool using_ssl = (irods::CS_NEG_USE_SSL == _comm->negotiation_results );
    if ( !using_ssl )
    {
      int err = sslStart( _comm );
      if ( err )
      {
        return ERROR( -1, "failed to enable ssl" );
      }
    }
    std::string session;
    int status = 0;
    std::tie(status, session) = pam_auth_get_session(_comm);
    bool active = true;
    std::string answer;
    std::string err_msg;
    bool conversation_done = false;
    bool authenticated = false;
    while(active && (status == 0))
    {
      authPluginReqInp_t req_in;
      authPluginReqOut_t* req_out = 0;
      irods::kvp_map_t kvp;
      std::string ctx_str = irods::escaped_kvp_string(irods::kvp_map_t{
          {"METHOD", "PUT"},
          {"SESSION", session},
          {"ANSWER", answer}});
      PATH_CLIENT_LOG("REQUEST:" << ctx_str);
      strncpy(req_in.context_, ctx_str.c_str(), ctx_str.size() + 1 );
      strncpy(req_in.auth_scheme_, irods::AUTH_PAM_INTERACTIVE_SCHEME.c_str(), irods::AUTH_PAM_INTERACTIVE_SCHEME.size() + 1 );
      status = rcAuthPluginRequest( _comm, &req_in, &req_out );
      if(status < 0)
      {
        if(req_out)
        {
          free(req_out);
        }
        break;
      }
      irods::error ret = irods::parse_escaped_kvp_string(std::string(req_out->result_), kvp);
      if ( !ret.ok() )
      {
        PATH_CLIENT_LOG("PARSING FAILED: " << req_out->result_);
        status = -1;
        break;
      }
      auto itr = kvp.find("CODE");
      if(itr == kvp.end())
      {
        PATH_CLIENT_LOG("HTTP CODE not returned");
        status = -1;
        break;
      }
      if(itr->second != "200" && itr->second != "401" && itr->second != "202")
      {
        PATH_CLIENT_LOG("HTTP CODE " << itr->second);
        status = -1;
        break;
      }
      auto sitr = kvp.find("STATE");
      if(sitr == kvp.end())
      {
        PATH_CLIENT_LOG("STATE not returned");
        status = -1;
        break;
      }
      PATH_CLIENT_LOG("STATE:" << sitr->second);
      auto mitr = kvp.find("MESSAGE");
      if(sitr->second == "WAITING")
      {
        answer = pam_input(((mitr == kvp.end()) ? std::string("") : mitr->second));
      }
      else if(sitr->second == "WAITING_PW")
      {
        answer = pam_input_password(((mitr == kvp.end()) ? std::string("") : mitr->second));
      }
      else if(sitr->second == "NOT_AUTHENTICATED")
      {
        status = 0;
        active = false;
        conversation_done = true;
        authenticated = false;
      }
      else if(sitr->second =="STATE_AUTHENTICATED")
      {
        status = 0;
        active = false;
        conversation_done = true;
        authenticated = true;
      }
      else if(sitr->second == "ERROR")
      {
        status = -1;
        active = false;
        err_msg = std::string("PAM error: ");
        if(mitr != kvp.end())
        {
          err_msg += mitr->second;
        }
      }
      else if(sitr->second == "TIMEOUT")
      {
        status = -1;
        active = false;
        err_msg = std::string("PAM timeout");
      }
      else if(sitr->second == "NEXT")
      {
        if(mitr != kvp.end())
        {
          if(!mitr->second.empty())
          {
            std::cout << mitr->second << std::endl;
          }
        }
      }
      else
      {
        status = -1;
        err_msg = std::string("invalid state '") + sitr->second + "'";
      }
    }
    PATH_CLIENT_LOG("CONVERSATION ERR MSG:" << err_msg);
    PATH_CLIENT_LOG("DELETE SESSION");
    if(!pam_auth_delete_session(_comm, session))
    {
      PATH_CLIENT_LOG("DELETE SESSION: FAILED");
      if(status == 0)
      {
        status = -1;
      }
    }
    if(!using_ssl )
    {
      PATH_CLIENT_LOG("SSL_END");
      sslEnd( _comm );
    }
    else
    {
      PATH_CLIENT_LOG("CONTINUE SSL");
    }
    if(status < 0 || !conversation_done)
    {
      if(status == 0)
      {
        status = -1;
      }
      PATH_CLIENT_LOG("ERROR: " << err_msg);
      return ERROR(status, err_msg.c_str());
    }
    else
    {
      PATH_CLIENT_LOG("CONVERSATION DONE");
      if(authenticated)
      {
        PATH_CLIENT_LOG("PAM AUTH CHECK SUCCESS");
        return SUCCESS();
#if 0
        // =-=-=-=-=-=-=-
        // copy over the resulting irods pam pasword
        // and cache the result in our auth object
        ptr->request_result( req_out->result_ );
        status = obfSavePw( 0, 0, 0, req_out->result_ );
#endif

      }
      else
      {
        PATH_CLIENT_LOG("PAM AUTH CHECK FAILED");
        return ERROR( PAM_AUTH_PASSWORD_FAILED, "pam auth check failed" );
      }
      //free( req_out );
    }
} // pam_auth_client_request

irods::error pam_auth_client_response(irods::plugin_context& _ctx,
                                      rcComm_t* _comm )
{
  return SUCCESS();
}

irods::error pam_auth_establish_context(irods::plugin_context& _ctx )
{
  if(!_ctx.valid< irods::pam_interactive_auth_object >().ok())
  {
    return ERROR(SYS_INVALID_INPUT_PARAM, "invalid plugin context" );
  }
  return SUCCESS();
}

#ifdef RODS_SERVER
irods::error pam_auth_agent_request(irods::plugin_context& _ctx )
{
  bool unixSocket = true;
  bool verbose = true;
  long port = 8080;
  std::string addr = "/var/pam_handshake.socket";
  int http_code;
  std::string session;
#if 0
    // @Todo
    // =-=-=-=-=-=-=-
    // validate incoming parameters
    if ( !_ctx.valid< irods::pam_interactive_auth_object >().ok() )
    {
        return ERROR( SYS_INVALID_INPUT_PARAM, "invalid plugin context" );
    }
#endif
    // =-=-=-=-=-=-=-
    // get the server host handle
    rodsServerHost_t* server_host = 0;
    int status = getAndConnRcatHost(_ctx.comm(),
                                    MASTER_RCAT,
                                    ( const char* )_ctx.comm()->clientUser.rodsZone,
                                    &server_host );
    if ( status < 0 )
    {
      return ERROR( status, "getAndConnRcatHost failed." );
    }

    irods::pam_interactive_auth_object_ptr ptr = boost::dynamic_pointer_cast <irods::pam_interactive_auth_object >(_ctx.fco());
    std::string context = ptr->context( );

    // =-=-=-=-=-=-=-
    // if we are not the catalog server, redirect the call
    // to there
    if ( server_host->localFlag != LOCAL_HOST )
    {
      // =-=-=-=-=-=-=-
      // protect the PAM plain text password by
      // using an SSL connection to the remote ICAT
      status = sslStart( server_host->conn );
      if ( status )
      {
        return ERROR( status, "could not establish SSL connection" );
      }
      // =-=-=-=-=-=-=-
      // manufacture structures for the redirected call
      authPluginReqOut_t* req_out = 0;
      authPluginReqInp_t  req_inp;
      strncpy( req_inp.auth_scheme_, irods::AUTH_PAM_INTERACTIVE_SCHEME.c_str(), irods::AUTH_PAM_INTERACTIVE_SCHEME.size() + 1 );
      strncpy( req_inp.context_, context.c_str(), context.size() + 1 );
      status = rcAuthPluginRequest( server_host->conn, &req_inp, &req_out );
      sslEnd( server_host->conn );
      rcDisconnect( server_host->conn );
      server_host->conn = NULL;
      if ( !req_out || status < 0 )
      {
        return ERROR( status, "redirected rcAuthPluginRequest failed." );
      }
      else
      {
        ptr->request_result( req_out->result_ );
        if ( _ctx.comm()->auth_scheme != NULL )
        {
          free( _ctx.comm()->auth_scheme );
        }
        _ctx.comm()->auth_scheme = strdup( irods::AUTH_PAM_INTERACTIVE_SCHEME.c_str() );
        return SUCCESS();
      }
    } // if !localhost
    irods::kvp_map_t kvp;
    irods::error ret = irods::parse_escaped_kvp_string(context, kvp);
    if ( !ret.ok() )
    {
      return PASS( ret );
    }
    try
    {
      auto itr = kvp.find("METHOD");
      if(itr == kvp.end())
      {
        return ERROR(SYS_INVALID_INPUT_PARAM, "METHOD key missing");
      }
      else if(itr->second == "POST")
      {
        std::tie(http_code, session) = PamHandshake::open_pam_handshake_session(unixSocket,
                                                                                addr,
                                                                                port,
                                                                                verbose);
        ptr->request_result(irods::escaped_kvp_string(irods::kvp_map_t{
              {"SESSION", session},
              {"CODE", std::to_string(http_code)}}).c_str());
        return SUCCESS();
      }
      else
      {
        std::string state_str;
        std::string message;
        auto sitr = kvp.find("SESSION");
        if(sitr == kvp.end())
        {
          return ERROR(SYS_INVALID_INPUT_PARAM, "SESSION key missing");
        }
        session = sitr->second;
        if(itr->second == "GET")
        {
          std::tie(http_code,
                   state_str,
                   message) = PamHandshake::pam_handshake_get(unixSocket,
                                                              addr,
                                                              port,
                                                              session,
                                                              verbose);
          ptr->request_result(irods::escaped_kvp_string(irods::kvp_map_t{
                {"SESSION", session},
                {"CODE", std::to_string(http_code)},
                {"STATE", state_str},
                {"MESSAGE", message}
              }).c_str());
          return SUCCESS();
        }
        else if(itr->second == "PUT")
        {
          auto aitr = kvp.find("ANSWER");
          std::tie(http_code,
                   state_str,
                   message) = PamHandshake::pam_handshake_put(unixSocket,
                                                              addr,
                                                              port,
                                                              session,
                                                              ((aitr == kvp.end()) ? std::string("") : aitr->second),
                                                              verbose);
          ptr->request_result(irods::escaped_kvp_string(irods::kvp_map_t{
                {"SESSION", session},
                {"CODE", std::to_string(http_code)},
                {"STATE", state_str},
                {"MESSAGE", message}
              }).c_str());
          return SUCCESS();
        }
        else if(itr->second == "DELETE")
        {
          http_code = PamHandshake::pam_handshake_delete(unixSocket,
                                                         addr,
                                                         port,
                                                         session,
                                                         verbose);
          ptr->request_result(irods::escaped_kvp_string(irods::kvp_map_t{
                {"SESSION", session},
                {"CODE", std::to_string(http_code)}}).c_str());
          return SUCCESS();
        }
        else
        {
          std::string msg("invalid METHOD '");
          msg+= itr->second;
          msg+= "'";
          return ERROR(SYS_INVALID_INPUT_PARAM, msg.c_str());
        }
      }
    }
    catch(const std::exception & ex)
    {
      //@todo error handling
      rodsLog(LOG_ERROR, "open_pam_handshake_session: %s", ex.what());
      return ERROR( -1, ex.what() );
    }
} // pam_auth_agent_request
#endif

#ifdef RODS_SERVER
irods::error pam_auth_agent_start(irods::plugin_context&, const char*)
{
    return SUCCESS();
}
#endif

#ifdef RODS_SERVER
irods::error pam_auth_agent_response(irods::plugin_context& _ctx, authResponseInp_t* _resp )
{
  return SUCCESS();
}
#endif

#ifdef RODS_SERVER
irods::error pam_auth_agent_verify(irods::plugin_context& ,
                                   const char* ,
                                   const char* ,
                                   const char* )
{
  return SUCCESS();
}
#endif

// =-=-=-=-=-=-=-
// derive a new pam_auth auth plugin from
// the auth plugin base class for handling
// native authentication
class pam_interactive_auth_plugin : public irods::auth {
    public:
        pam_interactive_auth_plugin(
            const std::string& _nm,
            const std::string& _ctx ) :
            irods::auth(
                _nm,
                _ctx ) {
        } // ctor

        ~pam_interactive_auth_plugin() {
        }

}; // class pam_auth_plugin

// =-=-=-=-=-=-=-
// factory function to provide instance of the plugin
extern "C"
irods::auth* plugin_factory(
    const std::string& _inst_name,
    const std::string& _context ) {
#ifdef RODS_SERVER
    curl_global_init(CURL_GLOBAL_ALL);
#endif
    // =-=-=-=-=-=-=-
    // create an auth object
    pam_interactive_auth_plugin* pam = new pam_interactive_auth_plugin(
        _inst_name,
        _context );

    // =-=-=-=-=-=-=-
    // fill in the operation table mapping call
    // names to function names
    using namespace irods;
    using namespace std;
    pam->add_operation(
        AUTH_ESTABLISH_CONTEXT,
        function<error(plugin_context&)>(
            pam_auth_establish_context ) );
    pam->add_operation<rcComm_t*,const char*>(
        AUTH_CLIENT_START,
        function<error(plugin_context&,rcComm_t*,const char*)>(
            pam_auth_client_start ) );
    pam->add_operation<rcComm_t*>(
        AUTH_CLIENT_AUTH_REQUEST,
        function<error(plugin_context&,rcComm_t*)>(
            pam_auth_client_request ) );
    pam->add_operation<rcComm_t*>(
        AUTH_CLIENT_AUTH_RESPONSE,
        function<error(plugin_context&,rcComm_t*)>(
            pam_auth_client_response ) );
#ifdef RODS_SERVER
    pam->add_operation<const char*>(
        AUTH_AGENT_START,
        function<error(plugin_context&,const char*)>(
            pam_auth_agent_start ) );
    pam->add_operation(
        AUTH_AGENT_AUTH_REQUEST,
        function<error(plugin_context&)>(
            pam_auth_agent_request )  );
    pam->add_operation<authResponseInp_t*>(
        AUTH_AGENT_AUTH_RESPONSE,
        function<error(plugin_context&,authResponseInp_t*)>(
            pam_auth_agent_response ) );
    pam->add_operation<const char*,const char*,const char*>(
        AUTH_AGENT_AUTH_VERIFY,
        function<error(plugin_context&,const char*,const char*,const char*)>(
            pam_auth_agent_verify ) );
#endif
    irods::auth* auth = dynamic_cast< irods::auth* >( pam );

    return auth;

} // plugin_factory

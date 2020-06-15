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
#include <unistd.h>

// =-=-=-=-=-=-=-
// system includes
#include <sys/types.h>
#include <sys/wait.h>

// 3rd party library
#include <json.hpp>


#ifdef RODS_SERVER
#include <curl/curl.h>
#include "handshake_client.h"
#endif
#include "pam_interactive_config.h"

int get64RandomBytes( char *buf );

irods::error pam_auth_client_start(irods::plugin_context& _ctx,
                                   rcComm_t* _comm,
                                   const char* _context )
{
  irods::error result = SUCCESS();
  irods::error ret;
  // =-=-=-=-=-=-=-
  // validate incoming parameters
  ret = _ctx.valid< irods::pam_interactive_auth_object >();
  if ( ( result = ASSERT_PASS( ret, "Invalid plugin context." ) ).ok() )
  {
    if ( ( result = ASSERT_ERROR( _comm, SYS_INVALID_INPUT_PARAM, "Null comm pointer." ) ).ok() )
    {
      if ( ( result = ASSERT_ERROR( _context, SYS_INVALID_INPUT_PARAM, "Null context pointer." ) ).ok() )
      {
        auto ptr = boost::dynamic_pointer_cast<irods::pam_interactive_auth_object>(_ctx.fco());

        // =-=-=-=-=-=-=-
        // set the user name from the conn
        ptr->user_name( _comm->proxyUser.userName );

        // =-=-=-=-=-=-=-
        // set the zone name from the conn
        ptr->zone_name( _comm->proxyUser.rodsZone );
        ptr->context(std::string(_context));
        irods::kvp_map_t kvp;
        irods::error ret = irods::parse_escaped_kvp_string(_context, kvp);
        if ( !ret.ok() )
        {
          return ERROR(SYS_INVALID_INPUT_PARAM, "cannot decode kvp");
        }
        auto itr = kvp.find("VVERBOSE");
        if(itr != kvp.end() && itr->second == "true")
        {
          ptr->verbose_level(2);
        }
        else
        {
          itr = kvp.find("VERBOSE");
          if(itr != kvp.end() && itr->second == "true")
          {
            ptr->verbose_level(1);
          }
          else
          {
            ptr->verbose_level(0);
          }
        }
        int VERBOSE_LEVEL = ptr->verbose_level();
        PAM_CLIENT_LOG(PAMLOG_DEBUG, "pam_auth_client_start " << _context);
        PAM_CLIENT_LOG(PAMLOG_DEBUG, "verbose level " << VERBOSE_LEVEL);
      } // if context not null ptr
    } // if comm not null ptr
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
    nlohmann::json json_conversation;
    irods::pam_interactive_auth_object_ptr ptr = boost::dynamic_pointer_cast <irods::pam_interactive_auth_object >(_ctx.fco());
    bool using_ssl = (irods::CS_NEG_USE_SSL == _comm->negotiation_results );
    int VERBOSE_LEVEL = ptr->verbose_level();
    PAM_CLIENT_LOG(PAMLOG_DEBUG, "pam_auth_client_start " << ptr->context());
    PAM_CLIENT_LOG(PAMLOG_DEBUG, "verbose level " << VERBOSE_LEVEL);
    if ( !using_ssl )
    {
      PAM_CLIENT_LOG(PAMLOG_DEBUG, "sslStart");
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
      if(VERBOSE_LEVEL >= PAMLOG_DEBUG)
      {
        std::string dbg_ctx_str = irods::escaped_kvp_string(irods::kvp_map_t{
          {"METHOD", "PUT"},
          {"SESSION", session},
          {"ANSWER", "***"}});
        PAM_CLIENT_LOG(PAMLOG_DEBUG, "REQUEST:" << dbg_ctx_str);
      }

      if((ctx_str.size() + 1) > MAX_NAME_LEN)
      {
        std::cerr << "input lenght exceeded (" << ctx_str.size() << ">=" << MAX_NAME_LEN << ")"
                  << std::endl;
        status = SYS_BAD_INPUT;
        break;
      }
      strncpy(req_in.context_, ctx_str.c_str(), ctx_str.size() + 1 );
      strncpy(req_in.auth_scheme_,
              irods::AUTH_PAM_INTERACTIVE_SCHEME.c_str(),
              irods::AUTH_PAM_INTERACTIVE_SCHEME.size() + 1 );
      status = rcAuthPluginRequest( _comm, &req_in, &req_out );
      if(status < 0)
      {
        if(req_out)
        {
          free(req_out);
        }
        if(status == PAM_AUTH_PASSWORD_FAILED)
        {
          conversation_done = true;
          authenticated = false;
        }
        break;
      }
      irods::error ret = irods::parse_escaped_kvp_string(std::string(req_out->result_), kvp);
      if ( !ret.ok() )
      {
        PAM_CLIENT_LOG(PAMLOG_INFO, "PARSING FAILED: " << req_out->result_);
        status = -1;
        break;
      }
      auto itr = kvp.find("CODE");
      if(itr == kvp.end())
      {
        PAM_CLIENT_LOG(PAMLOG_INFO, "HTTP CODE not returned");
        status = -1;
        break;
      }
      if(itr->second != "200" && itr->second != "401" && itr->second != "202")
      {
        PAM_CLIENT_LOG(PAMLOG_INFO, "HTTP CODE " << itr->second);
        status = -1;
        break;
      }
      auto sitr = kvp.find("STATE");
      if(sitr == kvp.end())
      {
        PAM_CLIENT_LOG(PAMLOG_INFO, "STATE not returned");
        status = -1;
        break;
      }
      PAM_CLIENT_LOG(PAMLOG_INFO, "STATE:" << sitr->second);
      auto mitr = kvp.find("MESSAGE");
      if(sitr->second == "WAITING")
      {
        answer = pam_input(((mitr == kvp.end()) ? std::string("") : mitr->second),
                           json_conversation);
      }
      else if(sitr->second == "WAITING_PW")
      {
        answer = pam_input_password(((mitr == kvp.end()) ? std::string("") : mitr->second),
                                    json_conversation);
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
    if(!err_msg.empty())
    {
      PAM_CLIENT_LOG(PAMLOG_INFO, "CONVERSATION ERR MSG:" << err_msg);
    }
    if(!using_ssl )
    {
      PAM_CLIENT_LOG(PAMLOG_DEBUG, "SSL_END");
      sslEnd( _comm );
    }
    else
    {
      PAM_CLIENT_LOG(PAMLOG_DEBUG, "CONTINUE SSL");
    }
    if(status < 0 || !conversation_done)
    {
      PAM_CLIENT_LOG(PAMLOG_DEBUG,
                     "ERROR: " << err_msg <<
                     " status:" << status <<
                     " conversation done:" << conversation_done);
      if(status == 0)
      {
        status = -1;
      }
      return ERROR(status, err_msg.c_str());
    }
    else
    {
      PAM_CLIENT_LOG(PAMLOG_DEBUG, "CONVERSATION DONE");
      if(authenticated)
      {
        PAM_CLIENT_LOG(PAMLOG_DEBUG, "PAM AUTH CHECK SUCCESS");
        // =-=-=-=-=-=-=-
        // and cache the result in our auth object
        std::stringstream ss;
        ss << json_conversation;
        ptr->request_result(ss.str().c_str());
        status = save_conversation(json_conversation, VERBOSE_LEVEL);
        if(status != 0)
        {
          return ERROR(status, "failed to save conversation" );
        }
        else
        {
          return SUCCESS();
        }
      }
      else
      {
        PAM_CLIENT_LOG(PAMLOG_DEBUG, "PAM AUTH CHECK FAILED");
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
          if(state_str == "NOT_AUTHENTICATED" ||
             state_str == "STATE_AUTHENTICATED" ||
             state_str == "ERROR" ||
             state_str == "TIMEOUT")
          {
            PamHandshake::pam_handshake_delete(unixSocket,
                                               addr,
                                               port,
                                               session,
                                               verbose);
          }
          ptr->request_result(irods::escaped_kvp_string(irods::kvp_map_t{
                {"SESSION", session},
                {"CODE", std::to_string(http_code)},
                {"STATE", state_str},
                {"MESSAGE", message}
              }).c_str());
          if(state_str == "NOT_AUTHENTICATED")
          {
            return ERROR(PAM_AUTH_PASSWORD_FAILED, "pam auth check failed" );
          }
          else if(state_str == "STATE_AUTHENTICATED")
          {
            return SUCCESS();
          }
          else if(state_str == "ERROR" || state_str == "TIMEOUT")
          {
            return ERROR( -1,
                          (std::string("pam aux service failure ") +
                           state_str +
                           std::string(" ") +
                           message).c_str());
          }
          else
          {
            return SUCCESS();
          }
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

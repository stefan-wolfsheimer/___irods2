#ifdef RODS_SERVER
#include "handshake_client.h"
#include <string>
#include <tuple>
#include <iostream>
#include <curl/curl.h>

#include "rodsLog.h"

using namespace PamHandshake;

std::tuple<int, std::string> PamHandshake::open_pam_handshake_session(bool unixSocket,
                                                                      const std::string & addr,
                                                                      long port,
                                                                      bool verbose)
{
  std::tuple<int, std::string, std::string> ret;
  CURL *curl = curl_easy_init();
  CURLcode res;
  PamHandshake::ReadWriteDataBuffer data("");
  std::string baseurl;
  int http_code = 500;
  std::string message;
  if(curl)
  {
    if(unixSocket)
    {
      curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, addr.c_str());
      curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/new");
    }
    else
    {
      curl_easy_setopt(curl, CURLOPT_PORT, port);
      curl_easy_setopt(curl, CURLOPT_URL, addr.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);

    if(verbose)
    {
      rodsLog(LOG_NOTICE, "curl POST %s", addr.c_str());
    }
    res = data.init(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    http_code = response_code;
    message = data.getResult();
    /* always cleanup */
    curl_easy_cleanup(curl);
    rodsLog(LOG_NOTICE, "curl http_code:%d message:%s", http_code, message.c_str());
  }
  else
  {
    throw std::runtime_error("curl init failed");
  }
  return std::make_tuple(http_code, message);
}

std::tuple<int, std::string, std::string> PamHandshake::pam_handshake_get(bool unixSocket,
                                                                          const std::string & addr,
                                                                          long port,
                                                                          const std::string & session,
                                                                          bool verbose)
{
  std::tuple<int, std::string, std::string> ret;
  CURL *curl = curl_easy_init();
  CURLcode res;
  ReadDataBuffer data;
  std::string baseurl;
  int http_code = 500;
  std::string next_state;
  std::string message;

  if(curl)
  {
    //curl_easy_setopt(curl, CURLOPT_GET, 1L);
    if(verbose)
    {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    if(unixSocket)
    {
      curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, addr.c_str());
      baseurl = "http://localhost";
    }
    else
    {
      baseurl = addr;
      curl_easy_setopt(curl, CURLOPT_PORT, port);
    }
    std::string url = baseurl + "/" + session;
    if(verbose)
    {
      rodsLog(LOG_NOTICE, "curl %s", url.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    res = data.init(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    http_code = response_code;
    message = data.getResult();
    std::size_t pos = message.find('\r');
    if(pos == std::string::npos)
    {
      next_state = message;
      message = "";
    }
    else
    {
      next_state.append(message.begin(), message.begin() +  pos);
      pos++;
      if(pos < message.size() && message[pos] == '\n')
      {
        pos++;
      }
      message.erase(message.begin(),
                    message.begin() + pos);
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  else
  {
    throw std::runtime_error("curl init failed");
  }
  return std::make_tuple(http_code, next_state, message);
}


std::tuple<int, std::string, std::string> PamHandshake::pam_handshake_put(bool unixSocket,
                                                                          const std::string & addr,
                                                                          long port,
                                                                          const std::string & session,
                                                                          const std::string & input,
                                                                          bool verbose)
{
  std::tuple<int, std::string, std::string> ret;
  //  long response_code;
  CURL *curl = curl_easy_init();
  CURLcode res;
  ReadWriteDataBuffer data(input);
  std::string baseurl;
  int http_code = 500;
  std::string next_state;
  std::string message;

  if(curl)
  {
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);
    if(verbose)
    {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    if(unixSocket)
    {
      curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, addr.c_str());
      baseurl = "http://localhost";
    }
    else
    {
      baseurl = addr;
      curl_easy_setopt(curl, CURLOPT_PORT, port);
    }
    std::string url = baseurl + "/" + session;
    if(verbose)
    {
      rodsLog(LOG_NOTICE, "curl PUT %s", url.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    res = data.init(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    http_code = response_code;
    message = data.getResult();
    std::size_t pos = message.find('\r');
    if(pos == std::string::npos)
    {
      next_state = message;
      message = "";
    }
    else
    {
      next_state.append(message.begin(), message.begin() +  pos);
      pos++;
      if(pos < message.size() && message[pos] == '\n')
      {
        pos++;
      }
      message.erase(message.begin(),
                    message.begin() + pos);
    }
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
  else
  {
    throw std::runtime_error("curl init failed");
  }
  return std::make_tuple(http_code, next_state, message);
}

int PamHandshake::pam_handshake_delete(bool unixSocket,
                                       const std::string & addr,
                                       long port,
                                       const std::string & session,
                                       bool verbose)
{
  CURL *curl = curl_easy_init();
  CURLcode res;
  ReadDataBuffer data;
  std::string baseurl;
  int http_code = 500;
  std::string next_state;
  std::string message;

  if(curl)
  {
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    if(verbose)
    {
      curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }
    if(unixSocket)
    {
      curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, addr.c_str());
      baseurl = "http://localhost";
    }
    else
    {
      baseurl = addr;
      curl_easy_setopt(curl, CURLOPT_PORT, port);
    }
    std::string url = baseurl + "/" + session;
    if(verbose)
    {
      rodsLog(LOG_NOTICE, "curl delete %s", url.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    res = data.init(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    res = curl_easy_perform(curl);
    if(res != CURLE_OK)
    {
      curl_easy_cleanup(curl);
      std::string msg = "curl_easy_perform() failed:";
      msg+= curl_easy_strerror(res);
      throw std::runtime_error(msg);
    }
    long response_code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    http_code = response_code;
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
  else
  {
    throw std::runtime_error("curl init failed");
  }
  return http_code;
}


////////////////////////////////////////////////////////////////////////////////
CURLcode ReadDataBuffer::init(CURL *curl) const
{
  CURLcode res;
  res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
  if(res != CURLE_OK)
  {
    return res;
  }
  res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &ReadDataBuffer::write);
  return res;
}

const std::string & ReadDataBuffer::getResult() const
{
  return result;
}

std::size_t ReadDataBuffer::write(void *contents, size_t size, size_t nmemb, void *data)
{
  auto self = static_cast<ReadDataBuffer*>(data);
  size_t realsize = size * nmemb;
  self->result.append((char*) contents, realsize);
  return realsize;
}

////////////////////////////////////////////////////////////////////////////////
ReadWriteDataBuffer::ReadWriteDataBuffer(const std::string & _buffer) :
  buffer(_buffer),
  content_length_header(std::string("Content-Length: ") + std::to_string(buffer.size())),
  uploaded(0)
{ 
}


CURLcode ReadWriteDataBuffer::init(CURL *curl) const
{
  CURLcode res;
  res = ReadDataBuffer::init(curl);
  if(res != CURLE_OK)
  {
    return res;
  }
  res = curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
  if(res != CURLE_OK)
  {
    return res;
  }

  res = curl_easy_setopt(curl, CURLOPT_INFILESIZE, buffer.size());
  if(res != CURLE_OK)
  {
    return res;
  }

  res = curl_easy_setopt(curl, CURLOPT_READFUNCTION, &ReadWriteDataBuffer::read);
  if(res != CURLE_OK)
  {
    return res;
  }
  res = curl_easy_setopt(curl, CURLOPT_READDATA, this);
  if(res != CURLE_OK)
  {
    return res;
  }

  {
    struct curl_slist *chunk = NULL;
    std::cout << content_length_header << std::endl;
    std::cout << "Buffer:" << buffer << ":" << buffer.size() << std::endl;
    chunk = curl_slist_append(chunk, content_length_header.c_str());
    chunk = curl_slist_append(chunk,"Expect:");
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
    if(res != CURLE_OK)
    {
      return res;
    }
  }
  return res;
}

std::size_t ReadWriteDataBuffer::read(void *ptr, size_t size, size_t nmemb, void *data)
{
  auto self = static_cast<ReadWriteDataBuffer*>(data);
  size_t left = self->buffer.size() - self->uploaded;
  size_t max_chunk = size * nmemb;
  size_t retcode = left < max_chunk ? left : max_chunk;
  std::cout << "left: " << left << " max chunk " << max_chunk << " uploaded " << self->uploaded << std::endl;
  std::cout << "buffer:" << self->buffer.c_str() << ":" << self->uploaded << ":" << retcode << std::endl;
  std::memcpy(ptr, self->buffer.c_str() + self->uploaded, retcode);
  self->uploaded += retcode;
  return retcode;
}

#endif

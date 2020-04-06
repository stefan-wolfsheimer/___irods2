#ifdef RODS_SERVER

#include <string>
#include <tuple>
#include <iostream>
#include <curl/curl.h>

class DataBuffer
{
public:
  DataBuffer(const std::string & _buffer,
             bool _verbose=false) : buffer(_buffer), uploaded(0) {}

  CURLcode init(CURL *curl) const
  {
    CURLcode res;
    res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
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

    res = curl_easy_setopt(curl, CURLOPT_READFUNCTION, &DataBuffer::read);
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
      chunk = curl_slist_append(chunk, (std::string("Content-Length: ") + std::to_string(buffer.size())).c_str());
      chunk = curl_slist_append(chunk,"Expect:");
      res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
      if(res != CURLE_OK)
      {
        return res;
      }
    }
    res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &DataBuffer::write);
    return res;
  }

  const std::string & getResult() const
  {
    return result;
  }

private:
  static std::size_t read(void *ptr, size_t size, size_t nmemb, void *data)
  {
    auto self = static_cast<DataBuffer*>(data);
    size_t left = self->buffer.size() - self->uploaded;
    size_t max_chunk = size * nmemb;
    size_t retcode = left < max_chunk ? left : max_chunk;
    std::memcpy(ptr, self->buffer.c_str() + self->uploaded, retcode);
    self->uploaded += retcode;
    return retcode;
  }

  static std::size_t write(void *contents, size_t size, size_t nmemb, void *data)
  {
    auto self = static_cast<DataBuffer*>(data);
    size_t realsize = size * nmemb;
    self->result.append((char*) contents, realsize);
    return realsize;
  }

  std::string buffer;
  std::string result;
  size_t uploaded;
};


std::tuple<int, std::string> curl_create_session(bool unixSocket,
                                                 const std::string & addr,
                                                 long port,
                                                 bool verbose)
{
  std::tuple<int, std::string, std::string> ret;
  CURL *curl = curl_easy_init();
  CURLcode res;
  DataBuffer data("");
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
    //curl_easy_setopt(curl, CURLOPT_PUT, 0L);
    //curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, nullptr);
 
    if(verbose)
    {
      std::cout << "curl POST " << addr << std::endl;
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
  }
  else
  {
    throw std::runtime_error("curl init failed");
  }
  return std::make_tuple(http_code, message);
}

std::tuple<int, std::string, std::string> exec_curl(bool unixSocket,
                                                    const std::string & addr,
                                                    long port,
                                                    const std::string & session,
                                                    const std::string & input,
                                                    bool verbose)
{
  std::tuple<int, std::string, std::string> ret;
  CURL *curl = curl_easy_init();
  CURLcode res;
  DataBuffer data(input, verbose);
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
      std::cout << "curl " << url << std::endl;
      std::cout << "data: '" << input << "'" << std::endl;
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

static bool isError(const std::string & s)
{
  return s == "ERROR";
}

static bool isFinal(const std::string & s)
{
  return isError(s) ||
    (s == "NOT_AUTHENTICATED") ||
    (s == "STATE_AUTHENTICATED");
}

#endif

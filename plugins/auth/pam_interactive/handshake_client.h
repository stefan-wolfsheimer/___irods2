#pragma once
#include <string>


#ifdef RODS_SERVER
#include <curl/curl.h>
#include <tuple>
#endif

namespace PamHandshake
{
#ifdef RODS_SERVER  
  std::tuple<int, std::string> open_pam_handshake_session(bool unixSocket,
                                                          const std::string & addr,
                                                          long port,
                                                          bool verbose);
  std::tuple<int, std::string, std::string> pam_handshake_get(bool unixSocket,
                                                              const std::string & addr,
                                                              long port,
                                                              const std::string & session,
                                                              bool verbose);
  std::tuple<int, std::string, std::string> pam_handshake_put(bool unixSocket,
                                                              const std::string & addr,
                                                              long port,
                                                              const std::string & session,
                                                              const std::string & input,
                                                              bool verbose);
  int pam_handshake_delete(bool unixSocket,
                           const std::string & addr,
                           long port,
                           const std::string & session,
                           bool verbose);

  class ReadDataBuffer
  {
  public:
    CURLcode init(void *curl) const;
    const std::string & getResult() const;
  private:
    static std::size_t write(void *contents, size_t size, size_t nmemb, void *data);
    std::string result;
  };

  class ReadWriteDataBuffer : public ReadDataBuffer
  {
  public:
    ReadWriteDataBuffer(const std::string & _buffer);
    CURLcode init(void *curl) const;
  private:
    static std::size_t read(void *ptr, size_t size, size_t nmemb, void *data);
    std::string buffer;
    std::string content_length_header;
    size_t uploaded;
  };
#endif
}
